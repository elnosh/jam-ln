use std::error::Error;

pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

pub mod parsing;
pub mod reputation_interceptor;

pub mod sink_attack_interceptor {
    use crate::reputation_interceptor::{endorsement_from_records, ReputationInterceptor};
    use async_trait::async_trait;
    use ln_resource_mgr::reputation::EndorsementSignal;
    use simln_lib::sim_node::{
        CustomRecords, ForwardingError, InterceptRequest, InterceptResolution, Interceptor,
    };
    use simln_lib::{NetworkParser, ShortChannelID};
    use std::collections::HashMap;
    use std::error::Error;
    use std::time::Duration;
    use tokio::{select, time};
    use triggered::{Listener, Trigger};

    #[derive(Eq, PartialEq)]
    enum TargetChannelType {
        Attacker,
        Peer,
    }

    // Implements a "sink" attack where an attacking node:
    // - General jams its peers so that htlcs will be endorsed
    // - Holds the endorsed htlcs to trash the target node's reputation with its peers
    //
    // This interceptor wraps an inner reputation interceptor so that we can still operate with regular reputation
    // on the non-attacking nodes. Doing so also allows us access to reputation values for monitoring.
    pub struct SinkInterceptor {
        /// Keeps track of the target's channels for custom behavior.
        target_channels: HashMap<ShortChannelID, TargetChannelType>,
        /// Inner reputation monitor that implements jamming mitigation.
        jamming_interceptor: ReputationInterceptor,
        /// Used to control shutdown.
        listener: Listener,
        shutdown: Trigger,
    }

    macro_rules! send_intercept_result {
        ($req:expr, $result:expr, $shutdown:expr) => {
            if let Err(e) = $req.response.send($result).await {
                log::error!("Could not send to interceptor: {e}");
                $shutdown.trigger();
            }
        };
    }

    fn print_request(req: &InterceptRequest) -> String {
        format!(
            "{}:{} {} -> {} with fee {} ({} -> {}) and cltv {} ({} -> {})",
            u64::from(req.incoming_htlc.channel_id),
            req.incoming_htlc.index,
            endorsement_from_records(&req.incoming_custom_records),
            if let Some(outgoing_chan) = req.outgoing_channel_id {
                outgoing_chan.into()
            } else {
                0
            },
            req.incoming_amount_msat - req.outgoing_amount_msat,
            req.incoming_amount_msat,
            req.outgoing_amount_msat,
            req.incoming_expiry_height - req.outgoing_expiry_height,
            req.incoming_expiry_height,
            req.outgoing_expiry_height
        )
    }

    impl SinkInterceptor {
        pub fn new_for_network(
            attacking_alias: String,
            target_alias: String,
            edges: &[NetworkParser],
            jamming_interceptor: ReputationInterceptor,
            listener: Listener,
            shutdown: Trigger,
        ) -> Self {
            let mut target_channels = HashMap::new();

            for channel in edges.iter() {
                let node_1_target = channel.node_1.alias == target_alias;
                let node_2_target = channel.node_2.alias == target_alias;

                if !(node_1_target || node_2_target) {
                    continue;
                }

                let channel_type = if node_1_target && channel.node_2.alias == attacking_alias {
                    TargetChannelType::Attacker
                } else if node_1_target {
                    TargetChannelType::Peer
                } else if node_2_target && channel.node_1.alias == attacking_alias {
                    TargetChannelType::Attacker
                } else {
                    TargetChannelType::Peer
                };

                target_channels.insert(channel.scid, channel_type);
            }

            Self {
                jamming_interceptor,
                target_channels,
                listener,
                shutdown,
            }
        }

        /// Intercepts payments flowing from target -> attacker, holding the htlc for the maximum allowable time to
        /// trash its reputation if the htlc is endorsed. We do not use our underlying jamming mitigation interceptor
        /// at all because the attacker is not required to run the mitigation.
        async fn intercept_attacker_incoming(&self, req: InterceptRequest) {
            // Exit early if not endorsed, no point in holding.
            if endorsement_from_records(&req.incoming_custom_records)
                == EndorsementSignal::Unendorsed
            {
                log::info!(
                    "HTLC from target -> attacker not endorsed, releasing: {}",
                    print_request(&req)
                );
                send_intercept_result!(req, Ok(Ok(CustomRecords::default())), self.shutdown);
                return;
            }

            // Get maximum hold time assuming 10 minute blocks.
            // TODO: this is actually the current height less the expiry, but we don't have the concept of height here.
            let max_hold_secs = Duration::from_secs(
                ((req.incoming_expiry_height - req.outgoing_expiry_height) * 10 * 60).into(),
            );

            log::info!(
                "HTLC from target -> attacker endorsed, holding for {:?}: {}",
                max_hold_secs,
                print_request(&req),
            );

            // If the htlc is endorsed, then we go ahead and hold the htlc for as long as we can only exiting if we
            // get a shutdown signal elsewhere.
            let resp = select! {
                _ = self.listener.clone() => Err(ForwardingError::InterceptorError("shutdown signal received".to_string())),

                _ = time::sleep(max_hold_secs) => Ok(CustomRecords::default())
            };

            send_intercept_result!(req, Ok(resp), self.shutdown);
        }

        /// Intercepts payments flowing from peer -> target, simulating a general jamming attack by failing any
        /// unendorsed payments.
        async fn intercept_peer_outgoing(&self, req: InterceptRequest) {
            log::info!(
                "HTLC from peer -> target, general jamming if endorsed: {}",
                print_request(&req),
            );

            // If the htlc is endorsed, apply usual reputation checks, otherwise just reject unendorsed htlcs to mimic
            // a general jam on the channel.
            match endorsement_from_records(&req.incoming_custom_records) {
                EndorsementSignal::Endorsed => self.jamming_interceptor.intercept_htlc(req).await,
                EndorsementSignal::Unendorsed => {
                    let resp = Ok(Err(ForwardingError::InterceptorError(
                        "general jamming unendorsed".to_string(),
                    )));

                    send_intercept_result!(req, resp, self.shutdown)
                }
            };
        }
    }

    #[async_trait]
    impl Interceptor for SinkInterceptor {
        /// Implemented by HTLC interceptors that provide input on the resolution of HTLCs forwarded in the simulation.
        async fn intercept_htlc(&self, req: InterceptRequest) {
            // Intercept payments from target -> attacker.
            if let Some(target_chan) = self.target_channels.get(&req.incoming_htlc.channel_id) {
                if *target_chan == TargetChannelType::Attacker {
                    self.intercept_attacker_incoming(req).await;
                    return;
                }
            }

            // Intercept payments from peers -> target. If there's no outgoing_channel_id, the intercepting node is
            // the recipient so we take no action.
            if let Some(outgoing_channel_id) = req.outgoing_channel_id {
                if let Some(target_chan) = self.target_channels.get(&outgoing_channel_id) {
                    if *target_chan == TargetChannelType::Peer {
                        self.intercept_peer_outgoing(req).await;
                        return;
                    }
                }
            }

            // The target is not involved in the forward at all, just use jamming interceptor to implement reputation
            // and bucketing.
            self.jamming_interceptor.intercept_htlc(req).await
        }

        /// Notifies the underlying jamming interceptor of htlc resolution, as our attacking interceptor doesn't need
        /// to handle notifications.
        async fn notify_resolution(
            &self,
            res: InterceptResolution,
        ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
            self.jamming_interceptor.notify_resolution(res).await
        }

        fn name(&self) -> String {
            "sink attack".to_string()
        }
    }
}

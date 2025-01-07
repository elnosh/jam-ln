use std::error::Error;

pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

pub mod parsing;

pub mod reputation_interceptor {
    use crate::BoxError;
    use async_trait::async_trait;
    use bitcoin::secp256k1::PublicKey;
    use simln_lib::sim_node::{
        CustomRecords, ForwardingError, InterceptRequest, InterceptResolution, Interceptor,
    };
    use simln_lib::NetworkParser;
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::ops::Sub;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use ln_resource_mgr::outgoing_reputation::{
        ForwardManager, ForwardManagerParams, ReputationParams,
    };
    use ln_resource_mgr::reputation::{
        EndorsementSignal, ForwardResolution, ForwardingOutcome, HtlcRef, ProposedForward,
        ReputationError, ReputationManager,
    };

    pub const ENDORSEMENT_TYPE: u64 = 106823;

    pub fn endorsement_from_records(records: &CustomRecords) -> EndorsementSignal {
        match records.get(&ENDORSEMENT_TYPE) {
            Some(endorsed) => {
                if endorsed.len() == 1 && endorsed[0] == 1 {
                    EndorsementSignal::Endorsed
                } else {
                    // Consider any value that isn't [1] to be unendorsed.
                    // TODO: we really shouldn't run into this?
                    EndorsementSignal::Unendorsed
                }
            }
            None => EndorsementSignal::Unendorsed,
        }
    }

    struct HtlcAdd {
        forwarding_node: PublicKey,
        htlc: ProposedForward,
    }

    struct HtlcResolve {
        outgoing_channel_id: u64,
        forwarding_node: PublicKey,
        incoming_htlc: HtlcRef,
        forward_resolution: ForwardResolution,
        resolved_ins: Instant,
    }

    enum BootstrapEvent {
        BootstrapAdd(HtlcAdd),
        BootstrapResolve(HtlcResolve),
    }

    /// Provides details of a htlc forward that is used to bootstrap reputation values for the network.
    pub struct BootstrapForward {
        pub incoming_amt: u64,
        pub outgoing_amt: u64,
        pub incoming_expiry: u32,
        pub outgoing_expiry: u32,
        pub added_ns: u64,
        pub settled_ns: u64,
        pub forwarding_node: PublicKey,
        pub channel_in_id: u64,
        pub channel_out_id: u64,
    }

    /// Implements a network-wide interceptor that implements resource management for every forwarding node in the
    /// network.
    pub struct JammingInterceptor {
        network_nodes: Arc<Mutex<HashMap<PublicKey, (ForwardManager, String)>>>,
    }

    impl JammingInterceptor {
        pub fn new_for_network(edges: &Vec<NetworkParser>) -> Result<Self, BoxError> {
            let mut network_nodes: HashMap<PublicKey, (ForwardManager, String)> = HashMap::new();

            macro_rules! add_node_to_network {
                ($network_nodes:expr, $node_pubkey:expr, $node_alias:expr, $channel:expr) => {
                    match $network_nodes.entry($node_pubkey) {
                        Entry::Vacant(e) => {
                            let forward_manager = ForwardManager::new(ForwardManagerParams {
                                reputation_params: ReputationParams {
                                    revenue_window: Duration::from_secs(14 * 24 * 60 * 60),
                                    reputation_multiplier: 12,
                                    resolution_period: Duration::from_secs(90),
                                    expected_block_speed: Some(Duration::from_secs(10 * 60 * 60)),
                                },
                                general_slot_portion: 50,
                                general_liquidity_portion: 50,
                            });

                            let _ = forward_manager
                                .add_channel($channel.scid.into(), $channel.capacity_msat)?;

                            e.insert((forward_manager, $node_alias));
                        }
                        Entry::Occupied(mut e) => {
                            let _ = e
                                .get_mut()
                                .0
                                .add_channel($channel.scid.into(), $channel.capacity_msat)?;
                        }
                    }
                };
            }

            for channel in edges {
                add_node_to_network!(
                    network_nodes,
                    channel.node_1.pubkey,
                    channel.node_1.alias.clone(),
                    channel
                );
                add_node_to_network!(
                    network_nodes,
                    channel.node_2.pubkey,
                    channel.node_2.alias.clone(),
                    channel
                );
            }

            Ok(Self {
                network_nodes: Arc::new(Mutex::new(network_nodes)),
            })
        }

        /// Creates a network from the set of edges provided and bootstraps the reputation of nodes in the network using
        /// the historical forwards provided. Forwards are expected to be sorted by added_ns in ascending order.
        pub async fn new_with_bootstrap(
            edges: &Vec<NetworkParser>,
            history: &[BootstrapForward],
        ) -> Result<Self, BoxError> {
            let mut interceptor =
                Self::new_for_network(edges).map_err(|_| "could not create network")?;
            interceptor.bootstrap_network_history(history).await?;
            Ok(interceptor)
        }

        async fn bootstrap_network_history(
            &mut self,
            history: &[BootstrapForward],
        ) -> Result<(), BoxError> {
            // We'll get all instants relative to the last timestamp we're given, so we get an instant now and track
            // the last timestamp in the set of forwards.
            let start_ins = Instant::now();
            let last_ts = history
                .iter()
                .max_by(|x, y| x.settled_ns.cmp(&y.settled_ns))
                .ok_or("at least one entry required in bootstrap history")?
                .settled_ns;

            // Run through history and create instants relative to the current time, we'll have two events per forward
            // so we can allocate accordingly.
            let mut bootstrap_events = Vec::with_capacity(history.len() * 2);
            for (i, h) in history.iter().enumerate() {
                let incoming_ref = HtlcRef {
                    channel_id: h.channel_in_id,
                    htlc_index: i as u64,
                };

                bootstrap_events.push(BootstrapEvent::BootstrapAdd(HtlcAdd {
                    forwarding_node: h.forwarding_node,
                    htlc: ProposedForward {
                        incoming_ref,
                        outgoing_channel_id: h.channel_out_id,
                        amount_in_msat: h.incoming_amt,
                        amount_out_msat: h.outgoing_amt,
                        expiry_in_height: h.incoming_expiry,
                        expiry_out_height: h.outgoing_expiry,
                        added_at: start_ins.sub(Duration::from_nanos(
                            last_ts
                                .checked_sub(h.added_ns)
                                .ok_or(format!("added ts: {} > last ts: {last_ts}", h.added_ns))?,
                        )),
                        incoming_endorsed: EndorsementSignal::Unendorsed,
                    },
                }));

                bootstrap_events.push(BootstrapEvent::BootstrapResolve(HtlcResolve {
                    outgoing_channel_id: h.channel_out_id,
                    forwarding_node: h.forwarding_node,
                    incoming_htlc: incoming_ref,
                    resolved_ins: start_ins.sub(Duration::from_nanos(
                        last_ts
                            .checked_sub(h.settled_ns)
                            .ok_or(format!("settled ts: {} > last ts: {last_ts}", h.settled_ns))?,
                    )),
                    forward_resolution: ForwardResolution::Settled,
                }));
            }

            // Sort all events by timestamp so that we can replay them "live". Fail on any error because we expect all
            // htlcs to be able to replay through our bootstrapping network.
            //
            // TODO: queue?
            bootstrap_events.sort_by_key(|event| match event {
                BootstrapEvent::BootstrapAdd(htlc_add) => htlc_add.htlc.added_at,
                BootstrapEvent::BootstrapResolve(htlc_resolve) => htlc_resolve.resolved_ins,
            });

            for e in bootstrap_events {
                match e {
                    BootstrapEvent::BootstrapAdd(htlc_add) => {
                        self.inner_add_htlc(htlc_add)
                            .await
                            .map_err(|e| e.to_string())?
                            .map_err(|e| e.to_string())?;
                    }
                    BootstrapEvent::BootstrapResolve(htlc_resolve) => {
                        self.inner_resolve_htlc(htlc_resolve)
                            .await
                            .map_err(|e| e.unwrap_or("inner resolve htlc failed".to_string()))?;
                    }
                }
            }

            Ok(())
        }

        /// Adds a htlc forward to the jamming interceptor, performing forwarding checks and returning the decided
        /// forwarding outcome for the htlc. Callers should fail if the outer result is an error, because an unexpected
        /// error has occurred.
        async fn inner_add_htlc(
            &self,
            htlc_add: HtlcAdd,
        ) -> Result<Result<HashMap<u64, Vec<u8>>, ForwardingError>, ReputationError> {
            // If the forwarding node can't be found, we've hit a critical error and can't proceed.
            let (allocation_check, alias) = match self
                .network_nodes
                .lock()
                .unwrap()
                .entry(htlc_add.forwarding_node)
            {
                Entry::Occupied(mut e) => {
                    let (node, alias) = e.get_mut();
                    (node.add_outgoing_hltc(&htlc_add.htlc)?, alias.to_string())
                }
                Entry::Vacant(_) => {
                    return Err(ReputationError::ErrUnrecoverable(format!(
                        "node not found: {}",
                        htlc_add.forwarding_node,
                    )))
                }
            };

            // Once we have a forwarding decision, return successfully to the interceptor with the call.
            let fwd_decision = allocation_check.forwarding_outcome(
                htlc_add.htlc.amount_out_msat,
                htlc_add.htlc.incoming_endorsed,
            );

            log::info!(
                "Node {} forwarding: {} with outcome {}",
                alias,
                htlc_add.htlc,
                fwd_decision,
            );

            match fwd_decision {
                ForwardingOutcome::Forward(endorsement) => {
                    let mut outgoing_records = HashMap::new();

                    match endorsement {
                        EndorsementSignal::Endorsed => {
                            outgoing_records.insert(ENDORSEMENT_TYPE, vec![1]);
                        }
                        EndorsementSignal::Unendorsed => {
                            outgoing_records.insert(ENDORSEMENT_TYPE, vec![0]);
                        }
                    }

                    Ok(Ok(outgoing_records))
                }
                ForwardingOutcome::Fail(reason) => Ok(Err(ForwardingError::InterceptorError(
                    format!("{:?}", reason),
                ))),
            }
        }

        /// Removes a htlc from the jamming interceptor, reporting its success/failure to the inner state machine.
        async fn inner_resolve_htlc(
            &self,
            resolved_htlc: HtlcResolve,
        ) -> Result<(), Option<String>> {
            match self
                .network_nodes
                .lock()
                .unwrap()
                .entry(resolved_htlc.forwarding_node)
            {
                Entry::Occupied(mut e) => e
                    .get_mut()
                    .0
                    .resolve_htlc(
                        resolved_htlc.outgoing_channel_id,
                        resolved_htlc.incoming_htlc,
                        resolved_htlc.forward_resolution,
                        resolved_htlc.resolved_ins,
                    )
                    .map_err(|e| Some(format!("{e}"))),
                Entry::Vacant(_) => Err(Some(format!(
                    "Node: {} not found",
                    resolved_htlc.forwarding_node
                ))),
            }
        }
    }

    #[async_trait]
    impl Interceptor for JammingInterceptor {
        /// Implemented by HTLC interceptors that provide input on the resolution of HTLCs forwarded in the simulation.
        async fn intercept_htlc(&self, req: InterceptRequest) {
            // If the intercept has no outgoing channel, we can just exit early because there's no action to be taken.
            let outgoing_channel_id = match req.outgoing_channel_id {
                Some(c) => c.into(),
                None => {
                    if let Err(e) = req.response.send(Ok(Ok(CustomRecords::default()))).await {
                        // TODO: select?
                        println!("Failed to send response: {:?}", e);
                    }
                    return;
                }
            };

            let htlc = ProposedForward {
                incoming_ref: HtlcRef {
                    channel_id: req.incoming_htlc.channel_id.into(),
                    htlc_index: req.incoming_htlc.index,
                },
                outgoing_channel_id,
                amount_in_msat: req.incoming_amount_msat,
                amount_out_msat: req.outgoing_amount_msat,
                expiry_in_height: req.incoming_expiry_height,
                expiry_out_height: req.outgoing_expiry_height,
                added_at: Instant::now(),
                incoming_endorsed: endorsement_from_records(&req.incoming_custom_records),
            };

            let resp = self
                .inner_add_htlc(HtlcAdd {
                    forwarding_node: req.forwarding_node,
                    htlc,
                })
                .await
                .map_err(|e| Some(e.to_string()));

            if let Err(e) = req.response.send(resp).await {
                // TODO: select
                println!("Failed to send response: {:?}", e); // TODO: error handling
            }
        }

        async fn notify_resolution(&self, res: InterceptResolution) -> Result<(), Option<String>> {
            // If there's not outgoing channel, we're notifying on the receiving node which doesn't need any action.
            let outgoing_channel_id = match res.outgoing_channel_id {
                Some(c) => c.into(),
                None => return Ok(()),
            };

            self.inner_resolve_htlc(HtlcResolve {
                outgoing_channel_id,
                forwarding_node: res.forwarding_node,
                incoming_htlc: HtlcRef {
                    channel_id: res.incoming_htlc.channel_id.into(),
                    htlc_index: res.incoming_htlc.index,
                },
                forward_resolution: ForwardResolution::from(res.success),
                resolved_ins: Instant::now(),
            })
            .await
        }

        /// Returns an identifying name for the interceptor for logging, does not need to be unique.
        fn name(&self) -> String {
            "channel jammer".to_string()
        }
    }
}

pub mod sink_attack_interceptor {
    use crate::reputation_interceptor::{endorsement_from_records, JammingInterceptor};
    use async_trait::async_trait;
    use ln_resource_mgr::reputation::EndorsementSignal;
    use simln_lib::sim_node::{
        CustomRecords, ForwardingError, InterceptRequest, InterceptResolution, Interceptor,
    };
    use simln_lib::{NetworkParser, ShortChannelID};
    use std::collections::HashMap;
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
        jamming_interceptor: JammingInterceptor,
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
            edges: Vec<NetworkParser>,
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
                jamming_interceptor: JammingInterceptor::new_for_network(&edges).unwrap(),
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
        async fn notify_resolution(&self, res: InterceptResolution) -> Result<(), Option<String>> {
            self.jamming_interceptor.notify_resolution(res).await
        }

        fn name(&self) -> String {
            "sink attack".to_string()
        }
    }
}

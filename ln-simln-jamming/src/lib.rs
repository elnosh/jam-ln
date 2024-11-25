pub mod reputation_interceptor {
    use async_trait::async_trait;
    use bitcoin::secp256k1::PublicKey;
    use simln_lib::sim_node::{
        CustomRecords, ForwardingError, InterceptRequest, InterceptResolution, Interceptor,
    };
    use simln_lib::NetworkParser;
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use ln_resource_mgr::outgoing_reputation::{
        ForwardManager, ForwardManagerParams, ReputationParams,
    };
    use ln_resource_mgr::reputation::{
        AllocatoinCheck, EndorsementSignal, ForwardResolution, ForwardingOutcome, HtlcRef,
        ProposedForward, ReputationError, ReputationManager,
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

    /// Implements a network-wide interceptor that implements resource management for every forwarding node in the
    /// network.
    pub struct JammingInterceptor {
        network_nodes: Arc<Mutex<HashMap<PublicKey, (ForwardManager, String)>>>,
    }

    impl JammingInterceptor {
        pub fn new_for_network(edges: &Vec<NetworkParser>) -> Result<Self, ()> {
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
                                .add_channel($channel.scid.into(), $channel.capacity_msat)
                                .map_err(|_| ())?;

                            e.insert((forward_manager, $node_alias));
                        }
                        Entry::Occupied(mut e) => {
                            let _ = e
                                .get_mut()
                                .0
                                .add_channel($channel.scid.into(), $channel.capacity_msat)
                                .map_err(|_| ())?;
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

        fn get_interceptor_resp(
            &self,
            forwading_node: PublicKey,
            htlc: &ProposedForward,
        ) -> Result<(AllocatoinCheck, String), ReputationError> {
            match self.network_nodes.lock().unwrap().entry(forwading_node) {
                Entry::Occupied(mut e) => {
                    let (node, alias) = e.get_mut();
                    Ok((node.add_outgoing_hltc(htlc)?, alias.to_string()))
                }
                Entry::Vacant(_) => Err(ReputationError::ErrUnknown(format!(
                    "node not found: {}",
                    forwading_node,
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

            let htlc = &ProposedForward {
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

            // If we can't successfully perform a reputation check, error out the interceptor so that the simulation
            // will fail - we do not expect failure here.
            let (allocation_check, alias) =
                match self.get_interceptor_resp(req.forwarding_node, htlc) {
                    Ok(a) => a,
                    Err(e) => {
                        if let Err(e) = req.response.send(Err(Some(e.to_string()))).await {
                            println!("Failed to send response: {:?}", e); // TODO: error handling
                        }
                        return;
                    }
                };

            // Once we have a forwarding decision, return successfully to the interceptor with the call.
            let fwd_decision =
                allocation_check.forwarding_outcome(htlc.amount_out_msat, htlc.incoming_endorsed);

            log::info!(
                "Node {} forwarding: {} with outcome {}",
                alias,
                htlc,
                fwd_decision,
            );

            let resp = match fwd_decision {
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

                    Ok(outgoing_records)
                }
                ForwardingOutcome::Fail(reason) => {
                    Err(ForwardingError::InterceptorError(format!("{:?}", reason)))
                }
            };

            if let Err(e) = req.response.send(Ok(resp)).await {
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

            match self
                .network_nodes
                .lock()
                .unwrap()
                .entry(res.forwarding_node)
            {
                Entry::Occupied(mut e) => e
                    .get_mut()
                    .0
                    .resolve_htlc(
                        outgoing_channel_id,
                        HtlcRef {
                            channel_id: res.incoming_htlc.channel_id.into(),
                            htlc_index: res.incoming_htlc.index,
                        },
                        ForwardResolution::from(res.success),
                        Instant::now(),
                    )
                    .map_err(|e| Some(format!("{e}"))),
                Entry::Vacant(_) => Err(Some(format!("Node: {} not found", res.forwarding_node))),
            }
        }

        /// Returns an identifying name for the interceptor for logging, does not need to be unique.
        fn name(&self) -> String {
            "channel jammer".to_string()
        }
    }
}

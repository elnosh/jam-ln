use crate::BoxError;
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use simln_lib::sim_node::{
    CustomRecords, ForwardingError, InterceptRequest, InterceptResolution, Interceptor,
};
use simln_lib::NetworkParser;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::error::Error;
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
pub struct ReputationInterceptor {
    network_nodes: Arc<Mutex<HashMap<PublicKey, (ForwardManager, String)>>>,
}

impl ReputationInterceptor {
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
                    self.inner_resolve_htlc(htlc_resolve).await?;
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
            ForwardingOutcome::Fail(reason) => Ok(Err(ForwardingError::InterceptorError(format!(
                "{:?}",
                reason
            )))),
        }
    }

    /// Removes a htlc from the jamming interceptor, reporting its success/failure to the inner state machine.
    async fn inner_resolve_htlc(
        &self,
        resolved_htlc: HtlcResolve,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        match self
            .network_nodes
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .entry(resolved_htlc.forwarding_node)
        {
            Entry::Occupied(mut e) => Ok(e.get_mut().0.resolve_htlc(
                resolved_htlc.outgoing_channel_id,
                resolved_htlc.incoming_htlc,
                resolved_htlc.forward_resolution,
                resolved_htlc.resolved_ins,
            )?),
            Entry::Vacant(_) => {
                Err(format!("Node: {} not found", resolved_htlc.forwarding_node).into())
            }
        }
    }
}

#[async_trait]
impl Interceptor for ReputationInterceptor {
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
            .map_err(|e| e.into()); // into maps error enum to erased Box<dyn Error>

        if let Err(e) = req.response.send(resp).await {
            // TODO: select
            println!("Failed to send response: {:?}", e); // TODO: error handling
        }
    }

    async fn notify_resolution(
        &self,
        res: InterceptResolution,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
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

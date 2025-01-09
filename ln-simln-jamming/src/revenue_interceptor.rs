use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap};
use std::error::Error;
use std::ops::{Add, Sub};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use ln_resource_mgr::reputation::HtlcRef;
use simln_lib::sim_node::{InterceptRequest, InterceptResolution, Interceptor};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tokio::{select, time};
use triggered::{Listener, Trigger};

use crate::parsing::peacetime_from_file;
use crate::BoxError;

pub struct RevenueInterceptor {
    target_node: PublicKey,
    target_revenue: Mutex<NodeRevenue>,
    peacetime_revenue: Mutex<PeacetimeRevenue>,
    listener: Listener,
    shutdown: Trigger,
}

struct NodeRevenue {
    revenue_total: u64,
    /// Tracks pending htlcs on the target node so that we can report fees once we know how they have resolved.
    pending_htlcs: HashMap<HtlcRef, u64>,
}

#[derive(Eq, PartialEq)]
pub struct RevenueEvent {
    pub timestamp_ns: u64,
    pub fee_msat: u64,
}

// Reverse the ordering to create a min-heap based on timestamp_ns
impl Ord for RevenueEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        other.timestamp_ns.cmp(&self.timestamp_ns)
    }
}

impl PartialOrd for RevenueEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Responsible for tracking what the target node's revenue would be in a peacetime network (without the attacker).
struct PeacetimeRevenue {
    /// Represents the revenue of the target node in peacetime (a network without the attacker).
    peacetime_revenue: u64,

    /// A queue of peacetime revenue events that need to be replayed with the simulation to compare peace and attack
    /// time revenue.
    revenue_events: BinaryHeap<RevenueEvent>,
}

impl PeacetimeRevenue {
    fn new_with_bootstrap(
        target_pubkey: PublicKey,
        revenue_file: PathBuf,
        bootstrap_duration: Duration,
    ) -> Result<Self, BoxError> {
        // TODO: paginate reads from file.
        let mut peacetime_activity = peacetime_from_file(&revenue_file, target_pubkey)?;

        // Grab the first event to get our starting timestamp, push the event back on so that we can process it.
        let first_event = peacetime_activity
            .peek()
            .ok_or(format!("should have at least one forward for target node"))?;

        let cutoff_ns = first_event
            .timestamp_ns
            .add(bootstrap_duration.as_nanos() as u64);

        // Accumulate the starting peacetime revenue, defined by the period of time that we bootstrapped the simulation
        // from, so that we're on the same starting point.
        let mut peacetime_revenue: u64 = 0;
        while let Some(event) = peacetime_activity.peek() {
            if event.timestamp_ns >= cutoff_ns {
                break;
            }

            peacetime_revenue += event.fee_msat;
            peacetime_activity.pop();
        }

        Ok(PeacetimeRevenue {
            peacetime_revenue,
            revenue_events: peacetime_activity,
        })
    }
}

impl RevenueInterceptor {
    pub fn new_with_bootstrap(
        target_pubkey: PublicKey,
        bootstrap_revenue: u64,
        bootstrap_duration: Duration,
        revenue_file: PathBuf,
        listener: Listener,
        shutdown: Trigger,
    ) -> Result<Self, BoxError> {
        Ok(Self {
            target_node: target_pubkey,
            target_revenue: Mutex::new(NodeRevenue {
                revenue_total: bootstrap_revenue,
                pending_htlcs: HashMap::new(),
            }),
            peacetime_revenue: Mutex::new(PeacetimeRevenue::new_with_bootstrap(
                target_pubkey,
                revenue_file,
                bootstrap_duration,
            )?),
            listener,
            shutdown,
        })
    }

    /// Replays projected forwards for the simulated network in a time of peace (ie, without the attacker). These events
    /// are replayed "live" so that they can be compared to the current simulation's revenue.
    pub async fn process_peacetime_fwds(&self) -> Result<(), BoxError> {
        let mut last_event_ts = None;

        loop {
            // Grab our lock to get the next event, we don't want to hold it because we have to sleep later.
            let mut peacetime_lock = self.peacetime_revenue.lock().await;
            let next_event = peacetime_lock
                .revenue_events
                .pop()
                .ok_or(format!("run out of peacetime events"))?;
            drop(peacetime_lock);

            let last_event_ts = last_event_ts.unwrap_or_else(|| {
                last_event_ts = Some(next_event.timestamp_ns);
                next_event.timestamp_ns
            });
            let wait = next_event.timestamp_ns.sub(last_event_ts);

            let _ = time::sleep(Duration::from_nanos(wait));

            self.peacetime_revenue.lock().await.peacetime_revenue += next_event.fee_msat;
        }
    }

    pub async fn poll_revenue_difference(&self, interval: Duration) -> Result<(), BoxError> {
		let start_ins = Instant::now();

        loop {
            select! {
                _ = self.listener.clone() => return Ok(()),
                _ = sleep(interval) => {
                    let simulation_revenue = self.target_revenue.lock().await.revenue_total;
                    let peacetime_revenue = self.peacetime_revenue.lock().await.peacetime_revenue;

                    if peacetime_revenue > simulation_revenue{
                        self.shutdown.trigger();
                        log::info!("Peacetime revenue: {peacetime_revenue} exceeds simulation
                            revenue: {simulation_revenue} after: {:?}", start_ins.elapsed());
                    }
                },
            }
        }
    }
}

#[async_trait]
impl Interceptor for RevenueInterceptor {
    /// RevenueInterceptor does not need to take any active action on incoming htlcs.
    async fn intercept_htlc(&self, req: InterceptRequest) {
        let resp = if req.forwarding_node == self.target_node {
            match self
                .target_revenue
                .lock()
                .await
                .pending_htlcs
                .entry(HtlcRef {
                    channel_id: req.incoming_htlc.channel_id.into(),
                    htlc_index: req.incoming_htlc.index,
                }) {
                Entry::Occupied(_) => {
                    Err(format!("duplicate incoming htlc index: {:?}", req.incoming_htlc).into())
                }
                Entry::Vacant(e) => {
                    e.insert(req.incoming_amount_msat - req.outgoing_amount_msat);
                    Ok(Ok(HashMap::new()))
                }
            }
        } else {
            Ok(Ok(HashMap::new()))
        };

        if let Err(e) = req.response.send(resp).await {
            // TODO: select and handle error
            println!("Failed to send response: {:?}", e);
        }
    }

    /// Notifies the underlying jamming interceptor of htlc resolution, as our attacking interceptor doesn't need
    /// to handle notifications.
    async fn notify_resolution(
        &self,
        res: InterceptResolution,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        if res.forwarding_node == self.target_node {
            let mut target_revenue = self.target_revenue.lock().await;

            match target_revenue.pending_htlcs.remove_entry(&HtlcRef {
                channel_id: res.incoming_htlc.channel_id.into(),
                htlc_index: res.incoming_htlc.index,
            }) {
                Some((_, fee)) => {
                    if res.success {
                        target_revenue.revenue_total += fee;
                    }

                    Ok(())
                }
                None => Err(format!("resolved htlc not found: {:?}", res.incoming_htlc).into()),
            }
        } else {
            Ok(())
        }
    }

    fn name(&self) -> String {
        "revenue interceptor".to_string()
    }
}

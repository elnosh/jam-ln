pub use reputation_tracker::ReputationParams;

use crate::decaying_average::DecayingAverage;
use crate::{
    AllocationCheck, ForwardResolution, ForwardingOutcome, HtlcRef, ProposedForward,
    ReputationError, ReputationManager, ReputationSnapshot,
};
use reputation_tracker::ReputationTracker;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForwardManagerParams {
    pub reputation_params: ReputationParams,
    pub general_slot_portion: u8,
    pub general_liquidity_portion: u8,
}

impl ForwardManagerParams {
    /// Returns the opportunity cost for the htlc amount and expiry provided, assuming 10 minute blocks.
    pub fn htlc_opportunity_cost(&self, fee_msat: u64, expiry: u32) -> u64 {
        self.reputation_params
            .opportunity_cost(fee_msat, Duration::from_secs(expiry as u64 * 10 * 60))
    }
}

/// Tracks reputation and revenue for a channel.
#[derive(Debug)]
struct TrackedChannel {
    outgoing_reputation: ReputationTracker,
    incoming_revenue: DecayingAverage,
}

/// Defines special actions that can be taken during a simulation that wouldn't otherwise be used in regular operation.
pub trait SimualtionDebugManager {
    fn general_jam_channel(&self, channel: u64) -> Result<(), ReputationError>;
}

/// Implements outgoing reputation algorithm and resource bucketing for an individual node.
#[derive(Debug)]
pub struct ForwardManager {
    params: ForwardManagerParams,
    channels: Mutex<HashMap<u64, TrackedChannel>>,
}

impl ForwardManager {
    pub fn new(params: ForwardManagerParams) -> Self {
        Self {
            params,
            channels: Mutex::new(HashMap::new()),
        }
    }
}

impl SimualtionDebugManager for ForwardManager {
    fn general_jam_channel(&self, channel: u64) -> Result<(), ReputationError> {
        self.channels
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .get_mut(&channel)
            .ok_or(ReputationError::ErrChannelNotFound(channel))?
            .outgoing_reputation
            .general_jam_channel();

        Ok(())
    }
}

impl ReputationManager for ForwardManager {
    fn add_channel(&self, channel_id: u64, capacity_msat: u64) -> Result<(), ReputationError> {
        match self
            .channels
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .entry(channel_id)
        {
            Entry::Occupied(_) => Err(ReputationError::ErrChannelExists(channel_id)),
            Entry::Vacant(v) => {
                let general_slot_count = 483 * self.params.general_slot_portion as u16 / 100;
                let general_liquidity_amount =
                    capacity_msat * self.params.general_liquidity_portion as u64 / 100;

                v.insert(TrackedChannel {
                    outgoing_reputation: ReputationTracker::new(
                        self.params.reputation_params,
                        general_slot_count,
                        general_liquidity_amount,
                    )?,
                    incoming_revenue: DecayingAverage::new(
                        self.params.reputation_params.revenue_window,
                    ),
                });

                Ok(())
            }
        }
    }

    fn remove_channel(&self, channel_id: u64) -> Result<(), ReputationError> {
        match self
            .channels
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .remove(&channel_id)
        {
            Some(_) => Ok(()),
            None => Err(ReputationError::ErrChannelNotFound(channel_id)),
        }
    }

    fn get_forwarding_outcome(
        &self,
        forward: &ProposedForward,
    ) -> Result<AllocationCheck, ReputationError> {
        forward.validate()?;

        let mut chan_lock = self
            .channels
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?;

        // Get the incoming revenue threshold that the outgoing channel must meet.
        let incoming_threshold = chan_lock
            .get_mut(&forward.incoming_ref.channel_id)
            .ok_or(ReputationError::ErrIncomingNotFound(
                forward.incoming_ref.channel_id,
            ))?
            .incoming_revenue
            .value_at_instant(forward.added_at)?;

        // Check reputation and resources available for the forward.
        let outgoing_channel = &mut chan_lock
            .get_mut(&forward.outgoing_channel_id)
            .ok_or(ReputationError::ErrOutgoingNotFound(
                forward.outgoing_channel_id,
            ))?
            .outgoing_reputation;

        Ok(AllocationCheck {
            reputation_check: outgoing_channel.new_reputation_check(
                forward.added_at,
                incoming_threshold,
                forward,
            )?,
            resource_check: outgoing_channel.general_bucket_resources(),
        })
    }

    fn add_htlc(&self, forward: &ProposedForward) -> Result<AllocationCheck, ReputationError> {
        // TODO: locks not atomic
        let allocation_check = self.get_forwarding_outcome(forward)?;

        if let ForwardingOutcome::Forward(_) =
            allocation_check.forwarding_outcome(forward.amount_out_msat, forward.incoming_endorsed)
        {
            self.channels
                .lock()
                .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
                .get_mut(&forward.outgoing_channel_id)
                .ok_or(ReputationError::ErrOutgoingNotFound(
                    forward.outgoing_channel_id,
                ))?
                .outgoing_reputation
                .add_outgoing_htlc(forward)?;
        }

        Ok(allocation_check)
    }

    fn resolve_htlc(
        &self,
        outgoing_channel: u64,
        incoming_ref: HtlcRef,
        resolution: ForwardResolution,
        resolved_instant: Instant,
    ) -> Result<(), ReputationError> {
        let mut chan_lock = self
            .channels
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?;

        // Remove from outgoing channel, which will return the amount that we need to add to the incoming channel's
        // revenue for forwarding the htlc.
        let outgoing_channel_tracker = chan_lock
            .get_mut(&outgoing_channel)
            .ok_or(ReputationError::ErrOutgoingNotFound(outgoing_channel))?;

        let in_flight = outgoing_channel_tracker
            .outgoing_reputation
            .remove_outgoing_htlc(outgoing_channel, incoming_ref, resolution, resolved_instant)?;

        if resolution == ForwardResolution::Failed {
            return Ok(());
        }

        // If the htlc was settled, update *both* the outgoing and incoming channel's revenue trackers.
        let fee_i64 = i64::try_from(in_flight.fee_msat).unwrap_or(i64::MAX);

        let _ = outgoing_channel_tracker
            .incoming_revenue
            .add_value(fee_i64, resolved_instant)?;

        chan_lock
            .get_mut(&incoming_ref.channel_id)
            .ok_or(ReputationError::ErrIncomingNotFound(
                incoming_ref.channel_id,
            ))?
            .incoming_revenue
            .add_value(fee_i64, resolved_instant)?;

        Ok(())
    }

    /// Lists the reputation scores of each channel at the access instant provided. This function will mutate the
    /// underlying decaying averages to be tracked at the instant provided.
    fn list_reputation(
        &self,
        access_ins: Instant,
    ) -> Result<HashMap<u64, ReputationSnapshot>, ReputationError> {
        let mut chan_lock = self
            .channels
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?;

        let mut reputations = HashMap::with_capacity(chan_lock.len());
        for (scid, channel) in chan_lock.iter_mut() {
            reputations.insert(
                *scid,
                ReputationSnapshot {
                    outgoing_reputation: channel
                        .outgoing_reputation
                        .outgoing_reputation(access_ins)?,
                    incoming_revenue: channel.incoming_revenue.value_at_instant(access_ins)?,
                },
            );
        }

        Ok(reputations)
    }
}

mod reputation_tracker {
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::ops::Sub;
    use std::time::{Duration, Instant};

    use crate::decaying_average::DecayingAverage;
    use crate::{
        validate_msat, EndorsementSignal, ForwardResolution, HtlcRef, ProposedForward,
        ReputationCheck, ReputationError, ResourceCheck,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct ReputationParams {
        /// The period of time that revenue should be tracked to determine the threshold for reputation decisions.
        pub revenue_window: Duration,
        /// The multiplier applied to [`revenue_window`] that determines the period that reputation is built over.
        pub reputation_multiplier: u8,
        /// The threshold above which htlcs will be penalized for slow resolution.
        pub resolution_period: Duration,
        /// Expected block speed, surfaced to allow test networks to set different durations, defaults to 10 minutes
        /// otherwise.
        pub expected_block_speed: Option<Duration>,
    }

    impl ReputationParams {
        /// Calculates the opportunity_cost of a htlc being held on our channel - allowing one [`reputation_period`]'s
        /// grace period, then charging for every subsequent period.
        pub(super) fn opportunity_cost(&self, fee_msat: u64, hold_time: Duration) -> u64 {
            (hold_time.as_secs() / self.resolution_period.as_secs()).saturating_mul(fee_msat)
        }

        /// Calculates the worst case reputation damage of a htlc, assuming it'll be held for its full expiry_delta.
        fn htlc_risk(&self, fee_msat: u64, expiry_delta: u32) -> u64 {
            let max_hold_time = self
                .expected_block_speed
                .unwrap_or_else(|| Duration::from_secs(60 * 10))
                * expiry_delta;

            self.opportunity_cost(fee_msat, max_hold_time)
        }

        /// Calculates the fee contribution of a htlc, based on its hold time, endorsement and resolution.
        pub(super) fn effective_fees(
            &self,
            fee_msat: u64,
            hold_time: Duration,
            incoming_endorsed: EndorsementSignal,
            settled: bool,
        ) -> Result<i64, ReputationError> {
            // If the htlc was successful, its fees contribute to our effective fee.
            let paid_fees = if settled { validate_msat(fee_msat)? } else { 0 };

            let effective_fees = paid_fees.saturating_sub(
                i64::try_from(self.opportunity_cost(fee_msat, hold_time)).unwrap_or(i64::MAX),
            );

            // Unendorsed htlcs do not have a negative impact on reputation.
            if incoming_endorsed == EndorsementSignal::Unendorsed && effective_fees < 0 {
                return Ok(0);
            }

            Ok(effective_fees)
        }
    }

    #[derive(Clone, Debug)]
    pub(super) struct InFlightHtlc {
        pub fee_msat: u64,
        hold_blocks: u32,
        outgoing_amt_msat: u64,
        added_instant: Instant,
        incoming_endorsed: EndorsementSignal,
    }

    #[derive(Clone, Debug)]
    pub(super) struct ReputationTracker {
        params: ReputationParams,

        /// The reputation that the channel has accrued as the outgoing link in htlc forwards. Tracked as a decaying
        /// average over the reputation_window that the tracker is created with.
        outgoing_reputation: DecayingAverage,

        /// Tracks the outstanding risk of htlcs in flight on the channel in the outgoing direction, keyed by the
        /// *incoming* htlc's unique identifying index - we don't yet have one for the outgoing channel when we
        /// intercept.
        outgoing_in_flight: HashMap<HtlcRef, InFlightHtlc>,

        /// The number of slots available in the general bucket.
        general_slot_count: u16,

        /// The amount of liquidity available in general bucket.
        general_liquidity_msat: u64,
    }

    impl ReputationTracker {
        pub(super) fn new(
            params: ReputationParams,
            general_slot_count: u16,
            general_liquidity_msat: u64,
        ) -> Result<Self, ReputationError> {
            if params.reputation_multiplier <= 1 {
                return Err(ReputationError::ErrInvalidMultiplier);
            }

            Ok(Self {
                params,
                outgoing_reputation: DecayingAverage::new(
                    params.revenue_window * params.reputation_multiplier.into(),
                ),
                outgoing_in_flight: HashMap::new(),
                general_slot_count,
                general_liquidity_msat,
            })
        }

        /// Returns the reputation that the channel has earned in the outgoing direction over [`revenue_window *
        /// reputation_multiplier`].
        pub(super) fn outgoing_reputation(
            &mut self,
            access_instant: Instant,
        ) -> Result<i64, ReputationError> {
            self.outgoing_reputation.value_at_instant(access_instant)
        }

        /// Returns the total htlc risk of all the endorsed htlcs that are currently in flight. Unendorsed htlcs do not
        /// contribute to risk, so no option is given to count unendorsed risk.
        fn total_incoming_risk_msat(&self) -> u64 {
            self.outgoing_in_flight
                .iter()
                .filter(|(_, v)| v.incoming_endorsed == EndorsementSignal::Endorsed)
                .map(|(_, v)| self.params.htlc_risk(v.fee_msat, v.hold_blocks))
                .sum()
        }

        /// Returns the total balance of htlcs in flight in msat, filtering by provided endorsement signal.
        fn total_outgoing_in_flight_msat(&self, endorsed: EndorsementSignal) -> u64 {
            self.outgoing_in_flight
                .iter()
                .filter(|(_, v)| v.incoming_endorsed == endorsed)
                .map(|(_, v)| v.outgoing_amt_msat)
                .sum()
        }

        fn total_in_flight_count(&self, endorsed: EndorsementSignal) -> u16 {
            self.outgoing_in_flight
                .iter()
                .filter(|(_, v)| v.incoming_endorsed == endorsed)
                .count() as u16 // Safe because we have in protocol limit 483.
        }

        /// Gets a snapshot of reputation for the outgoing channel, taking into account the risk of all outgoing
        /// endorsed in-flight htlcs.
        pub(super) fn new_reputation_check(
            &mut self,
            access_instant: Instant,
            incoming_revenue: i64,
            forward: &ProposedForward,
        ) -> Result<ReputationCheck, ReputationError> {
            let outgoing_reputation = self.outgoing_reputation(access_instant)?;
            let in_flight_total_risk = self.total_incoming_risk_msat();
            let htlc_risk = self
                .params
                // The underlying simulation is block height agnostic, and starts its routes with a height of zero, so
                // we can just use the incoming expiry to reflect "maximum time htlc can be held on channel", because
                // we're calculating expiry_in_height - 0.
                .htlc_risk(forward.fee_msat(), forward.expiry_in_height);

            Ok(ReputationCheck {
                outgoing_reputation,
                incoming_revenue,
                in_flight_total_risk,
                htlc_risk,
            })
        }

        /// Gets the current state of the general bucket's resources.
        pub(super) fn general_bucket_resources(&self) -> ResourceCheck {
            ResourceCheck {
                general_slots_used: self.total_in_flight_count(EndorsementSignal::Unendorsed),
                general_slots_availabe: self.general_slot_count,
                general_liquidity_msat_used: self
                    .total_outgoing_in_flight_msat(EndorsementSignal::Unendorsed),
                general_liquidity_msat_available: self.general_liquidity_msat,
            }
        }

        /// Adds an in flight htlc to the outgoing channel.
        pub(super) fn add_outgoing_htlc(
            &mut self,
            forward: &ProposedForward,
        ) -> Result<(), ReputationError> {
            match self.outgoing_in_flight.entry(forward.incoming_ref) {
                Entry::Occupied(_) => Err(ReputationError::ErrDuplicateHtlc(forward.incoming_ref)),
                Entry::Vacant(v) => {
                    v.insert(InFlightHtlc {
                        hold_blocks: forward.expiry_in_height,
                        outgoing_amt_msat: forward.amount_out_msat,
                        fee_msat: forward.fee_msat(),
                        added_instant: forward.added_at,
                        incoming_endorsed: forward.incoming_endorsed,
                    });
                    Ok(())
                }
            }
        }

        /// Removes an in flight htlc, updating reputation to reflect impact of resolution. Will return an error if the
        /// htlc was not previously added using [`add_outgoing_hltc`]. Returns the details of the in flight htlc.
        pub(super) fn remove_outgoing_htlc(
            &mut self,
            outgoing_channel: u64,
            incoming_ref: HtlcRef,
            resolution: ForwardResolution,
            resolved_instant: Instant,
        ) -> Result<InFlightHtlc, ReputationError> {
            let in_flight = self.outgoing_in_flight.remove(&incoming_ref).ok_or(
                ReputationError::ErrForwardNotFound(outgoing_channel, incoming_ref),
            )?;

            // Unendorsed payments only have a positive impact on reputation (no negative effective fees are applied),
            // and endorsed payments
            let settled = resolution == ForwardResolution::Settled;
            let effective_fees = self.params.effective_fees(
                in_flight.fee_msat,
                resolved_instant.sub(in_flight.added_instant),
                in_flight.incoming_endorsed,
                settled,
            )?;

            // Update reputation to reflect its reputation impact.
            let _ = self
                .outgoing_reputation
                .add_value(effective_fees, resolved_instant)?;

            Ok(in_flight)
        }

        pub(super) fn general_jam_channel(&mut self) {
            self.general_slot_count = 0;
            self.general_liquidity_msat = 0;
        }
    }

    #[cfg(test)]
    mod tests {
        use std::time::{Duration, Instant};

        use crate::outgoing_reputation::ReputationParams;
        use crate::{
            EndorsementSignal, ForwardResolution, HtlcRef, ProposedForward, ReputationCheck,
            ReputationError, ResourceCheck,
        };

        use super::ReputationTracker;

        fn get_test_params() -> ReputationParams {
            ReputationParams {
                revenue_window: Duration::from_secs(60 * 60 * 24), // 1 week
                reputation_multiplier: 10,
                resolution_period: Duration::from_secs(60),
                expected_block_speed: Some(Duration::from_secs(60 * 10)),
            }
        }

        /// Returns a ReputationTracker with 100 general slots and 100_00 msat of general liquidity.
        fn get_test_tracker() -> ReputationTracker {
            ReputationTracker::new(get_test_params(), 100, 100_000).unwrap()
        }

        fn get_test_htlc(id: u64, endorsed: EndorsementSignal, fee_msat: u64) -> ProposedForward {
            ProposedForward {
                incoming_ref: HtlcRef {
                    channel_id: 1,
                    htlc_index: id,
                },
                outgoing_channel_id: 2,
                amount_in_msat: 1000 + fee_msat,
                amount_out_msat: 1000,
                expiry_in_height: 500_010,
                expiry_out_height: 500_000,
                added_at: Instant::now(),
                incoming_endorsed: endorsed,
            }
        }

        #[test]
        fn test_opportunity_cost() {
            let params = get_test_params();
            // Less than resolution_period has zero cost.
            assert_eq!(params.opportunity_cost(100, Duration::from_secs(10)), 0);

            // Equal to resolution_period or within one period is equal to fee.
            assert_eq!(params.opportunity_cost(100, Duration::from_secs(60)), 100);
            assert_eq!(params.opportunity_cost(100, Duration::from_secs(65)), 100);

            // Multiple periods above resolution_period charges multiples of fee.
            assert_eq!(params.opportunity_cost(100, Duration::from_secs(600)), 1000);
        }

        #[test]
        fn test_effective_fees() {
            let params = get_test_params();
            let fast_resolve = params.resolution_period / 2;
            let slow_resolve = params.resolution_period * 3;

            let cases = vec![
                (
                    1000,
                    fast_resolve,
                    EndorsementSignal::Endorsed,
                    true,
                    Ok(1000),
                ),
                (
                    1000,
                    slow_resolve,
                    EndorsementSignal::Endorsed,
                    true,
                    Ok(-2000),
                ),
                (
                    1000,
                    fast_resolve,
                    EndorsementSignal::Endorsed,
                    false,
                    Ok(0),
                ),
                (
                    1000,
                    slow_resolve,
                    EndorsementSignal::Endorsed,
                    false,
                    Ok(-3000),
                ),
                (
                    1000,
                    fast_resolve,
                    EndorsementSignal::Unendorsed,
                    true,
                    Ok(1000),
                ),
                (
                    1000,
                    slow_resolve,
                    EndorsementSignal::Unendorsed,
                    true,
                    Ok(0),
                ),
                (
                    1000,
                    fast_resolve,
                    EndorsementSignal::Unendorsed,
                    false,
                    Ok(0),
                ),
                (
                    1000,
                    slow_resolve,
                    EndorsementSignal::Unendorsed,
                    false,
                    Ok(0),
                ),
            ];

            for (fee_msat, hold_time, endorsed, settled, expected) in cases {
                let result = params.effective_fees(fee_msat, hold_time, endorsed, settled);
                assert_eq!(result, expected, "Case failed: fee_msat={fee_msat:?}, hold_time={hold_time:?}, endorsed={endorsed:?}, settled={settled:?}");
            }
        }

        #[test]
        fn test_add_htlc() {
            let mut tracker = get_test_tracker();

            // Endorsed htlc contribute to in flight risk and count.
            let htlc_1 = get_test_htlc(0, EndorsementSignal::Endorsed, 1000);
            let htlc_1_risk = tracker
                .params
                .htlc_risk(htlc_1.fee_msat(), htlc_1.expiry_in_height);

            assert!(tracker.add_outgoing_htlc(&htlc_1).is_ok());
            assert_eq!(tracker.total_incoming_risk_msat(), htlc_1_risk,);
            assert_eq!(
                tracker.total_outgoing_in_flight_msat(EndorsementSignal::Endorsed),
                htlc_1.amount_out_msat,
            );
            assert_eq!(
                tracker.total_in_flight_count(EndorsementSignal::Endorsed),
                1
            );

            assert!(matches!(
                tracker.add_outgoing_htlc(&htlc_1).err().unwrap(),
                ReputationError::ErrDuplicateHtlc(_)
            ));

            // Unendorsed doesn't contribute to in flight risk, but counted in other tracking.
            let htlc_2 = get_test_htlc(1, EndorsementSignal::Unendorsed, 2000);

            assert!(tracker.add_outgoing_htlc(&htlc_2).is_ok());
            assert_eq!(tracker.total_incoming_risk_msat(), htlc_1_risk,);
            assert_eq!(
                tracker.total_outgoing_in_flight_msat(EndorsementSignal::Unendorsed),
                htlc_2.amount_out_msat,
            );
            assert_eq!(
                tracker.total_in_flight_count(EndorsementSignal::Endorsed),
                1
            );

            // While we're here, test some lookup functions.
            let htlc_3 = get_test_htlc(2, EndorsementSignal::Endorsed, 3000);
            assert_eq!(
                tracker
                    .new_reputation_check(Instant::now(), 550, &htlc_3)
                    .unwrap(),
                ReputationCheck {
                    outgoing_reputation: 0,
                    incoming_revenue: 550,
                    in_flight_total_risk: htlc_1_risk,
                    htlc_risk: tracker
                        .params
                        .htlc_risk(htlc_3.fee_msat(), htlc_1.expiry_in_height,),
                },
            );

            assert_eq!(
                tracker.general_bucket_resources(),
                ResourceCheck {
                    general_slots_used: 1,
                    general_slots_availabe: tracker.general_slot_count,
                    general_liquidity_msat_used: htlc_2.amount_out_msat,
                    general_liquidity_msat_available: tracker.general_liquidity_msat,
                }
            );
        }

        /// Tests addition / removal of a successfully settled htlc.
        #[test]
        fn test_remove_htlc() {
            let mut tracker = get_test_tracker();
            let htlc_1 = get_test_htlc(0, EndorsementSignal::Endorsed, 1000);

            tracker.add_outgoing_htlc(&htlc_1).unwrap();
            let mut remove_htlc_1 = || {
                tracker.remove_outgoing_htlc(
                    htlc_1.outgoing_channel_id,
                    htlc_1.incoming_ref,
                    ForwardResolution::Settled,
                    htlc_1.added_at,
                )
            };

            assert!(remove_htlc_1().is_ok());
            assert!(matches!(
                remove_htlc_1().err().unwrap(),
                ReputationError::ErrForwardNotFound(_, _)
            ));

            assert_eq!(
                tracker.outgoing_reputation(htlc_1.added_at).unwrap(),
                htlc_1.fee_msat() as i64
            );
        }
    }
}

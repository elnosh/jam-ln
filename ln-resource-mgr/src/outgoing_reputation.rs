pub use crate::outgoing_reputation::forward_manager::{ForwardManager, ForwardManagerParams};
pub use crate::outgoing_reputation::reputation_tracker::ReputationParams;

pub mod forward_manager {
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;

    use super::decaying_average::DecayingAverage;
    use super::reputation_tracker::{ReputationParams, ReputationTracker};
    use crate::reputation::{AllocatoinCheck, ReputationManager};
    use crate::reputation::{
        ForwardResolution, ForwardingOutcome, HtlcRef, ProposedForward, ReputationError,
    };

    struct TrackedChannel {
        outgoing_reputation: ReputationTracker,
        incoming_revenue: DecayingAverage,
    }

    pub struct ForwardManagerParams {
        pub reputation_params: ReputationParams,
        pub general_slot_portion: u8,
        pub general_liquidity_portion: u8,
    }

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
        ) -> Result<AllocatoinCheck, ReputationError> {
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

            Ok(AllocatoinCheck {
                reputation_check: outgoing_channel.new_reputation_check(
                    forward.added_at,
                    incoming_threshold,
                    &forward,
                )?,
                resource_check: outgoing_channel.general_bucket_resources(),
            })
        }

        fn add_outgoing_hltc(
            &self,
            forward: &ProposedForward,
        ) -> Result<AllocatoinCheck, ReputationError> {
            // TODO: locks not atomic
            let allocation_check = self.get_forwarding_outcome(&forward)?;

            if let ForwardingOutcome::Forward(_) = allocation_check
                .forwarding_outcome(forward.amount_out_msat, forward.incoming_endorsed)
            {
                let _ = self
                    .channels
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
                .remove_outgoing_htlc(
                    outgoing_channel,
                    incoming_ref,
                    resolution,
                    resolved_instant,
                )?;

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
    }
}

mod reputation_tracker {
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::ops::Sub;
    use std::time::{Duration, Instant};

    use super::decaying_average::DecayingAverage;
    use crate::reputation::{
        validate_msat, EndorsementSignal, ForwardResolution, HtlcRef, ProposedForward,
        ReputationCheck, ReputationError, ResourceCheck,
    };

    #[derive(Clone, Copy)]
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
        fn opportunity_cost(&self, fee_msat: u64, hold_time: Duration) -> u64 {
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
        pub fn effective_fees(
            &self,
            fee_msat: u64,
            hold_time: Duration,
            incoming_endorsed: bool,
            settled: bool,
        ) -> Result<i64, ReputationError> {
            // If the htlc was successful, its fees contribute to our effective fee.
            let paid_fees = if settled { validate_msat(fee_msat)? } else { 0 };

            let effective_fees = paid_fees.saturating_sub(
                i64::try_from(self.opportunity_cost(fee_msat, hold_time)).unwrap_or(i64::MAX),
            );

            // Unendorsed htlcs do not have a negative impact on reputation.
            if !incoming_endorsed && effective_fees < 0 {
                return Ok(0);
            }

            Ok(effective_fees)
        }
    }

    pub struct InFlightHtlc {
        pub fee_msat: u64,
        cltv_delta: u32,
        amount_msat: u64,
        added_instant: Instant,
        incoming_endorsed: EndorsementSignal,
    }

    pub struct ReputationTracker {
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
        pub fn new(
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
        pub fn outgoing_reputation(
            &mut self,
            access_instant: Instant,
        ) -> Result<i64, ReputationError> {
            self.outgoing_reputation.value_at_instant(access_instant)
        }

        /// Returns the total htlc risk of all the endorsed htlcs that are currently in flight. Unendorsed htlcs do not
        /// contribute to risk, so no option is given to count unendorsed risk.
        fn total_in_flight_risk(&self) -> u64 {
            self.outgoing_in_flight
                .iter()
                .filter(|(_, v)| v.incoming_endorsed == EndorsementSignal::Endorsed)
                .map(|(_, v)| self.params.htlc_risk(v.fee_msat, v.cltv_delta))
                .sum()
        }

        /// Returns the total balance of htlcs in flight in msat, filtering by provided endorsement signal.
        fn total_in_flight_msat(&self, endorsed: EndorsementSignal) -> u64 {
            self.outgoing_in_flight
                .iter()
                .filter(|(_, v)| v.incoming_endorsed == endorsed)
                .map(|(_, v)| v.amount_msat)
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
        pub fn new_reputation_check(
            &mut self,
            access_instant: Instant,
            incoming_revenue: i64,
            forward: &ProposedForward,
        ) -> Result<ReputationCheck, ReputationError> {
            let outgoing_reputation = self.outgoing_reputation(access_instant)?;
            let in_flight_total_risk = self.total_in_flight_risk();
            let htlc_risk = self
                .params
                .htlc_risk(forward.fee_msat(), forward.expiry_delta());

            Ok(ReputationCheck {
                outgoing_reputation,
                incoming_revenue,
                in_flight_total_risk,
                htlc_risk,
            })
        }

        /// Gets the current state of the general bucket's resources.
        pub fn general_bucket_resources(&self) -> ResourceCheck {
            ResourceCheck {
                general_slots_used: self.total_in_flight_count(EndorsementSignal::Unendorsed),
                general_slots_availabe: self.general_slot_count,
                general_liquidity_msat_used: self
                    .total_in_flight_msat(EndorsementSignal::Unendorsed),
                general_liquidity_msat_available: self.general_liquidity_msat,
            }
        }

        /// Adds an in flight htlc to the outgoing channel.
        pub fn add_outgoing_htlc(
            &mut self,
            forward: &ProposedForward,
        ) -> Result<(), ReputationError> {
            match self.outgoing_in_flight.entry(forward.incoming_ref) {
                Entry::Occupied(_) => Err(ReputationError::ErrDuplicateHtlc(forward.incoming_ref)),
                Entry::Vacant(v) => {
                    v.insert(InFlightHtlc {
                        cltv_delta: forward.expiry_delta(),
                        amount_msat: forward.amount_out_msat,
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
        pub fn remove_outgoing_htlc(
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
                in_flight.incoming_endorsed == EndorsementSignal::Endorsed,
                settled,
            )?;

            // Update reputation to reflect its reputation impact.
            let _ = self
                .outgoing_reputation
                .add_value(effective_fees, resolved_instant)?;

            Ok(in_flight)
        }
    }
}

mod decaying_average {
    use std::time::{Duration, Instant};

    use crate::reputation::ReputationError;

    /// Tracks a timestamped decaying average, which may be positive or negative. Acts
    pub struct DecayingAverage {
        value: i64,
        last_updated: Option<Instant>,
        decay_rate: f64,
    }

    impl DecayingAverage {
        pub fn new(period: Duration) -> Self {
            DecayingAverage {
                value: 0,
                last_updated: None,
                decay_rate: Self::calc_decay_rate(period),
            }
        }

        fn calc_decay_rate(period: Duration) -> f64 {
            0.5f64.powf(2.0 / period.as_secs_f64())
        }

        pub fn value_at_instant(
            &mut self,
            access_instant: Instant,
        ) -> Result<i64, ReputationError> {
            if let Some(last_updated) = self.last_updated {
                let elapsed = access_instant.duration_since(last_updated).as_secs_f64();
                if elapsed < 0.0 {
                    return Err(ReputationError::ErrUpdateInPast(
                        last_updated,
                        access_instant,
                    ));
                }

                self.value = self
                    .value
                    .saturating_mul(self.decay_rate.powf(elapsed) as i64); // TODO: does this rounding break things?
            }

            self.last_updated = Some(access_instant);
            Ok(self.value)
        }

        /// Updates the current value of the decaying average and then adds the new value provided. The value provided
        /// will act as a saturating add
        pub fn add_value(
            &mut self,
            value: i64,
            update_time: Instant,
        ) -> Result<i64, ReputationError> {
            // Progress current value to the new timestamp so that it'll be appropriately decayed.
            let _ = self.value_at_instant(update_time);

            // No need to decay the new value as we're now at our last updated time.
            self.value = self.value.saturating_add(value);
            self.last_updated = Some(update_time);
            Ok(self.value)
        }
    }
}

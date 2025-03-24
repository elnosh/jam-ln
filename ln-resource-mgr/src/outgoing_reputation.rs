use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ops::Sub;
use std::time::Instant;

use crate::decaying_average::DecayingAverage;
use crate::forward_manager::ReputationParams;
use crate::{
    EndorsementSignal, ForwardResolution, HtlcRef, ProposedForward, ReputationCheck,
    ReputationError, ResourceCheck,
};

#[derive(Clone, Debug)]
pub(super) struct InFlightHtlc {
    pub fee_msat: u64,
    hold_blocks: u32,
    outgoing_amt_msat: u64,
    added_instant: Instant,
    incoming_endorsed: EndorsementSignal,
}

#[derive(Clone, Debug)]
pub(super) struct OutgoingReputation {
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

impl OutgoingReputation {
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

    use super::OutgoingReputation;

    fn get_test_params() -> ReputationParams {
        ReputationParams {
            revenue_window: Duration::from_secs(60 * 60 * 24), // 1 week
            reputation_multiplier: 10,
            resolution_period: Duration::from_secs(60),
            expected_block_speed: Some(Duration::from_secs(60 * 10)),
        }
    }

    /// Returns a ReputationTracker with 100 general slots and 100_00 msat of general liquidity.
    fn get_test_tracker() -> OutgoingReputation {
        OutgoingReputation::new(get_test_params(), 100, 100_000).unwrap()
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

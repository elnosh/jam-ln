use crate::decaying_average::DecayingAverage;
use crate::outgoing_reputation::OutgoingChannel;
use crate::{
    validate_msat, AllocationCheck, EndorsementSignal, ForwardResolution, ForwardingOutcome,
    HtlcRef, ProposedForward, ReputationError, ReputationManager, ReputationSnapshot,
};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
    pub(super) fn htlc_risk(&self, fee_msat: u64, expiry_delta: u32) -> u64 {
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

/// Tracks reputation and revenue for a channel.
#[derive(Debug)]
struct TrackedChannel {
    outgoing_direction: OutgoingChannel,
    incoming_revenue: DecayingAverage,
}

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

/// Defines special actions that can be taken during a simulation that wouldn't otherwise be used in regular operation.
pub trait SimualtionDebugManager {
    fn general_jam_channel(&self, channel: u64) -> Result<(), ReputationError>;
}

/// Implements outgoing reputation algorithm and resource bucketing for an individual node.
#[derive(Debug)]
pub struct ForwardManager {
    params: ForwardManagerParams,
    inner: Mutex<ForwardManagerImpl>,
}

#[derive(Debug)]
struct ForwardManagerImpl {
    channels: HashMap<u64, TrackedChannel>,
}

impl ForwardManager {
    pub fn new(params: ForwardManagerParams) -> Self {
        Self {
            params,
            inner: Mutex::new(ForwardManagerImpl {
                channels: HashMap::new(),
            }),
        }
    }
}

impl SimualtionDebugManager for ForwardManager {
    fn general_jam_channel(&self, channel: u64) -> Result<(), ReputationError> {
        self.inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels
            .get_mut(&channel)
            .ok_or(ReputationError::ErrChannelNotFound(channel))?
            .outgoing_direction
            .general_jam_channel();

        Ok(())
    }
}

impl ReputationManager for ForwardManager {
    fn add_channel(&self, channel_id: u64, capacity_msat: u64) -> Result<(), ReputationError> {
        match self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels
            .entry(channel_id)
        {
            Entry::Occupied(_) => Err(ReputationError::ErrChannelExists(channel_id)),
            Entry::Vacant(v) => {
                let general_slot_count = 483 * self.params.general_slot_portion as u16 / 100;
                let general_liquidity_amount =
                    capacity_msat * self.params.general_liquidity_portion as u64 / 100;

                v.insert(TrackedChannel {
                    outgoing_direction: OutgoingChannel::new(
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
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels
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

        let inner_lock = &mut self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels;

        // Get the incoming revenue threshold that the outgoing channel must meet.
        let incoming_threshold = inner_lock
            .get_mut(&forward.incoming_ref.channel_id)
            .ok_or(ReputationError::ErrIncomingNotFound(
                forward.incoming_ref.channel_id,
            ))?
            .incoming_revenue
            .value_at_instant(forward.added_at)?;

        // Check reputation and resources available for the forward.
        let outgoing_channel = &mut inner_lock
            .get_mut(&forward.outgoing_channel_id)
            .ok_or(ReputationError::ErrOutgoingNotFound(
                forward.outgoing_channel_id,
            ))?
            .outgoing_direction;

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
            self.inner
                .lock()
                .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
                .channels
                .get_mut(&forward.outgoing_channel_id)
                .ok_or(ReputationError::ErrOutgoingNotFound(
                    forward.outgoing_channel_id,
                ))?
                .outgoing_direction
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
        let inner_lock = &mut self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels;

        // Remove from outgoing channel, which will return the amount that we need to add to the incoming channel's
        // revenue for forwarding the htlc.
        let outgoing_channel_tracker = inner_lock
            .get_mut(&outgoing_channel)
            .ok_or(ReputationError::ErrOutgoingNotFound(outgoing_channel))?;

        let in_flight = outgoing_channel_tracker
            .outgoing_direction
            .remove_outgoing_htlc(outgoing_channel, incoming_ref, resolution, resolved_instant)?;

        if resolution == ForwardResolution::Failed {
            return Ok(());
        }

        // If the htlc was settled, update *both* the outgoing and incoming channel's revenue trackers.
        let fee_i64 = i64::try_from(in_flight.fee_msat).unwrap_or(i64::MAX);

        let _ = outgoing_channel_tracker
            .incoming_revenue
            .add_value(fee_i64, resolved_instant)?;

        inner_lock
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
        let inner_lock = &mut self
            .inner
            .lock()
            .map_err(|e| ReputationError::ErrUnrecoverable(e.to_string()))?
            .channels;

        let mut reputations = HashMap::with_capacity(inner_lock.len());
        for (scid, channel) in inner_lock.iter_mut() {
            reputations.insert(
                *scid,
                ReputationSnapshot {
                    outgoing_reputation: channel
                        .outgoing_direction
                        .outgoing_reputation(access_ins)?,
                    incoming_revenue: channel.incoming_revenue.value_at_instant(access_ins)?,
                },
            );
        }

        Ok(reputations)
    }
}

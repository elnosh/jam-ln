use std::ops::Sub;
use std::time::Instant;

use crate::decaying_average::DecayingAverage;
use crate::forward_manager::BucketParameters;
use crate::htlc_manager::InFlightHtlc;
use crate::{ForwardResolution, ReputationError, ReputationParams, ResourceBucketType};

/// Tracks information about the usage of the channels when it is utilized as the incoming direction in a htlc forward.
#[derive(Debug)]
pub(super) struct IncomingChannel {
    params: ReputationParams,

    /// The reputation that the channel has accrued as the incoming link in htlc forwards. Tracked as a decaying
    /// average over the reputation_window that the tracker is created with.
    incoming_reputation: DecayingAverage,

    /// The resources available for htlcs that are not endorsed, or are not sent by a peer with sufficient reputation.
    pub(super) general_bucket: BucketParameters,

    /// The resources available for htlcs that are endorsed from peers that do not have sufficient reputation. This
    /// bucket is only used when the general bucket is full, and peers are limited to a single slot/liquidity block.
    pub(super) congestion_bucket: BucketParameters,

    /// Tracks the last instant that the incoming channel misused use of congested resources, if any.
    last_congestion_misuse: Option<Instant>,
}

impl IncomingChannel {
    pub(super) fn new(
        params: ReputationParams,
        general_bucket: BucketParameters,
        congestion_bucket: BucketParameters,
    ) -> Self {
        Self {
            params,
            incoming_reputation: DecayingAverage::new(
                params.revenue_window * params.reputation_multiplier.into(),
            ),
            general_bucket,
            congestion_bucket,
            last_congestion_misuse: None,
        }
    }

    /// Returns true if the channel has never misused congestion resources, or sufficient time has passed since last
    /// abuse (set by ReputationParams.revenue_window, as this is the period we can be jammed for).
    pub(super) fn no_congestion_misuse(&self, access_ins: Instant) -> bool {
        if let Some(instant) = self.last_congestion_misuse {
            access_ins.duration_since(instant) > self.params.revenue_window
        } else {
            true
        }
    }

    /// Returns the reputation that the channel has earned in the incoming direction over [`revenue_window *
    /// reputation_multiplier`].
    pub(super) fn incoming_reputation(
        &mut self,
        access_instant: Instant,
    ) -> Result<i64, ReputationError> {
        self.incoming_reputation.value_at_instant(access_instant)
    }

    /// Resolves an in flight htlc, updating use of congestion resources to reflect misuse, if any.
    pub(super) fn remove_incoming_htlc(
        &mut self,
        in_flight: &InFlightHtlc,
        resolution: ForwardResolution,
        resolved_ins: Instant,
    ) -> Result<(), ReputationError> {
        if in_flight.bucket == ResourceBucketType::Congestion
            && resolved_ins.duration_since(in_flight.added_instant) >= self.params.resolution_period
        {
            self.last_congestion_misuse = Some(resolved_ins)
        }

        let settled = resolution == ForwardResolution::Settled;
        let effective_fees = self.params.effective_fees(
            in_flight.fee_msat,
            resolved_ins.sub(in_flight.added_instant),
            in_flight.incoming_endorsed,
            settled,
        )?;

        // Update reputation to reflect its reputation impact.
        self.incoming_reputation
            .add_value(effective_fees, resolved_ins)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::IncomingChannel;
    use crate::forward_manager::BucketParameters;
    use crate::htlc_manager::InFlightHtlc;
    use crate::ForwardResolution;
    use crate::{EndorsementSignal, ReputationParams, ResourceBucketType};

    #[test]
    fn test_no_congestion_abuse() {
        let now = Instant::now();
        let params = ReputationParams {
            revenue_window: Duration::from_secs(60 * 60 * 24 * 14),
            reputation_multiplier: 12,
            resolution_period: Duration::from_secs(90),
            expected_block_speed: None,
        };
        let mut incoming_channel = IncomingChannel::new(
            params,
            BucketParameters {
                slot_count: 100,
                liquidity_msat: 100_000,
            },
            BucketParameters {
                slot_count: 30,
                liquidity_msat: 50_000,
            },
        );

        assert!(incoming_channel.no_congestion_misuse(now));

        // Fast resolving HTLC does not trigger misuse.
        incoming_channel
            .remove_incoming_htlc(
                &InFlightHtlc {
                    outgoing_channel_id: 1,
                    fee_msat: 100,
                    hold_blocks: 40,
                    incoming_amt_msat: 5000 + 100,
                    outgoing_amt_msat: 5000,
                    added_instant: now,
                    incoming_endorsed: EndorsementSignal::Endorsed,
                    bucket: ResourceBucketType::Congestion,
                },
                ForwardResolution::Settled,
                now.checked_add(params.resolution_period / 2).unwrap(),
            )
            .unwrap();
        assert!(incoming_channel.no_congestion_misuse(now));

        // Slow resolving HTLC does trigger misuse.
        let last_misuse = now.checked_add(params.resolution_period * 2).unwrap();
        incoming_channel
            .remove_incoming_htlc(
                &InFlightHtlc {
                    outgoing_channel_id: 1,
                    fee_msat: 100,
                    hold_blocks: 40,
                    incoming_amt_msat: 5000 + 100,
                    outgoing_amt_msat: 5000,
                    added_instant: now,
                    incoming_endorsed: EndorsementSignal::Endorsed,
                    bucket: ResourceBucketType::Congestion,
                },
                ForwardResolution::Settled,
                last_misuse,
            )
            .unwrap();
        assert!(!incoming_channel.no_congestion_misuse(now));

        // Only recover once the cooldown period has fully passed.
        let half_recovered = last_misuse.checked_add(params.revenue_window / 2).unwrap();
        assert!(!incoming_channel.no_congestion_misuse(half_recovered));

        let fully_recovered = last_misuse.checked_add(params.revenue_window).unwrap();
        assert!(!incoming_channel.no_congestion_misuse(fully_recovered));
    }
}

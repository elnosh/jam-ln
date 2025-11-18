use std::time::{Duration, Instant};

use ln_resource_mgr::decaying_average::DecayingAverage;
use ln_resource_mgr::forward_manager::ForwardManagerParams;
use ln_resource_mgr::ReputationError;

pub struct Channel {
    pub node_a: usize,
    pub node_b: usize,

    // fees earned every 2 weeks
    pub ab_fees: u64,
    pub ba_fees: u64,
    fwd_params: ForwardManagerParams,
}

impl Channel {
    pub fn a_reputation(&self, at: Instant) -> Result<i64, ReputationError> {
        self.simulated_reputation_for_fee(self.ab_fees, at)
    }

    fn simulated_reputation_for_fee(
        &self,
        fee_every_two_weeks: u64,
        at: Instant,
    ) -> Result<i64, ReputationError> {
        let two_weeks = Duration::from_secs(60 * 60 * 24 * 14);

        let params = self.fwd_params.reputation_params;
        let window = params.revenue_window * params.reputation_multiplier.into();
        let mut da = DecayingAverage::new(window);
        let fee_i64 = i64::try_from(fee_every_two_weeks).unwrap_or(i64::MAX);

        for i in 0..params.reputation_multiplier {
            let delta = two_weeks * (i as u32);
            let sample_time = at.checked_add(delta).unwrap_or(at);
            da.add_value(fee_i64, sample_time)?;
        }

        da.value_at_instant(
            at.checked_add(Duration::from_secs(window.as_secs()))
                .unwrap(),
        )
    }

    // returns # of loops over a
    pub fn loops_for_htlc(&self, htlc_cost: u64) -> Result<u8, ReputationError> {
        let a_reputation = self.a_reputation(Instant::now())?;
        let a_loops = (a_reputation as u64 - self.ba_fees) / htlc_cost;
        Ok(a_loops as u8)
    }
}

pub struct LoopAttack {
    pub node_count: usize,
    /// Channels in the circular route
    pub channels: Vec<Channel>,
    htlc_cost: u64,
}

impl LoopAttack {
    pub fn new(node_count: usize, htlc_amount_msat: u64) -> Self {
        assert!(node_count > 2, "Loop must have more than 2 nodes");

        let fwd_params = ForwardManagerParams::default();
        let htlc_cost = fwd_params
            .htlc_opportunity_cost(1000 + (0.0001 * htlc_amount_msat as f64) as u64, 2016);

        // Build circular channels: 0->1, 1->2, ..., N-1->0
        let mut channels = Vec::with_capacity(node_count);
        for i in 0..node_count {
            let node_a = i;
            let node_b = (i + 1) % node_count; // wrap to 0 for final edge
            channels.push(Channel {
                node_a,
                node_b,
                ab_fees: 0,
                ba_fees: 0,
                fwd_params,
            });
        }

        Self {
            node_count,
            channels,
            htlc_cost,
        }
    }

    /// Calculate the maximum number of identical HTLCs that can be placed around the circular
    /// route. This is the minimum per-hop capacity in the loop direction.
    pub fn max_loops_for_route(&self) -> Result<u8, ReputationError> {
        let mut min_capacity: Option<u8> = None;

        // HTLCs wont be the same amount since there are fees but this should be close
        // enough
        for ch in &self.channels {
            let cap_loops = ch.loops_for_htlc(self.htlc_cost)?;
            min_capacity = Some(match min_capacity {
                Some(current) => current.min(cap_loops),
                None => cap_loops,
            });
        }

        Ok(min_capacity.unwrap_or(0))
    }

    /// Cost to receive an accountable HTLC = min_revenue + HTLC cost.
    pub fn cost_to_receive_accountable_htlc(&self) -> Result<u64, ReputationError> {
        let mut min_fee = u64::MAX;
        for ch in &self.channels {
            min_fee = min_fee.min(ch.ba_fees);
        }
        Ok(min_fee.saturating_add(self.htlc_cost))
    }
}

mod tests {
    use crate::attacks::r#loop::LoopAttack;

    #[test]
    fn test_1() {
        let htlc_amount = 10_000_000;
        let mut attack = LoopAttack::new(3, htlc_amount);

        let fee_earned = 50_000_000;
        for channel in &mut attack.channels {
            channel.ab_fees = fee_earned;
            channel.ba_fees = fee_earned;
        }

        let max_loops = attack.max_loops_for_route().unwrap();
        let cost = attack.cost_to_receive_accountable_htlc().unwrap();

        println!("max # loops {}", max_loops);
        println!("cost to receive accountable HTLC {}", cost);
    }
}

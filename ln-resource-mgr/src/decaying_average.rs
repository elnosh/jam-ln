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

    pub fn value_at_instant(&mut self, access_instant: Instant) -> Result<i64, ReputationError> {
        if let Some(last_updated) = self.last_updated {
            let elapsed = access_instant.duration_since(last_updated).as_secs_f64();
            if elapsed < 0.0 {
                return Err(ReputationError::ErrUpdateInPast(
                    last_updated,
                    access_instant,
                ));
            }

            self.value = (self.value as f64 * self.decay_rate.powf(elapsed)).round() as i64;
        }

        self.last_updated = Some(access_instant);
        Ok(self.value)
    }

    /// Updates the current value of the decaying average and then adds the new value provided. The value provided
    /// will act as a saturating add
    pub fn add_value(&mut self, value: i64, update_time: Instant) -> Result<i64, ReputationError> {
        // Progress current value to the new timestamp so that it'll be appropriately decayed.
        let _ = self.value_at_instant(update_time);

        // No need to decay the new value as we're now at our last updated time.
        self.value = self.value.saturating_add(value);
        self.last_updated = Some(update_time);
        Ok(self.value)
    }
}

/// Describes the size of a resource bucket.
#[derive(Clone, Debug)]
pub struct BucketParameters {
    /// The number of HTLC slots available in the bucket.
    pub slot_count: u16,
    /// The amount of liquidity available in the bucket.
    pub liquidity_msat: u64,
}

/// Tracks resources available on the channel when it is utilized as the incoming direction in a htlc forward.
#[derive(Debug)]
pub(super) struct IncomingChannel {
    /// The resources available for htlcs that are not accountable, or are not sent by a peer with sufficient reputation.
    pub(super) general_bucket: BucketParameters,

    /// The resources available for htlcs that are accountable from peers that do not have sufficient reputation. This
    /// bucket is only used when the general bucket is full, and peers are limited to a single slot/liquidity block.
    pub(super) congestion_bucket: BucketParameters,
}

impl IncomingChannel {
    pub(super) fn new(
        general_bucket: BucketParameters,
        congestion_bucket: BucketParameters,
    ) -> Self {
        Self {
            general_bucket,
            congestion_bucket,
        }
    }

    pub(super) fn general_jam_channel(&mut self) {
        self.general_bucket = BucketParameters {
            slot_count: 0,
            liquidity_msat: 0,
        };
    }
}

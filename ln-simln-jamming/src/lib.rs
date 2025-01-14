use ln_resource_mgr::EndorsementSignal;
use simln_lib::sim_node::CustomRecords;
use std::error::Error;

pub mod clock;
pub mod parsing;
pub mod reputation_interceptor;
pub mod revenue_interceptor;
pub mod sink_interceptor;

/// Error type for errors that can be erased, includes 'static so that down-casting is possible.
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// The TLV type used to represent experimental endorsement signals.
pub const ENDORSEMENT_TYPE: u64 = 106823;

/// Converts a set of custom tlv records to an endorsement signal.
pub fn endorsement_from_records(records: &CustomRecords) -> EndorsementSignal {
    match records.get(&ENDORSEMENT_TYPE) {
        Some(endorsed) => {
            if endorsed.len() == 1 && endorsed[0] == 1 {
                EndorsementSignal::Endorsed
            } else {
                EndorsementSignal::Unendorsed
            }
        }
        None => EndorsementSignal::Unendorsed,
    }
}

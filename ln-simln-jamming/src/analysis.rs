use crate::BoxError;
use bitcoin::secp256k1::PublicKey;
use csv::WriterBuilder;
use ln_resource_mgr::{AllocationCheck, ProposedForward};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::fs::{metadata, OpenOptions};

/// Implemented to report forwards for analytics and data recording.
pub trait ForwardReporter: Send + Sync {
    fn report_forward(
        &mut self,
        forwarding_node: PublicKey,
        decision: AllocationCheck,
        forward: ProposedForward,
    ) -> Result<(), BoxError>;
}

struct Record {
    forward: ProposedForward,
    decision: AllocationCheck,
}

impl Serialize for Record {
    /// Serializes a record as a single flat struct, including forwarding outcome for its allocation check. Implemented
    /// as custom serialization because serde + csv can't handle headers for custom structs, and we need to do some
    /// transformations on the data.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Record", 14)?;
        state.serialize_field("incoming_channel_id", &self.forward.incoming_ref.channel_id)?;
        state.serialize_field("outgoing_channel_id", &self.forward.outgoing_channel_id)?;
        state.serialize_field("amount_in_msat", &self.forward.amount_in_msat)?;
        state.serialize_field("amount_out_msat", &self.forward.amount_out_msat)?;
        state.serialize_field("expiry_in_height", &self.forward.expiry_in_height)?;
        state.serialize_field("expiry_out_height", &self.forward.expiry_out_height)?;
        state.serialize_field("incoming_endorsed", &self.forward.incoming_endorsed)?;
        state.serialize_field(
            "forwarding_outcome",
            &self
                .decision
                .forwarding_outcome(self.forward.amount_in_msat, self.forward.incoming_endorsed),
        )?;
        state.serialize_field(
            "incoming_revenue",
            &self.decision.reputation_check.incoming_revenue,
        )?;
        state.serialize_field(
            "outgoing_reputation",
            &self.decision.reputation_check.outgoing_reputation,
        )?;
        state.serialize_field("htlc_risk", &self.decision.reputation_check.htlc_risk)?;
        state.serialize_field(
            "in_flight_risk",
            &self.decision.reputation_check.in_flight_total_risk,
        )?;
        state.serialize_field(
            "slots_available",
            &self.decision.resource_check.general_slots_availabe,
        )?;
        state.serialize_field(
            "liquidity_available",
            &self
                .decision
                .resource_check
                .general_liquidity_msat_available,
        )?;
        state.end()
    }
}

/// Tracks a set of nodes to record forward decisions for and periodically writes them to disk.
pub struct BatchForwardWriter {
    /// The set of nodes that we want to store forward results for.
    nodes: HashMap<PublicKey, (Vec<Record>, String)>,
    /// The number of forwards to accumulate in memory before writing to disk.
    batch_size: u16,
    record_count: u16,
}

impl BatchForwardWriter {
    pub fn new(nodes: &[(PublicKey, String)], batch_size: u16) -> Self {
        Self {
            nodes: nodes
                .iter()
                .cloned()
                .map(|(pubkey, alias)| (pubkey, (vec![], alias)))
                .collect(),
            batch_size,
            record_count: 0,
        }
    }

    pub fn write(&mut self) -> Result<(), BoxError> {
        if self.record_count < self.batch_size {
            return Ok(());
        }

        for (pubkey, (records, alias)) in self.nodes.iter_mut() {
            if records.is_empty() {
                continue;
            }

            write_records_for_node(get_filename(pubkey, alias.to_string()), records)?;
            records.clear();
        }
        self.record_count = 0;

        Ok(())
    }
}

fn get_filename(node: &PublicKey, alias: String) -> String {
    format!("{alias}_{}.csv", &node.to_string()[0..6])
}

fn write_records_for_node(filename: String, records: &[Record]) -> Result<(), BoxError> {
    let file_exists = metadata(&filename).is_ok();

    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&filename)?;

    let mut writer = WriterBuilder::new()
        .has_headers(!file_exists)
        .from_writer(file);

    for record in records {
        writer.serialize(record)?;
    }

    writer.flush().map_err(|e| e.into())
}

impl ForwardReporter for BatchForwardWriter {
    /// Queues a forward for write to disk if it's one of the nodes that we're interested in.
    fn report_forward(
        &mut self,
        forwarding_node: PublicKey,
        decision: AllocationCheck,
        forward: ProposedForward,
    ) -> Result<(), BoxError> {
        if let Some((records, _)) = self.nodes.get_mut(&forwarding_node) {
            records.push(Record { decision, forward });
            self.record_count += 1;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::read_to_string;
    use std::path::Path;
    use std::time::SystemTime;

    use crate::analysis::get_filename;
    use crate::test_utils::{get_random_keypair, test_allocation_check, test_proposed_forward};

    use super::{BatchForwardWriter, ForwardReporter};

    /// Tests that only forwards on nodes of interest are queued for writing.
    #[test]
    fn test_report_forward() {
        let node_0 = get_random_keypair().1;
        let node_1 = get_random_keypair().1;

        let mut writer = BatchForwardWriter::new(&[(node_0, "0".to_string())], 5);

        // Tracked node reported.
        let tracked_forward = test_proposed_forward(0);
        writer
            .report_forward(node_0, test_allocation_check(true), tracked_forward.clone())
            .unwrap();
        assert_eq!(writer.record_count, 1);

        // Non-tracked node ignored.
        writer
            .report_forward(
                node_1,
                test_allocation_check(true),
                test_proposed_forward(1),
            )
            .unwrap();
        assert_eq!(writer.record_count, 1);

        let node_0_records = &writer.nodes.get(&node_0).unwrap().0;
        assert_eq!(node_0_records.len(), 1);
        assert_eq!(node_0_records[0].forward, tracked_forward);
    }

    /// Tests flushing of records to disk, using the current time to ensure a unique filename that can be cleaned up
    /// after.
    #[test]
    fn test_write_records() {
        let node_0 = get_random_keypair().1;
        let node_1 = get_random_keypair().1;

        let alias = format!(
            "test_{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        let filename = get_filename(&node_0, alias.clone());

        let mut writer = BatchForwardWriter::new(&[(node_0, alias)], 2);

        // Track a forward that should be written to disk.
        writer
            .report_forward(
                node_0,
                test_allocation_check(true),
                test_proposed_forward(0),
            )
            .unwrap();
        assert_eq!(writer.record_count, 1);

        // Writing with a single record shouldn't go to disk yet.
        writer.write().unwrap();
        assert!(!Path::new(&filename).exists());

        // Non-tracked node ignored and not written to disk.
        writer
            .report_forward(
                node_1,
                test_allocation_check(true),
                test_proposed_forward(1),
            )
            .unwrap();
        writer.write().unwrap();
        assert!(!Path::new(&filename).exists());

        // Tracked record meets threshold is written to disk with a header line and our two records.
        writer
            .report_forward(
                node_0,
                test_allocation_check(true),
                test_proposed_forward(2),
            )
            .unwrap();
        assert_eq!(writer.record_count, 2);

        writer.write().unwrap();
        assert_eq!(read_to_string(&filename).unwrap().lines().count(), 3);

        // Write three more tracked forward and assert the file is updated.
        writer
            .report_forward(
                node_0,
                test_allocation_check(true),
                test_proposed_forward(3),
            )
            .unwrap();
        writer
            .report_forward(
                node_0,
                test_allocation_check(true),
                test_proposed_forward(4),
            )
            .unwrap();
        writer
            .report_forward(
                node_0,
                test_allocation_check(true),
                test_proposed_forward(5),
            )
            .unwrap();

        writer.write().unwrap();
        assert_eq!(read_to_string(&filename).unwrap().lines().count(), 6);

        std::fs::remove_file(filename).unwrap();
    }
}

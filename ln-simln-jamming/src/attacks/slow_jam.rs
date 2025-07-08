use crate::{
    accountable_from_records,
    attacks::JammingAttack,
    clock::InstantClock,
    records_from_signal,
    reputation_interceptor::{GeneralChannelJammer, ReputationMonitor},
    BoxError,
};

use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use lightning::routing::gossip::NetworkGraph;
use rand::Rng;
use sim_cli::parsing::NetworkParser;
use simln_lib::{
    clock::Clock,
    sim_node::{CustomRecords, ForwardingError, InterceptRequest, SimGraph, SimNode, WrappedLog},
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use triggered::Listener;

use super::utils::build_reputation;

// idea: attacker1 -> peer1 -> target -> attacker2
// build reputation on attacker2 and jam channel peer1 <-> target

type LdkNetworkGraph = NetworkGraph<Arc<WrappedLog>>;

pub struct SlowJam<C, J, R>
where
    C: Clock + InstantClock,
    R: ReputationMonitor + Send + Sync,
    J: GeneralChannelJammer + Send + Sync,
{
    clock: Arc<C>,
    target_pubkey: PublicKey,
    attacker_sender: (String, PublicKey),
    attacker: (String, PublicKey),
    target_channels: HashMap<u64, PublicKey>,
    channel_to_jam: (PublicKey, u64),
    risk_margin: u64,
    reputation_monitor: Arc<Mutex<R>>,
    general_jammer: Arc<Mutex<J>>,
    network_graph: Arc<LdkNetworkGraph>,
}

impl<C, J, R> SlowJam<C, J, R>
where
    C: Clock + InstantClock,
    R: ReputationMonitor + Send + Sync,
    J: GeneralChannelJammer + Send + Sync,
{
    pub fn new(
        clock: Arc<C>,
        network: &[NetworkParser],
        target_pubkey: PublicKey,
        attacker_sender: (String, PublicKey),
        attacker: (String, PublicKey),
        channel_to_jam: (PublicKey, u64),
        risk_margin: u64,
        reputation_monitor: Arc<Mutex<R>>,
        general_jammer: Arc<Mutex<J>>,
        network_graph: Arc<LdkNetworkGraph>,
    ) -> Self {
        Self {
            clock,
            target_pubkey,
            attacker_sender,
            attacker,
            target_channels: HashMap::from_iter(network.iter().filter_map(|channel| {
                if channel.node_1.pubkey == target_pubkey {
                    Some((channel.scid.into(), channel.node_2.pubkey))
                } else if channel.node_2.pubkey == target_pubkey {
                    Some((channel.scid.into(), channel.node_1.pubkey))
                } else {
                    None
                }
            })),
            channel_to_jam,
            risk_margin,
            reputation_monitor,
            general_jammer,
            network_graph,
        }
    }

    pub async fn build_reputation(
        &self,
        attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph>>>>,
        target_channel: (PublicKey, u64),
    ) -> Result<u64, BoxError> {
        let hops = vec![self.target_pubkey, self.attacker.1];

        let attacker_node_sender = attacker_nodes.get(&self.attacker_sender.0).ok_or(format!(
            "node {} not found in attacker nodes list",
            self.attacker_sender.0
        ))?;

        let fees_paid = build_reputation(
            Arc::clone(attacker_node_sender),
            &hops,
            &self.network_graph,
            vec![10_000_000],
            self.risk_margin,
            target_channel,
            Arc::clone(&self.reputation_monitor),
            Arc::clone(&self.clock),
        )
        .await?;

        let to_attacker_channel = self
            .target_channels
            .iter()
            .find(|chan| self.attacker.1 == *chan.1)
            .ok_or(format!(
                "Target does not have a channel with {}",
                self.attacker.1
            ))?
            .0;

        let target_channel_snapshots = self
            .reputation_monitor
            .lock()
            .await
            .list_channels(self.target_pubkey, InstantClock::now(&*self.clock))
            .await?;

        let to_attacker_channel_snapshot = target_channel_snapshots
            .get(to_attacker_channel)
            .ok_or(format!("Channel {} not found", to_attacker_channel))?; // this shouldn't happen

        let peer_target_channel = target_channel_snapshots
            .get(&target_channel.1)
            .ok_or(format!("Channel {} not found", target_channel.1))?;

        if to_attacker_channel_snapshot.outgoing_reputation
            >= peer_target_channel.bidirectional_revenue + self.risk_margin as i64
        {
            println!(
                "Finished building reputation. It cost {} in fees",
                fees_paid
            );
            return Ok(fees_paid);
        }

        Err("could not build reputation".into())
    }
}

pub fn get_random_bytes() -> [u8; 32] {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    bytes
}

#[async_trait]
impl<C, J, R> JammingAttack for SlowJam<C, J, R>
where
    C: Clock + InstantClock,
    R: ReputationMonitor + Send + Sync,
    J: GeneralChannelJammer + Send + Sync,
{
    async fn intercept_attacker_htlc(
        &self,
        req: InterceptRequest,
    ) -> Result<Result<CustomRecords, ForwardingError>, BoxError> {
        return Ok(Ok(records_from_signal(accountable_from_records(
            &req.incoming_custom_records,
        ))));
    }

    async fn run_custom_actions(
        &self,
        attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph>>>>,
        _shutdown_listener: Listener,
    ) -> Result<(), BoxError> {
        // - Build reputation with helper
        // - after building reputation, jam general resources.
        // - use congestion
        // - with sufficient reputation, continuously jam protected resources by sending slow (80s)
        //  resolving payments that don't slash reputation.

        let fees_paid = self
            .build_reputation(attacker_nodes, self.channel_to_jam)
            .await?;

        // after building reputation, jam general resources.
        self.general_jammer
            .lock()
            .await
            .jam_channel(&self.target_pubkey, self.channel_to_jam.1)
            .await?;

        //  send payments from multiple channels to use congestion resources.

        // with reputation, jam protected resources by sending 80s resolving payments continuously.
        // NOTE: prob better to occupy protected slots with low-value htlcs.
        Ok(())
    }
}

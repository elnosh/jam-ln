use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use ln_resource_mgr::forward_manager::ForwardManagerParams;
use ln_resource_mgr::ReputationParams;
use ln_simln_jamming::analysis::BatchForwardWriter;
use ln_simln_jamming::clock::InstantClock;
use ln_simln_jamming::parsing::{get_history_for_bootstrap, history_from_file, Cli};
use ln_simln_jamming::reputation_interceptor::ReputationInterceptor;
use ln_simln_jamming::revenue_interceptor::{RevenueInterceptor, RevenueSnapshot};
use ln_simln_jamming::sink_interceptor::{NetworkReputation, SinkInterceptor, TargetChannelType};
use ln_simln_jamming::BoxError;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use simln_lib::clock::Clock;
use simln_lib::clock::SimulationClock;
use simln_lib::interceptors::LatencyIntercepor;
use simln_lib::sim_node::{Interceptor, SimulatedChannel};
use simln_lib::{NetworkParser, ShortChannelID, Simulation, SimulationCfg};
use simple_logger::SimpleLogger;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::select;
use tokio::task::JoinSet;

#[derive(Serialize, Deserialize)]
pub struct SimNetwork {
    #[serde(default)]
    pub sim_network: Vec<NetworkParser>,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        // Lower logging from sim-ln so that we can focus on our own logs.
        .with_module_level("simln_lib", LevelFilter::Info)
        .with_module_level("sim_cli", LevelFilter::Off)
        // Debug so that we can read interceptor-related logging.
        .with_module_level("simln_lib::sim_node", LevelFilter::Debug)
        .init()
        .unwrap();

    let cli = Cli::parse();
    cli.validate()?;

    let SimNetwork { sim_network } =
        serde_json::from_str(&fs::read_to_string(cli.sim_file.as_path())?)?;

    let mut tasks = JoinSet::new();
    let (shutdown, listener) = triggered::trigger();

    // Match the target alias using pubkeys provided in sim network file, then collect the pubkeys of all the
    // non-attacker target peers.
    let target_pubkey = find_pubkey_by_alias(&cli.target_alias, &sim_network)?;
    let attacker_pubkey = find_pubkey_by_alias(&cli.attacker_alias, &sim_network)?;

    let target_channels =
        get_target_channel_descriptions(&sim_network, attacker_pubkey, target_pubkey);

    // We want to monitor results for all non-attacking nodes and the target node.
    let mut monitor_nodes = target_channels
        .iter()
        .filter_map(|(_, channel)| {
            if channel.channel_type == TargetChannelType::Peer {
                return Some((channel.peer_pubkey, channel.alias.clone()));
            }

            None
        })
        .collect::<Vec<(PublicKey, String)>>();
    monitor_nodes.push((target_pubkey, cli.target_alias.to_string()));

    // Create a map of all the target's channels, and a vec of its non-attacking peers.
    let target_channel_map = target_channels
        .values()
        .map(|channel| (channel.scid, channel.channel_type.clone()))
        .collect();

    let honest_peers = target_channels
        .iter()
        .filter_map(|(_, channel)| {
            if channel.channel_type == TargetChannelType::Peer {
                Some(channel.peer_pubkey)
            } else {
                None
            }
        })
        .collect();

    let jammed_peers = target_channels
        .iter()
        .filter_map(|(scid, channel)| {
            if channel.channel_type == TargetChannelType::Peer {
                let scid = *scid;
                Some((channel.peer_pubkey, scid.into()))
            } else {
                None
            }
        })
        .collect();

    let target_to_attacker: Vec<u64> = target_channels
        .iter()
        .filter(|(_, channel)| channel.channel_type == TargetChannelType::Attacker)
        .map(|(scid, _)| u64::from(*scid))
        .collect();

    if target_to_attacker.len() != 1 {
        return Err(format!(
            "expected one target -> attacker channel, got: {}",
            target_to_attacker.len()
        )
        .into());
    }

    // Pull history that bootstraps the simulation in a network with the attacker's channels present, filter to only
    // have attacker forwards present when the and calculate revenue for the target node during this bootstrap period.
    let unfiltered_history = history_from_file(&cli.bootstrap_file, Some(cli.reputation_window()))?;
    let bootstrap = get_history_for_bootstrap(
        cli.attacker_bootstrap,
        unfiltered_history,
        *target_to_attacker.first().unwrap(),
    )?;
    let bootstrap_revenue = bootstrap.forwards.iter().fold(0, |acc, item| {
        if item.forwarding_node == target_pubkey {
            acc + item.incoming_amt - item.outgoing_amt
        } else {
            acc
        }
    });

    // Use the channel jamming interceptor and latency for simulated payments.
    let latency_interceptor: Arc<dyn Interceptor> =
        Arc::new(LatencyIntercepor::new_poisson(150.0)?);

    let clock = Arc::new(SimulationClock::new(cli.clock_speedup)?);
    let forward_params = ForwardManagerParams {
        reputation_params: ReputationParams {
            revenue_window: Duration::from_secs(cli.revenue_window_seconds),
            reputation_multiplier: cli.reputation_multiplier,
            resolution_period: Duration::from_secs(90),
            expected_block_speed: Some(Duration::from_secs(10 * 60)),
        },
        general_slot_portion: 50,
        general_liquidity_portion: 50,
    };

    // Create a writer to store results for nodes that we care about.
    let results_writer = Arc::new(Mutex::new(BatchForwardWriter::new(
        cli.results_dir.clone(),
        &monitor_nodes,
        cli.result_batch_size,
        InstantClock::now(&*clock),
    )));

    let results_writer_1 = results_writer.clone();
    let results_listener = listener.clone();
    let results_shutdown = shutdown.clone();
    let results_clock = clock.clone();
    tasks.spawn(async move {
        let interval = Duration::from_secs(60);
        loop {
            select! {
                _ = results_listener.clone() => return,
                _ = results_clock.sleep(interval) => {
                      if let Err(e) = results_writer_1.lock().unwrap().write(){
                        log::error!("Error writing results: {e}");
                        results_shutdown.trigger();
                        return
                    }
                }
            }
        }
    });

    let attack_interceptor = SinkInterceptor::new_for_network(
        clock.clone(),
        attacker_pubkey,
        target_pubkey,
        target_channel_map,
        honest_peers,
        ReputationInterceptor::new_with_bootstrap(
            forward_params,
            &sim_network,
            jammed_peers,
            &bootstrap,
            clock.clone(),
            Some(results_writer),
            shutdown.clone(),
        )
        .await?,
        listener.clone(),
        shutdown.clone(),
    );

    // Do some preliminary checks on our reputation state - there isn't much point in running if we haven't built up
    // some reputation.
    let start_reputation = attack_interceptor
        .get_reputation_status(InstantClock::now(&*clock))
        .await?;

    check_reputation_status(&cli, &forward_params, &start_reputation, true)?;

    let attack_interceptor = Arc::new(attack_interceptor);

    // Spawn a task that will trigger shutdown of the simulation if the attacker loses reputation.
    let attack_interceptor_1 = attack_interceptor.clone();
    let attack_clock = clock.clone();
    let attack_listener = listener.clone();
    let attack_shutdown = shutdown.clone();
    let reputation_threshold = forward_params.htlc_opportunity_cost(
        get_reputation_margin_fee(cli.reputation_margin_msat),
        cli.reputation_margin_expiry_blocks,
    );

    tasks.spawn(async move {
    let interval = Duration::from_secs(cli.attacker_poll_interval_seconds);
    loop {
        select! {
            _ = attack_listener.clone() => return,
            _ = attack_clock.sleep(interval) => {
                match attack_interceptor_1
                    .get_target_pairs(
                        target_pubkey,
                        TargetChannelType::Attacker,
                        InstantClock::now(&*attack_clock),
                    )
                .await {
                    Ok(rep) => {
                        if !rep.iter().any(|pair| pair.outgoing_reputation(reputation_threshold)) {
                            log::error!("Attacker has no more reputation with the target");
                            attack_shutdown.trigger();
                            return;
                        }
                    },
                    Err(e) => {
                        log::error!("Error checking attacker reputation: {e}");
                        attack_shutdown.trigger();
                        return;
                    },
                }
            }
        }
    }});

    let revenue_interceptor = Arc::new(RevenueInterceptor::new_with_bootstrap(
        clock.clone(),
        target_pubkey,
        bootstrap_revenue,
        cli.attacker_bootstrap,
        cli.peacetime_file,
        listener.clone(),
        shutdown.clone(),
    )?);

    let revenue_interceptor_1 = revenue_interceptor.clone();
    let revenue_shutdown = shutdown.clone();
    tasks.spawn(async move {
        if let Err(e) = revenue_interceptor_1.process_peacetime_fwds().await {
            log::error!("Error processing peacetime forwards: {e}");
            revenue_shutdown.trigger();
        }
    });

    let revenue_interceptor_2 = revenue_interceptor.clone();
    let revenue_shutdown = shutdown.clone();
    tasks.spawn(async move {
        if let Err(e) = revenue_interceptor_2
            .poll_revenue_difference(Duration::from_secs(5))
            .await
        {
            log::error!("Error polling revenue difference: {e}");
            revenue_shutdown.trigger();
        }
    });

    let interceptors = vec![
        latency_interceptor,
        attack_interceptor.clone(),
        revenue_interceptor.clone(),
    ];

    // Simulated channels for our simulated graph.
    let channels = sim_network
        .clone()
        .into_iter()
        .map(SimulatedChannel::from)
        .collect::<Vec<SimulatedChannel>>();

    // Setup the simulated network with our fake graph.
    let (simulation, graph) = Simulation::new_with_sim_network(
        SimulationCfg::new(None, 3_800_000, 2.0, None, Some(13995354354227336701)),
        channels,
        vec![], // No activities, we want random activity!
        clock.clone(),
        interceptors,
        listener,
        shutdown,
    )
    .await
    .map_err(|e| anyhow::anyhow!(e))?;

    // Run simulation until it shuts down, then wait for the graph to exit.
    simulation.run().await?;
    graph.lock().await.wait_for_shutdown().await;

    // Write start and end state to a summary file.
    let end_reputation = attack_interceptor
        .get_reputation_status(InstantClock::now(&*clock))
        .await?;

    let snapshot = revenue_interceptor.get_revenue_difference().await;
    write_simulation_summary(
        cli.results_dir,
        cli.reputation_margin_msat,
        cli.reputation_margin_expiry_blocks,
        &forward_params,
        &snapshot,
        &start_reputation,
        &end_reputation,
    )?;

    Ok(())
}

struct TargetChannel {
    /// The public key of the target's counterparty.
    peer_pubkey: PublicKey,
    scid: ShortChannelID,
    alias: String,
    channel_type: TargetChannelType,
}

fn get_target_channel_descriptions(
    edges: &[NetworkParser],
    attacker_pubkey: PublicKey,
    target_pubkey: PublicKey,
) -> HashMap<ShortChannelID, TargetChannel> {
    let mut target_channels = HashMap::new();

    for channel in edges.iter() {
        let node_1_target = channel.node_1.pubkey == target_pubkey;
        let node_2_target = channel.node_2.pubkey == target_pubkey;

        if !(node_1_target || node_2_target) {
            continue;
        }

        let chan_policy = if node_1_target {
            &channel.node_2
        } else {
            &channel.node_1
        };

        let channel_type = if chan_policy.pubkey == attacker_pubkey {
            TargetChannelType::Attacker
        } else {
            TargetChannelType::Peer
        };

        target_channels.insert(
            channel.scid,
            TargetChannel {
                peer_pubkey: chan_policy.pubkey,
                scid: channel.scid,
                alias: chan_policy.alias.clone(),
                channel_type,
            },
        );
    }

    target_channels
}

fn find_pubkey_by_alias(alias: &str, sim_network: &[NetworkParser]) -> Result<PublicKey, BoxError> {
    let target_channel = sim_network
        .iter()
        .find(|hist| hist.node_1.alias == alias || hist.node_2.alias == alias)
        .ok_or(format!("alias: {alias} not found in sim file"))?;

    Ok(if target_channel.node_1.alias == alias {
        target_channel.node_1.pubkey
    } else {
        target_channel.node_2.pubkey
    })
}

fn get_reputation_margin_fee(reputation_margin_msat: u64) -> u64 {
    1000 + (0.0001 * reputation_margin_msat as f64) as u64
}

fn get_reputation_count(
    reputation_margin_msat: u64,
    reputation_margin_expiry_blocks: u32,
    params: &ForwardManagerParams,
    status: &NetworkReputation,
) -> (usize, usize) {
    let margin_fee = get_reputation_margin_fee(reputation_margin_msat);

    let attacker_reputation =
        status.reputation_count(false, params, margin_fee, reputation_margin_expiry_blocks);

    let target_reputation =
        status.reputation_count(true, params, margin_fee, reputation_margin_expiry_blocks);

    (attacker_reputation, target_reputation)
}

/// Gets reputation pairs for the target node and attacking node, logs them and optionally checking that each node
/// meets the configured threshold of good reputation if require_reputation is set.
fn check_reputation_status(
    cli: &Cli,
    params: &ForwardManagerParams,
    status: &NetworkReputation,
    require_reputation: bool,
) -> Result<(), BoxError> {
    let (attacker_reputation, target_reputation) = get_reputation_count(
        cli.reputation_margin_msat,
        cli.reputation_margin_expiry_blocks,
        params,
        status,
    );

    log::info!(
        "Attacker has {} out of {} pairs with reputation",
        attacker_reputation,
        status.attacker_reputation.len()
    );

    log::info!(
        "Target has {}/{} pairs with reputation with its peers",
        target_reputation,
        status.target_reputation.len()
    );

    if !require_reputation {
        return Ok(());
    }

    let attacker_threshold =
        status.attacker_reputation.len() * cli.attacker_reputation_percent as usize / 100;
    if attacker_reputation < attacker_threshold {
        return Err(format!(
            "attacker has {}/{} good reputation pairs which does not meet threshold {}",
            attacker_reputation,
            status.attacker_reputation.len(),
            attacker_threshold,
        )
        .into());
    }

    let target_threshold =
        status.target_reputation.len() * cli.target_reputation_percent as usize / 100;
    if target_reputation < target_threshold {
        return Err(format!(
            "target has {}/{} good reputation pairs which does not meet threshold {}",
            target_reputation,
            status.target_reputation.len(),
            target_threshold,
        )
        .into());
    }

    Ok(())
}

fn write_simulation_summary(
    data_dir: PathBuf,
    reputation_margin_msat: u64,
    reputation_margin_expiry_blocks: u32,
    params: &ForwardManagerParams,
    revenue: &RevenueSnapshot,
    start_reputation: &NetworkReputation,
    end_reputation: &NetworkReputation,
) -> Result<(), BoxError> {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(data_dir.join("summary.txt"))?;

    let mut writer = BufWriter::new(file);

    writeln!(writer, "Runtime (seconds): {:?}", revenue.runtime.as_secs())?;
    writeln!(
        writer,
        "Peacetime revenue (msat): {}",
        revenue.peacetime_revenue_msat
    )?;
    writeln!(
        writer,
        "Simulation revenue (msat): {}",
        revenue.simulation_revenue_msat,
    )?;

    if revenue.simulation_revenue_msat > revenue.peacetime_revenue_msat {
        writeln!(
            writer,
            "Revenue gain in simulation: {}",
            revenue.simulation_revenue_msat - revenue.peacetime_revenue_msat,
        )?;
    } else {
        writeln!(
            writer,
            "Revenue loss in simulation: {}",
            revenue.peacetime_revenue_msat - revenue.simulation_revenue_msat,
        )?;
    }

    let start_count = get_reputation_count(
        reputation_margin_msat,
        reputation_margin_expiry_blocks,
        params,
        start_reputation,
    );
    let end_count = get_reputation_count(
        reputation_margin_msat,
        reputation_margin_expiry_blocks,
        params,
        end_reputation,
    );
    writeln!(
        writer,
        "Attacker start reputation (pairs): {}/{}",
        start_count.0,
        start_reputation.attacker_reputation.len()
    )?;
    writeln!(
        writer,
        "Attacker end reputation (pairs): {}/{}",
        end_count.0,
        end_reputation.attacker_reputation.len()
    )?;

    writeln!(
        writer,
        "Target start reputation (pairs): {}/{}",
        start_count.1,
        start_reputation.target_reputation.len()
    )?;
    writeln!(
        writer,
        "Target end reputation (pairs): {}/{}",
        end_count.1,
        end_reputation.target_reputation.len()
    )?;
    writer.flush()?;

    Ok(())
}

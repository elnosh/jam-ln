use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use core::panic;
use ln_simln_jamming::analysis::BatchForwardWriter;
use ln_simln_jamming::attack_interceptor::AttackInterceptor;
use ln_simln_jamming::clock::InstantClock;
use ln_simln_jamming::parsing::{
    find_pubkey_by_alias, reputation_snapshot_from_file, setup_attack, AttackType, Cli,
    SimulationFiles, TrafficType,
};
use ln_simln_jamming::reputation_interceptor::{ChannelJammer, ReputationInterceptor};
use ln_simln_jamming::revenue_interceptor::{
    PeacetimeRevenueMonitor, RevenueInterceptor, RevenueSnapshot,
};
use ln_simln_jamming::{
    get_network_reputation, BoxError, NetworkReputation, ACCOUNTABLE_TYPE, UPGRADABLE_TYPE,
};
use log::LevelFilter;
use sim_cli::parsing::{create_simulation_with_network, SimParams};
use simln_lib::clock::Clock;
use simln_lib::clock::SimulationClock;
use simln_lib::latency_interceptor::LatencyIntercepor;
use simln_lib::sim_node::{CustomRecords, Interceptor, SimGraph, SimNode};
use simln_lib::SimulationCfg;
use simple_logger::SimpleLogger;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::sync::Mutex;
use tokio_util::task::TaskTracker;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();
    let forward_params = cli.validate()?;

    SimpleLogger::new()
        .with_level(cli.log_level)
        // Lower logging from sim-ln so that we can focus on our own logs.
        .with_module_level("simln_lib", LevelFilter::Info)
        .with_module_level("sim_cli", LevelFilter::Off)
        // Debug so that we can read interceptor-related logging.
        .with_module_level("simln_lib::sim_node", LevelFilter::Debug)
        .init()
        .unwrap();

    // We always want to load the attack time graph when running the simulation.
    let network_dir =
        SimulationFiles::new(cli.network.network_dir.clone(), TrafficType::Attacktime)?;
    let target_pubkey = network_dir.target.1;

    let tasks = TaskTracker::new();
    let (shutdown, listener) = triggered::trigger();

    let target_channels: HashMap<u64, (PublicKey, String)> = network_dir
        .sim_network
        .iter()
        .filter_map(|channel| {
            if channel.node_1.pubkey == target_pubkey {
                Some((
                    channel.scid.into(),
                    (channel.node_2.pubkey, channel.node_2.alias.clone()),
                ))
            } else if channel.node_2.pubkey == target_pubkey {
                Some((
                    channel.scid.into(),
                    (channel.node_1.pubkey, channel.node_1.alias.clone()),
                ))
            } else {
                None
            }
        })
        .collect();

    let clock = Arc::new(SimulationClock::new(cli.clock_speedup)?);

    // Use the channel jamming interceptor and latency for simulated payments.
    let latency_interceptor: Arc<dyn Interceptor> =
        Arc::new(LatencyIntercepor::new_poisson(150.0)?);

    let now = InstantClock::now(&*clock);

    // Create a writer to store results for nodes that we care about.
    let results_dir = network_dir.results_dir(Clock::now(&*clock))?;
    let mut monitor_channels: Vec<(PublicKey, String)> =
        target_channels.values().cloned().collect();
    monitor_channels.push((target_pubkey, network_dir.target.0.clone()));
    let results_writer = Arc::new(Mutex::new(BatchForwardWriter::new(
        results_dir.clone(),
        &monitor_channels,
        cli.result_batch_size,
        now,
    )));

    let results_writer_1 = results_writer.clone();
    let results_listener = listener.clone();
    let results_shutdown = shutdown.clone();
    let results_clock = clock.clone();
    tasks.spawn(async move {
        let interval = Duration::from_secs(60);
        loop {
            select! {
                _ = results_listener.clone() => {
                    if let Err(e) = results_writer_1.lock().await.write(true) {
                        log::error!("Error writing results on shutdown: {e}");
                    }
                    return
                },
                _ = results_clock.sleep(interval) => {
                      if let Err(e) = results_writer_1.lock().await.write(false) {
                        log::error!("Error writing results: {e}");
                        results_shutdown.trigger();
                        return
                    }
                }
            }
        }
    });

    let (reputation_state, target_revenue) = network_dir.reputation_summary(cli.attacker_bootstrap);
    let reputation_snapshot = reputation_snapshot_from_file(&reputation_state).map_err(|e| {
        format!(
            "could not find reputation snapshot {:?}, try generating one with reputation-builder: {:?}",
            reputation_state, e
        )
    })?;
    let bootstrap_revenue: u64 = std::fs::read_to_string(target_revenue)?.parse()?;

    let attacker_pubkeys: Vec<PublicKey> = network_dir.attackers.iter().map(|a| a.1).collect();
    let reputation_interceptor = Arc::new(
        ReputationInterceptor::new_from_snapshot(
            forward_params,
            &network_dir.sim_network,
            reputation_snapshot,
            // If bootstrapping the attacker's reputation, we expect them to be in our snapshot
            // of starting reputation values. Otherwise, they can be omitted.
            if cli.attacker_bootstrap.is_some() {
                HashSet::new()
            } else {
                HashSet::from_iter(attacker_pubkeys.clone())
            },
            clock.clone(),
            Some(results_writer),
        )
        .await?,
    );

    // While we run the simulation, replay projected peacetime revenue to serve as a comparison.
    let revenue_interceptor = Arc::new(
        RevenueInterceptor::new_with_bootstrap(
            clock.clone(),
            target_pubkey,
            bootstrap_revenue,
            cli.attacker_bootstrap,
            network_dir.peacetime_traffic(),
            listener.clone(),
        )
        .await?,
    );

    let revenue_interceptor_1 = revenue_interceptor.clone();
    let revenue_shutdown = shutdown.clone();
    tasks.spawn(async move {
        if let Err(e) = revenue_interceptor_1.process_peacetime_fwds().await {
            log::error!("Error processing peacetime forwards: {e}");
            revenue_shutdown.trigger();
        }
    });

    // Reputation is assessed for a channel pair and a specific HTLC that's being proposed. To assess whether pairs
    // have reputation, we'll use LND's default fee policy to get the HTLC risk for our configured htlc size and hold
    // time.
    let risk_margin = forward_params.htlc_opportunity_cost(
        1000 + (0.0001 * cli.reputation_margin_msat as f64) as u64,
        cli.reputation_margin_expiry_blocks,
    );

    // Next, setup the attack interceptor to use our custom attack.
    let attack = setup_attack(
        &cli,
        &network_dir,
        Arc::clone(&clock),
        Arc::clone(&reputation_interceptor),
        Arc::clone(&revenue_interceptor),
        Arc::clone(&reputation_interceptor),
    )?;

    let attack_setup = attack.setup_for_network()?;
    for (channel, pubkey) in attack_setup.general_jammed_nodes.iter() {
        reputation_interceptor
            .jam_general_resources(pubkey, *channel)
            .await?;
    }

    // Do some preliminary checks on our reputation state - there isn't much point in running if we haven't built up
    // some reputation.
    let target_pubkey_map: HashMap<u64, PublicKey> =
        target_channels.iter().map(|(k, v)| (*k, v.0)).collect();

    let start_reputation = get_network_reputation(
        reputation_interceptor.clone(),
        target_pubkey,
        &attacker_pubkeys,
        &target_pubkey_map,
        risk_margin,
        // The reputation_interceptor clock has been set on decaying averages so we use the clock
        // to provide a new instant rather than the previous fixed point.
        InstantClock::now(&*clock),
    )
    .await?;

    check_reputation_status(&cli, &start_reputation)?;

    let attack_interceptor = AttackInterceptor::new(
        attacker_pubkeys.clone(),
        reputation_interceptor.clone(),
        attack.clone(),
    );
    let attack_interceptor = Arc::new(attack_interceptor);

    let interceptors = vec![
        latency_interceptor,
        attack_interceptor.clone(),
        revenue_interceptor.clone(),
    ];

    let custom_records =
        CustomRecords::from([(UPGRADABLE_TYPE, vec![1]), (ACCOUNTABLE_TYPE, vec![0])]);

    let mut exclude = attacker_pubkeys.clone();
    exclude.push(target_pubkey);

    // Setup the simulated network with our fake graph.
    let sim_params = SimParams {
        nodes: vec![],
        sim_network: network_dir.sim_network.clone(),
        activity: vec![],
        exclude,
    };

    let sim_cfg = SimulationCfg::new(None, 3_800_000, 2.0, None, Some(13995354354227336701));
    let (simulation, validated_activities, sim_nodes) = create_simulation_with_network(
        sim_cfg,
        &sim_params,
        clock.clone(),
        tasks.clone(),
        interceptors,
        custom_records,
    )
    .await?;
    let simulation = Arc::new(simulation);

    // Ugly hack specific to SlowJam attack to include this node in the list of nodes passed to run_attack.
    // This node is used as an "honest" node to send a test payment through our target channel to
    // check that it is actually jammed.
    let honest_sender_pubkey = find_pubkey_by_alias("69", &network_dir.sim_network)?;
    let attacker_nodes: HashMap<String, Arc<Mutex<SimNode<SimGraph, SimulationClock>>>> = sim_nodes
        .into_iter()
        .filter_map(|(pk, node)| {
            if cli.attack == AttackType::SlowJam && pk == honest_sender_pubkey {
                Some(("69".to_string(), node))
            } else {
                network_dir
                    .attackers
                    .iter()
                    .find(|attacker| attacker.1 == pk)
                    .map(|a| (a.0.clone(), node))
            }
        })
        .collect();

    let attack_shutdown_listener = listener.clone();
    let attack_shutdown_trigger = shutdown.clone();
    let attack_start_reputation = start_reputation.clone();
    let attack_simulation_shutdown = Arc::clone(&simulation);
    tokio::spawn(async move {
        // run_attack will block until the attack is done so trigger a simulation shutdown after
        // it returns and log any errors.
        if let Err(e) = attack
            .run_attack(
                attack_start_reputation,
                attacker_nodes,
                attack_shutdown_listener,
            )
            .await
        {
            log::error!("Error running custom attacker actions: {e}");
        }
        attack_shutdown_trigger.trigger();
        attack_simulation_shutdown.shutdown();
    });

    let ctrlc_shutdown = shutdown.clone();
    let simulation_shutdown = Arc::clone(&simulation);
    ctrlc::set_handler(move || {
        ctrlc_shutdown.trigger();
        simulation_shutdown.shutdown();
    })?;

    // Run simulation until it shuts down, then wait for the graph to exit.
    simulation.run(&validated_activities).await?;

    // Write start and end state to a summary file.
    let end_reputation = get_network_reputation(
        reputation_interceptor,
        network_dir.target.1,
        &attacker_pubkeys,
        &target_pubkey_map,
        risk_margin,
        InstantClock::now(&*clock),
    )
    .await?;

    let snapshot = revenue_interceptor.get_revenue_difference().await;
    write_simulation_summary(
        &cli,
        results_dir,
        &snapshot,
        &start_reputation,
        &end_reputation,
        attack_setup.general_jammed_nodes.len(),
    )?;

    Ok(())
}

/// Checks whether the attacker and target meet the required portion of high reputation pairs to required.
fn check_reputation_status(cli: &Cli, status: &NetworkReputation) -> Result<(), BoxError> {
    log::info!(
        "Attacker has {} out of {} pairs with reputation",
        status.attacker_reputation,
        status.attacker_pair_count,
    );

    log::info!(
        "Target has {}/{} pairs with reputation with its peers",
        status.target_reputation,
        status.target_pair_count,
    );

    if let Some(attacker_percentage) = cli.attacker_reputation_percent {
        let attacker_threshold = status.attacker_pair_count * attacker_percentage as usize / 100;
        if status.attacker_reputation < attacker_threshold {
            return Err(format!(
                "attacker has {}/{} good reputation pairs which does not meet threshold {}",
                status.attacker_reputation, status.attacker_pair_count, attacker_threshold,
            )
            .into());
        }
    }

    let target_threshold = status.target_pair_count * cli.target_reputation_percent as usize / 100;
    if status.target_reputation < target_threshold {
        return Err(format!(
            "target has {}/{} good reputation pairs which does not meet threshold {}",
            status.target_reputation, status.target_pair_count, target_threshold,
        )
        .into());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_simulation_summary(
    cli: &Cli,
    data_dir: PathBuf,
    revenue: &RevenueSnapshot,
    start_reputation: &NetworkReputation,
    end_reputation: &NetworkReputation,
    general_jammed: usize,
) -> Result<(), BoxError> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
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
    writeln!(
        writer,
        "Attacker bootstrapped reputation for: {} seconds",
        cli.attacker_bootstrap.unwrap_or(Duration::ZERO).as_secs(),
    )?;
    writeln!(
        writer,
        "Attacker start reputation (pairs): {}/{}",
        start_reputation.attacker_reputation, start_reputation.attacker_pair_count,
    )?;
    writeln!(
        writer,
        "Attacker end reputation (pairs): {}/{}",
        end_reputation.attacker_reputation, end_reputation.attacker_pair_count,
    )?;

    writeln!(
        writer,
        "Target start reputation (pairs): {}/{}",
        start_reputation.target_reputation, start_reputation.target_pair_count,
    )?;
    writeln!(
        writer,
        "Target end reputation (pairs): {}/{}",
        end_reputation.target_reputation, end_reputation.target_pair_count,
    )?;
    writeln!(
        writer,
        "Attacker general jammed {general_jammed} edges (directional)",
    )?;
    writer.flush()?;

    Ok(())
}

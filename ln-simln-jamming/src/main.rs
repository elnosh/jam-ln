use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use ln_simln_jamming::parsing::{history_from_file, Cli};
use ln_simln_jamming::reputation_interceptor::ReputationInterceptor;
use ln_simln_jamming::revenue_interceptor::RevenueInterceptor;
use ln_simln_jamming::sink_interceptor::SinkInterceptor;
use ln_simln_jamming::BoxError;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use simln_lib::interceptors::LatencyIntercepor;
use simln_lib::sim_node::{Interceptor, SimulatedChannel};
use simln_lib::{NetworkParser, Simulation, SimulationCfg};
use simple_logger::SimpleLogger;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
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

    let SimNetwork { sim_network } =
        serde_json::from_str(&fs::read_to_string(cli.sim_file.as_path())?)?;

    // Match the target alias using pubkeys provided in sim network file.
    let target_alias = "22".to_string(); // TODO: cli argument
    let target_channel = sim_network
        .iter()
        .find(|hist| hist.node_1.alias == target_alias || hist.node_2.alias == target_alias)
        .ok_or(format!(
            "attacker alias: {target_alias} not found in sim file"
        ))?;

    let target_pubkey = if target_channel.node_1.alias == target_alias {
        target_channel.node_1.pubkey
    } else {
        target_channel.node_2.pubkey
    };

    // Pull history that bootstraps the simulation in a network with the attacker's channels present and calculate
    // revenue for the target node during this bootstrap period.
    let history = history_from_file(&cli.bootstrap_file, Some(cli.bootstrap_duration))?;

    let bootstrap_revenue = history.iter().fold(0, |acc, item| {
        if item.forwarding_node == target_pubkey {
            acc + item.incoming_amt - item.outgoing_amt
        } else {
            acc
        }
    });

    // TODO: args!
    let target_pubkey = find_pubkey_by_alias("22", &sim_network)?;
    let attacker_pubkey = find_pubkey_by_alias("50", &sim_network)?;

    // Use the channel jamming interceptor and latency for simulated payments.
    let latency_interceptor: Arc<dyn Interceptor> =
        Arc::new(LatencyIntercepor::new_poisson(150.0)?);

    // TODO: these should be shared with simln!!
    let (shutdown, listener) = triggered::trigger();
    let attack_interceptor: Arc<dyn Interceptor> = Arc::new(SinkInterceptor::new_for_network(
        attacker_pubkey,
        target_pubkey,
        &sim_network,
        ReputationInterceptor::new_with_bootstrap(&sim_network, &history).await?,
        listener.clone(),
        shutdown.clone(),
    ));

    let revenue_interceptor = Arc::new(RevenueInterceptor::new_with_bootstrap(
        target_pubkey,
        bootstrap_revenue,
        cli.bootstrap_duration,
        cli.peacetime_file,
        listener.clone(),
        shutdown.clone(),
    )?);

    let mut tasks = JoinSet::new();

    let revenue_interceptor_1 = revenue_interceptor.clone();
    tasks.spawn(async move { revenue_interceptor_1.process_peacetime_fwds().await });

    let revenue_interceptor_2 = revenue_interceptor.clone();
    tasks.spawn(async move {
        revenue_interceptor_2
            .poll_revenue_difference(Duration::from_secs(5))
            .await
    });

    let interceptors = vec![latency_interceptor, attack_interceptor, revenue_interceptor];

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
        1,      // No clock speedup, just run with regular timing for now.
        interceptors,
        listener,
        shutdown,
    )
    .await
    .map_err(|e| anyhow::anyhow!(e))?;

    // Run simulation until it shuts down, then wait for the graph to exit.
    simulation.run().await?;
    graph.lock().await.wait_for_shutdown().await;

    Ok(())
}

fn find_pubkey_by_alias(
    alias: &str,
    sim_network: &Vec<NetworkParser>,
) -> Result<PublicKey, BoxError> {
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

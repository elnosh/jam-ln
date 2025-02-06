#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <top_level_directory>"
    exit 1
fi

top_level_dir="$1"

cargo install --path ln-simln-jamming

if [ ! -d "$top_level_dir" ]; then
    echo "Error: $top_level_dir is not a directory"
    exit 1
fi

# Define the different values to iterate over
attacker_bootstrap_values=("30d" "90d" "165d")

# Iterate over each network directory
for network_dir in "$top_level_dir"/*; do
    if [ -d "$network_dir" ]; then
        network_name=$(basename "$network_dir")
        target=$(cat "$network_dir"/target.txt)

        # Loop through each attacker-bootstrap value
        for attacker_bootstrap in "${attacker_bootstrap_values[@]}"; do
            results_dir="results/${network_name}_${attacker_bootstrap}"
            mkdir -p "$results_dir"

            ln-simln-jamming --attacker-bootstrap="$attacker_bootstrap" \
              --sim-file "$network_dir/simln_bootstrap.json" \
              --peacetime-file "$network_dir/peacetime.csv" \
              --bootstrap-file "$network_dir/bootstrap.csv" \
              --target-reputation-percent=10 \
              --attacker-reputation-percent=10 \
              --clock-speedup 100 \
              --target-alias="$target" \
              --attacker-alias=50 \
              --results-dir "$results_dir" \
              --reputation-margin-msat 1000000 \
              >> "$results_dir/logs.txt" 2>&1 &

            echo "Started simulation for attacker-bootstrap=$attacker_bootstrap, network=$network_name. Logs are being written to $results_dir/logs.txt"
        done
    fi

done

# Wait for all background jobs to finish before exiting
wait
echo "All simulations completed."

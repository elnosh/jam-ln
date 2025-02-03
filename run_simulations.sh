#!/bin/bash
if [ $# -eq 0 ] || [ $# -gt 2 ]; then
    echo "Expected network name"
    exit 1
fi

network_name="$1"
target=$(cat data/"$network_name"/target.txt)

# Define the different values to iterate over
attacker_bootstrap_values=("30d" "90d" "165d")

# Loop through each combination of attacker-bootstrap and reputation-margin-msat
for attacker_bootstrap in "${attacker_bootstrap_values[@]}"; do
    results_dir="results/${network_name}_${attacker_bootstrap}"
    mkdir -p "$results_dir"

    # Run the cargo command in the background and redirect its output to logs.txt
    cargo run --package ln-simln-jamming \
      -- --attacker-bootstrap="$attacker_bootstrap" \
      --sim-file data/"$network_name"/simln.json \
      --peacetime-file data/"$network_name"/peacetime.csv \
      --bootstrap-file data/"$network_name"/bootstrap.csv \
      --target-reputation-percent=25 \
      --attacker-reputation-percent=25 \
      --clock-speedup 100 \
      --target-alias="$target" \
      --attacker-alias=50 \
      --results-dir "$results_dir" \
      --reputation-margin-msat 1000000 \
      >> "$results_dir/logs.txt" 2>&1 &

    echo "Started simulation for attacker-bootstrap=$attacker_bootstrap, network=$network_name. Logs are being written to $results_dir/logs.txt"
done

# Wait for all background jobs to finish before exiting
wait
echo "All simulations completed."

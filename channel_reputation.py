import sys
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def main():
    if len(sys.argv) < 3:
        print("Usage: python plot_outgoing.py <csv_file_path> <outgoing_channel_id>")
        sys.exit(1)

    csv_file_path = sys.argv[1]
    outgoing_channel = int(sys.argv[2])

    if not os.path.isfile(csv_file_path):
        print(f"CSV file not found: {csv_file_path}")
        sys.exit(1)

    csv_dir = os.path.dirname(os.path.abspath(csv_file_path))
    df = pd.read_csv(csv_file_path)
    df = df[df["outgoing_channel_id"] == outgoing_channel]

    if df.empty:
        print(f"No data found for outgoing channel {outgoing_channel}")
        return

    df["total_risk"] = df["htlc_risk"] + df["in_flight_risk"]
    df["net_value"] = df["outgoing_reputation"] - df["total_risk"] - df["revenue_threshold"]

    output_dir = os.path.join(csv_dir, f"{outgoing_channel}_reputation")
    os.makedirs(output_dir, exist_ok=True)

    for inc_id, group in df.groupby("incoming_channel_id"):
        plt.figure(figsize=(12, 6))
        plt.plot(group["ts_offset_ns"], group["outgoing_reputation"], label="Outgoing Reputation", alpha=0.7)
        plt.plot(group["ts_offset_ns"], group["total_risk"], label="Total Risk (HTLC + In-Flight)", alpha=0.7)
        plt.plot(group["ts_offset_ns"], group["revenue_threshold"], label="Revenue Threshold", alpha=0.7)
        plt.plot(group["ts_offset_ns"], group["net_value"], label="Reputation Assessment", color="black", linewidth=2)

        ax = plt.gca()
        ax.spines['bottom'].set_position('zero')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.xaxis.set_label_position('bottom')
        ax.xaxis.label.set_horizontalalignment('right')
        ax.xaxis.label.set_verticalalignment('top')
        ax.xaxis.set_label_coords(1.0, -0.05)

        plt.xlabel("ts_offset_ns")
        plt.ylabel("Value (msat)")
        plt.title(f"Outgoing channel {outgoing_channel} - Incoming {inc_id}")
        plt.legend()
        plt.tight_layout()

        plot_path = os.path.join(output_dir, f"incoming_{inc_id}.png")
        plt.savefig(plot_path)
        plt.close()
        print(f"Saved plot for incoming channel {inc_id} -> {plot_path}")

    plt.figure(figsize=(12, 6))
    channels_to_plot = []
    for inc_id, group in df.groupby("incoming_channel_id"):
        if (group["net_value"] > 0).any():
            channels_to_plot.append((inc_id, group))
            plt.plot(group["ts_offset_ns"], group["net_value"], alpha=0.6, label=f"Incoming {inc_id}")

    if channels_to_plot:
        x_min = df["ts_offset_ns"].min()
        x_max = df["ts_offset_ns"].max()
        common_ts = np.linspace(x_min, x_max, 1000)

        interpolated_values = []
        for inc_id, group in channels_to_plot:
            y_interp = np.interp(common_ts, group["ts_offset_ns"], group["net_value"])
            interpolated_values.append(y_interp)

        mean_values = np.mean(interpolated_values, axis=0)
        plt.plot(common_ts, mean_values, color="black", linewidth=2, label="Reputation Assessment")

    ax = plt.gca()
    ax.spines['bottom'].set_position('zero')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.xaxis.set_label_position('bottom')
    ax.xaxis.label.set_horizontalalignment('right')
    ax.xaxis.label.set_verticalalignment('top')
    ax.xaxis.set_label_coords(1.0, -0.05)

    plt.xlabel("ts_offset_ns")
    plt.ylabel("Net Value (msat)")
    plt.title(f"Outgoing channel {outgoing_channel} - Average Reputation Change")
    plt.legend()
    plt.tight_layout()

    avg_plot_path = os.path.join(output_dir, "average.png")
    plt.savefig(avg_plot_path)
    plt.close()
    print(f"Saved average plot -> {avg_plot_path}")

if __name__ == "__main__":
    main()

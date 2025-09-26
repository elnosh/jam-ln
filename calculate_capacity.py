#!/usr/bin/env python3

import json
from collections import defaultdict

def calculate_total_capacity():
    with open('data/100-mainnet/peacetime_network.json', 'r') as f:
        data = json.load(f)

    capacity_by_pubkey = defaultdict(int)

    for channel in data['sim_network']:
        capacity_msat = channel['capacity_msat']
        half_capacity = capacity_msat // 2

        node1_pubkey = channel['node_1']['pubkey']
        node2_pubkey = channel['node_2']['pubkey']

        capacity_by_pubkey[node1_pubkey] += half_capacity
        capacity_by_pubkey[node2_pubkey] += half_capacity

    threshold = 8700000 * 2
    for pubkey, total_capacity in sorted(capacity_by_pubkey.items()):
        if total_capacity < threshold:
            print(f"{pubkey}: {total_capacity} ⚠️  WARNING: Below threshold")

if __name__ == "__main__":
    calculate_total_capacity()
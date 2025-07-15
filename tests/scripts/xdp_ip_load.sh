#!/bin/bash

set -ex           # Print each command and exit on errors
set -u            # Treat unset variables as an error

readonly TMUX=ipv6  # Define tmux session name

# Kill previous tmux session (if any)
tmux kill-session -t "${TMUX}" 2>/dev/null || true

# Delete all existing network namespaces to avoid conflicts
ip -all netns delete

# Create network namespaces: two hosts and one router
ip netns add h0
ip netns add h1
ip netns add r0

# Create veth pairs (virtual Ethernet interfaces)
ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3

# Assign interfaces to namespaces
ip link set veth0 netns h0
ip link set veth1 netns r0
ip link set veth2 netns r0
ip link set veth3 netns h1

###################
#### Node: h0 #####
###################
echo -e "\nNode: h0"

# Enable loopback and veth0, assign IP addresses
ip netns exec h0 ip link set dev lo up
ip netns exec h0 ip link set dev veth0 up
ip netns exec h0 ip addr add 10.0.0.1/24 dev veth0          # IPv4 address
ip netns exec h0 ip addr add cafe::1/64 dev veth0           # IPv6 address

# Set default gateways
ip netns exec h0 ip -6 route add default via cafe::254 dev veth0
ip netns exec h0 ip -4 route add default via 10.0.0.254 dev veth0

###################
#### Node: r0 #####
###################
echo -e "\nNode: r0"

# Enable packet forwarding
ip netns exec r0 sysctl -w net.ipv4.ip_forward=1
ip netns exec r0 sysctl -w net.ipv6.conf.all.forwarding=1

# Disable reverse path filtering (important for routing between interfaces)
ip netns exec r0 sysctl -w net.ipv4.conf.all.rp_filter=0
ip netns exec r0 sysctl -w net.ipv4.conf.veth1.rp_filter=0
ip netns exec r0 sysctl -w net.ipv4.conf.veth2.rp_filter=0

# Bring up interfaces
ip netns exec r0 ip link set dev lo up
ip netns exec r0 ip link set dev veth1 up
ip netns exec r0 ip link set dev veth2 up

# Assign IP addresses to both router interfaces
ip netns exec r0 ip addr add cafe::254/64 dev veth1         # IPv6 side (h0)
ip netns exec r0 ip addr add 10.0.0.254/24 dev veth1        # IPv4 side (h0)

ip netns exec r0 ip addr add beef::254/64 dev veth2         # IPv6 side (h1)
ip netns exec r0 ip addr add 10.0.2.254/24 dev veth2        # IPv4 side (h1)

# Build script to run inside r0 when tmux shell starts
set +e
read -r -d '' r0_env <<-EOFa
set -x
mount -t bpf bpf /sys/fs/bpf/                      # Mount BPF filesystem
mkdir -p /sys/fs/bpf/netprog/{progs,maps}          # Create dirs for pinning
mount -t tracefs nodev /sys/kernel/tracing         # Mount tracefs (for debugging)
ulimit -l unlimited                                 # Allow locked memory (required by eBPF)
bpftool prog loadall xdp_ip_whitelist.bpf.o /sys/fs/bpf/netprog/progs pinmaps /sys/fs/bpf/netprog/maps
bpftool net attach xdp pinned /sys/fs/bpf/netprog/progs/xdp_ip_whitelist dev veth1
/bin/bash                                           # Keep shell open
EOF
set -e

###################
#### Node: h1 #####
###################
echo -e "\nNode: h1"

# Enable loopback and veth3, assign IP addresses
ip netns exec h1 ip link set dev lo up
ip netns exec h1 ip link set dev veth3 up
ip netns exec h1 ip addr add 10.0.2.1/24 dev veth3         # IPv4 address
ip netns exec h1 ip addr add beef::1/64 dev veth3          # IPv6 address

# Set default gateways
ip netns exec h1 ip -4 route add default via 10.0.2.254 dev veth3
ip netns exec h1 ip -6 route add default via beef::254 dev veth3

# Create tmux session and open three terminals (one per node)
tmux new-session -d -s "${TMUX}" -n h0 ip netns exec h0 bash
tmux new-window -t "${TMUX}" -n r0 ip netns exec r0 bash -c "${r0_env}"
tmux new-window -t "${TMUX}" -n h1 ip netns exec h1 bash
tmux select-window -t :0
tmux set-option -g mouse on
tmux attach -t "${TMUX}"

#!/usr/bin/env bash
# SDN Shield - environment setup for Linux Mint 21.3 / Ubuntu 22.04
set -euo pipefail

sudo apt update
sudo apt install -y git python3 python3-pip python3-venv \
    mininet openvswitch-switch \
    hping3 iperf3 tcpdump curl build-essential

sudo systemctl enable --now openvswitch-switch

# Python venv for Ryu baseline + analysis (Ryu needs eventlet 0.30.2 on Python 3.10)
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install "eventlet==0.30.2" ryu scapy psutil numpy pandas scikit-learn matplotlib

# Rust toolchain (skip if already installed)
if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

# Record pinned versions
mkdir -p env
{
  echo "date: $(date -Is)"
  uname -a
  echo "mininet: $(mn --version 2>&1)"
  ovs-vsctl --version | head -1
  hping3 --version 2>&1 | head -1
  iperf3 --version | head -1
  python3 --version
  pip freeze | grep -Ei 'ryu|eventlet|scapy|scikit|numpy|pandas|psutil'
  (rustc --version && cargo --version) 2>&1 || true
} | tee env/versions.txt

echo
echo "Done. Next: sudo mn --test pingall"

#!/usr/bin/env python3
"""SDN Shield - Mininet topology (single OVS switch, remote controller).

h1..h4 attackers, h5..h7 legitimate clients, h8 victim server (10.0.0.x).
Usage:
  sudo python3 topology.py --test          # pingall then exit
  sudo python3 topology.py --cli
"""
import argparse

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

N_ATTACKERS = 4
N_CLIENTS = 3


def build(controller_ip, controller_port, bw_mbps):
    net = Mininet(controller=None, switch=OVSKernelSwitch, link=TCLink,
                  autoSetMacs=True, build=False)
    net.addController("c0", controller=RemoteController,
                      ip=controller_ip, port=controller_port)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    total = N_ATTACKERS + N_CLIENTS + 1
    for i in range(1, total + 1):
        h = net.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
        net.addLink(h, s1, bw=bw_mbps)
    net.build()
    net.start()
    return net


def roles(net):
    attackers = [net.get(f"h{i}") for i in range(1, N_ATTACKERS + 1)]
    clients = [net.get(f"h{i}") for i in range(N_ATTACKERS + 1,
                                               N_ATTACKERS + N_CLIENTS + 1)]
    victim = net.get(f"h{N_ATTACKERS + N_CLIENTS + 1}")
    return attackers, clients, victim


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--controller", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=6653)
    ap.add_argument("--bw", type=float, default=10, help="link bw in Mbit/s")
    ap.add_argument("--cli", action="store_true")
    ap.add_argument("--test", action="store_true")
    args = ap.parse_args()

    setLogLevel("info")
    net = build(args.controller, args.port, args.bw)
    try:
        if args.test:
            loss = net.pingAll()
            info(f"*** pingAll packet loss: {loss}%\n")
        if args.cli or not args.test:
            CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()

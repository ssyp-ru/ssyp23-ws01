#!/bin/bash
set -e

cargo b
sudo setcap CAP_NET_ADMIN=eip ./target/debug/team_a
./target/debug/team_a &
pid=$!

#sudo ip a add 192.168.0.127/24 dev mytun
sudo ip a add 10.0.1.5/24 dev tun1
sudo ip link set up dev tun1

trap "kill $pid" INT TERM
wait $pid

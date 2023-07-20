#!/bin/bash

cargo build
sudo setcap cap_net_admin=eip target/debug/tcp
target/debug/tcp &
pid=$!
sudo ip addr add 10.0.0.2/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid
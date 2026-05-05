#!/bin/sh
tc qdisc del dev eth0 root
tc qdisc add dev eth0 root handle 1:0 htb default 10
tc class add dev eth0 parent 1:0 classid 1:10 htb rate 100Mbit
tc qdisc add dev eth0 parent 1:10 handle 10:0 netem delay 50ms 3ms 25% distribution normal

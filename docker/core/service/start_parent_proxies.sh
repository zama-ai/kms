#!/bin/bash

# This script will start proxies that permit the enclave to access external
# services, like AWS API. It's mostly meant for running the enclave on a
# standalone EC2 instance. There might be better ways to start proxies in larger
# production environments, like K8S.

RESOLVCONF_PORT=4200
KMS_SERVER_TUN_IF=vsocktun

if [ "$#" -ne 9 ]; then
    echo "usage: start_parent_proxies.sh ENCLAVE_CID ENCLAVE_NET_PORT ENCLAVE_TUN_ADDR KMS_SERVER_TUN_ADDR ENCLAVE_LOG_PORT ENCLAVE_CONFIG_PORT ENCLAVE_TOKEN_PORT KMS_SERVER_CONFIG_FILE WEB_IDENTITY_TOKEN_FILE"
    exit 1
fi

ENCLAVE_CID="$1"
ENCLAVE_NET_PORT="$2"
ENCLAVE_TUN_ADDR="$3"
KMS_SERVER_TUN_ADDR="$4"
ENCLAVE_LOG_PORT="$5"
ENCLAVE_CONFIG_PORT="$6"
ENCLAVE_TOKEN_PORT="$7"
KMS_SERVER_CONFIG_FILE="$8"
WEB_IDENTITY_TOKEN_FILE="$9"
KMS_SERVER_TUN_IP="${KMS_SERVER_TUN_ADDR%/*}"
UPSTREAM_DNS=""

while read -r key value _; do
    if [ "$key" = "nameserver" ]; then
        UPSTREAM_DNS="$value"
        break
    fi
done < /etc/resolv.conf

get_configured_port() {
    local SERVICE_NAME="$1"
    get_value "$SERVICE_NAME" | cut -d ":" -f 3
}

get_value() {
    local KEY="$1"
    yq -e -p toml -oy ".$KEY" "$KMS_SERVER_CONFIG_FILE"
}

is_threshold() {
    yq -e -p toml -oy '.threshold' "$KMS_SERVER_CONFIG_FILE" &>/dev/null
}

start_tcp_proxy_in() {
    local NAME="$1"
    local PORT="$2"
    echo "start_proxies: starting parent-side $NAME proxy"
    socat -T180 TCP-LISTEN:"$PORT",fork,nodelay,reuseaddr VSOCK-CONNECT:"$ENCLAVE_CID":"$PORT"
}

# start the log stream for the enclave
echo "start_proxies: starting enclave log stream"
socat -T180 -u VSOCK-LISTEN:"$ENCLAVE_LOG_PORT",fork STDOUT &

# start the config stream for the enclave
echo "start_proxies: starting enclave config stream"
socat -T180 VSOCK-LISTEN:"$ENCLAVE_CONFIG_PORT",fork,reuseaddr OPEN:"$KMS_SERVER_CONFIG_FILE",rdonly &

# start the web identity token stream for the enclave
echo "start_proxies: starting web identity token stream"
socat VSOCK-LISTEN:"$ENCLAVE_TOKEN_PORT",fork,reuseaddr OPEN:"$WEB_IDENTITY_TOKEN_FILE",rdonly &

# start the resolv.conf stream for the enclave
echo "start_proxies: starting /etc/resolv.conf stream"
socat -T180 VSOCK-LISTEN:"$RESOLVCONF_PORT",fork,reuseaddr OPEN:/etc/resolv.conf,rdonly &

# enable NAT for enclave outgoing connections
echo "start_proxies: starting enclave network tunnel interface"
sudo socat VSOCK-LISTEN:"$ENCLAVE_NET_PORT",fork,reuseaddr TUN:"$KMS_SERVER_TUN_ADDR",tun-name=$KMS_SERVER_TUN_IF,iff-up &
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s "$ENCLAVE_TUN_ADDR" -j MASQUERADE

for _ in $(seq 1 30);
do
    if ifconfig "$KMS_SERVER_TUN_IF" &>/dev/null; then
        break
    fi
    sleep 1
done
if ! ifconfig "$KMS_SERVER_TUN_IF" &>/dev/null; then
    echo "start_proxies: tunnel interface $KMS_SERVER_TUN_IF did not come up"
    exit 1
fi

if [ -z "$UPSTREAM_DNS" ]; then
    echo "start_proxies: cannot determine upstream nameserver from /etc/resolv.conf"
    exit 1
fi

echo "start_proxies: starting dnsproxy on $KMS_SERVER_TUN_IP via $UPSTREAM_DNS"
sudo dnsproxy -v -l "$KMS_SERVER_TUN_IP" -u "$UPSTREAM_DNS" &

# if needed, start a TCP proxy for incoming threshold peer-to-peer connections
if is_threshold; then
    start_tcp_proxy_in "gRPC peer" "$(get_configured_port "threshold.listen_port")" &
fi

# start a TCP proxy to let the world access the gRPC API in the enclave
start_tcp_proxy_in "gRPC client" "$(get_configured_port "service.listen_port")" &

wait

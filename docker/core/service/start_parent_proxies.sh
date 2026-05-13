#!/bin/bash

# This script will start proxies that permit the enclave to access external
# services, like AWS API. It's mostly meant for running the enclave on a
# standalone EC2 instance. There might be better ways to start proxies in larger
# production environments, like K8S.

KMS_SERVER_TUN_IF=vsocktun

if [ "$#" -ne 4 ]; then
    echo "usage: start_parent_proxies.sh ENCLAVE_LOG_PORT ENCLAVE_CONFIG_PORT KMS_SERVER_CONFIG_FILE WEB_IDENTITY_TOKEN_FILE"
    exit 1
fi

ENCLAVE_LOG_PORT="$1"
ENCLAVE_CONFIG_PORT="$2"
KMS_SERVER_CONFIG_FILE="$3"
WEB_IDENTITY_TOKEN_FILE="$4"
UPSTREAM_DNS=""
PARENT_IF=""
PARENT_IP=""
VSOCKTUN_BIN="$(command -v vsocktun)"

if [ -z "$VSOCKTUN_BIN" ]; then
    echo "start_proxies: could not resolve vsocktun in PATH"
    exit 1
fi

while read -r key value _; do
    if [ "$key" = "nameserver" ]; then
        UPSTREAM_DNS="$value"
        break
    fi
done < /etc/resolv.conf

get_configured_port() {
    local SERVICE_NAME="$1"
    local SERVICE_URL
    SERVICE_URL=$(get_value "$SERVICE_NAME" | tr -d '"')
    echo "${SERVICE_URL##*:}"
}

get_value() {
    local KEY="$1"
    yq -e -p toml -oy ".$KEY" "$KMS_SERVER_CONFIG_FILE"
}

is_threshold() {
    yq -e -p toml -oy '.threshold' "$KMS_SERVER_CONFIG_FILE" &>/dev/null
}

ENCLAVE_TOKEN_PORT="$(get_value "enclave_bootstrap.web_identity_token_port")"
RESOLVCONF_PORT="$(get_value "enclave_bootstrap.resolv_conf_port")"
ENCLAVE_NET_PORT="$(get_value "enclave_bootstrap.network_tunnel.vsock_port")"
KMS_SERVER_TUN_ADDR="$(get_value "enclave_bootstrap.network_tunnel.parent_address" | tr -d '"')"
ENCLAVE_TUN_IP="$(get_value "enclave_bootstrap.network_tunnel.enclave_address" | tr -d '"')"
if yq -e -p toml -oy '.enclave_bootstrap.network_tunnel.queue_count' "$KMS_SERVER_CONFIG_FILE" &>/dev/null; then
    TUN_QUEUE_COUNT="$(get_value "enclave_bootstrap.network_tunnel.queue_count")"
else
    TUN_QUEUE_COUNT="8"
fi
if yq -e -p toml -oy '.enclave_bootstrap.network_tunnel.tokio_worker_threads' "$KMS_SERVER_CONFIG_FILE" &>/dev/null; then
    TUN_TOKIO_WORKER_THREADS="$(get_value "enclave_bootstrap.network_tunnel.tokio_worker_threads")"
else
    TUN_TOKIO_WORKER_THREADS="$(default_tun_tokio_worker_threads "$TUN_QUEUE_COUNT")"
fi

if [ "${KMS_SERVER_TUN_ADDR%/*}" = "$KMS_SERVER_TUN_ADDR" ]; then
    echo "start_proxies: parent tunnel address missing CIDR prefix: $KMS_SERVER_TUN_ADDR"
    exit 1
fi

case "$ENCLAVE_TUN_IP" in
    */*)
        echo "start_proxies: enclave tunnel address must not contain CIDR prefix: $ENCLAVE_TUN_IP"
        exit 1
        ;;
esac

ENCLAVE_TUN_ADDR="${ENCLAVE_TUN_IP}/${KMS_SERVER_TUN_ADDR#*/}"
KMS_SERVER_TUN_IP="${KMS_SERVER_TUN_ADDR%/*}"

add_ingress_dnat() {
    local PORT="$1"
    sudo iptables -t nat -C PREROUTING -i "$PARENT_IF" -d "$PARENT_IP" -p tcp --dport "$PORT" -j DNAT --to-destination "$ENCLAVE_TUN_IP:$PORT" 2>/dev/null || \
        sudo iptables -t nat -A PREROUTING -i "$PARENT_IF" -d "$PARENT_IP" -p tcp --dport "$PORT" -j DNAT --to-destination "$ENCLAVE_TUN_IP:$PORT"
    sudo iptables -C FORWARD -i "$PARENT_IF" -o "$KMS_SERVER_TUN_IF" -p tcp -d "$ENCLAVE_TUN_IP" --dport "$PORT" -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        sudo iptables -A FORWARD -i "$PARENT_IF" -o "$KMS_SERVER_TUN_IF" -p tcp -d "$ENCLAVE_TUN_IP" --dport "$PORT" -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
}

delete_ingress_dnat() {
    local PORT="$1"
    if [ -n "$PARENT_IF" ] && [ -n "$PARENT_IP" ]; then
        sudo iptables -t nat -D PREROUTING -i "$PARENT_IF" -d "$PARENT_IP" -p tcp --dport "$PORT" -j DNAT --to-destination "$ENCLAVE_TUN_IP:$PORT" 2>/dev/null || true
        sudo iptables -D FORWARD -i "$PARENT_IF" -o "$KMS_SERVER_TUN_IF" -p tcp -d "$ENCLAVE_TUN_IP" --dport "$PORT" -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    fi
}

cleanup() {
    if [ -f "$KMS_SERVER_CONFIG_FILE" ]; then
        delete_ingress_dnat "$(get_configured_port "telemetry.metrics_bind_address")"
        delete_ingress_dnat "$(get_configured_port "service.listen_port")"
        if is_threshold; then
            delete_ingress_dnat "$(get_configured_port "threshold.listen_port")"
        fi
    fi
    if [ -n "$PARENT_IF" ]; then
        sudo iptables -t nat -D POSTROUTING -s "$ENCLAVE_TUN_ADDR" -o "$PARENT_IF" -j MASQUERADE 2>/dev/null || true
    fi
    sudo iptables -D FORWARD -i "$KMS_SERVER_TUN_IF" -j ACCEPT 2>/dev/null || true
    sudo iptables -D FORWARD -o "$KMS_SERVER_TUN_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    kill $(jobs -p) 2>/dev/null || true
}

trap cleanup EXIT INT TERM

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
sudo "$VSOCKTUN_BIN" parent \
    --tun-name "$KMS_SERVER_TUN_IF" \
    --tun-address "$KMS_SERVER_TUN_ADDR" \
    --vsock-port "$ENCLAVE_NET_PORT" \
    --queues "$TUN_QUEUE_COUNT" \
    --tokio-worker-threads "$TUN_TOKIO_WORKER_THREADS" &
sudo sysctl -w net.ipv4.ip_forward=1

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

set -- $(ip route get 1.1.1.1)
while [ "$#" -gt 0 ]; do
    case "$1" in
        dev)
            PARENT_IF="$2"
            shift 2
            ;;
        src)
            PARENT_IP="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [ -z "$PARENT_IF" ] || [ -z "$PARENT_IP" ]; then
    echo "start_proxies: cannot determine parent interface or IP"
    exit 1
fi

sudo iptables -t nat -C POSTROUTING -s "$ENCLAVE_TUN_ADDR" -o "$PARENT_IF" -j MASQUERADE 2>/dev/null || \
    sudo iptables -t nat -A POSTROUTING -s "$ENCLAVE_TUN_ADDR" -o "$PARENT_IF" -j MASQUERADE
sudo iptables -C FORWARD -i "$KMS_SERVER_TUN_IF" -j ACCEPT 2>/dev/null || \
    sudo iptables -A FORWARD -i "$KMS_SERVER_TUN_IF" -j ACCEPT
sudo iptables -C FORWARD -o "$KMS_SERVER_TUN_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    sudo iptables -A FORWARD -o "$KMS_SERVER_TUN_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

echo "start_proxies: DNATing metrics, client, and peer ingress to $ENCLAVE_TUN_IP over $KMS_SERVER_TUN_IF"
add_ingress_dnat "$(get_configured_port "telemetry.metrics_bind_address")"
add_ingress_dnat "$(get_configured_port "service.listen_port")"
if is_threshold; then
    add_ingress_dnat "$(get_configured_port "threshold.listen_port")"
fi

echo "start_proxies: starting dnsproxy on $KMS_SERVER_TUN_IP via $UPSTREAM_DNS"
sudo dnsproxy -v -l "$KMS_SERVER_TUN_IP" -u "$UPSTREAM_DNS" &

wait

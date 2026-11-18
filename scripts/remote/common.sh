#!/usr/bin/env bash

find_experiment_interface() {
    local address=$1
    local iface

    iface=$(
        ip -o -4 addr show |
            awk -v ip="$address" '{
                split($4, candidate, "/")
                if (candidate[1] == ip) {print $2; exit}
            }'
    )
    iface=${iface%%@*}
    test -n "$iface"
    printf '%s\n' "$iface"
}

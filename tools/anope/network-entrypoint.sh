#!/bin/sh
# Puts the link password and JSON-RPC token from the environment into Anope's
# configuration, then starts Anope. Used by the docker/ network.
set -eu
for secret in "${SERVICES_SECRET:-}" "${RPC_TOKEN:-}"; do
    # Restricted so a value can't break the sed below or Anope's quoted strings.
    case "$secret" in
        "" | *[!A-Za-z0-9._-]*)
            echo "SERVICES_SECRET and RPC_TOKEN must be set, using only A-Z a-z 0-9 . _ -" >&2
            exit 1 ;;
    esac
done
sed -i "s/@SERVICES_SECRET@/$SERVICES_SECRET/" /anope/conf/services.conf
sed -i "s/@RPC_TOKEN@/$RPC_TOKEN/" /anope/conf/modules.example.conf
exec /anope/bin/anope --nofork --nopid --config=services.conf "$@"

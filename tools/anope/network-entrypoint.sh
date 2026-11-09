#!/bin/sh
# Puts the link password, JSON-RPC token and optional services root from the
# environment into Anope's configuration, then starts Anope. Used by docker/.
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

root="${SERVICES_ROOT:-}"
case "$root" in
    "") ;;
    *[!A-Za-z0-9_-]*)
        echo "SERVICES_ROOT must be a nickname using only A-Z a-z 0-9 _ -" >&2
        exit 1 ;;
    *)
        # Appended once per container; a changed .env recreates the container.
        if ! grep -q "# SERVICES_ROOT" /anope/conf/services.conf; then
            # require_oper: the nick must also be an IRC operator (/OPER), so
            # registering the nick alone does not give services root.
            printf '\n# SERVICES_ROOT\noper\n{\n\tname = "%s"\n\ttype = "Services Root"\n\trequire_oper = yes\n}\n' \
                "$root" >> /anope/conf/services.conf
        fi ;;
esac
exec /anope/bin/anope --nofork --nopid --config=services.conf "$@"

# SOURCED, not executed. Runs on the VM HOST.
#
# The four lab upstreams and the one function that registers and signs
# them. It lives in its own file because two callers need it --
# gateway-serve-provision.sh on a first install, and
# gateway-serve-verify.sh, which rebuilds the database on every run so the
# Tool Quarantine before/after is a real observation rather than a
# leftover.
#
# Two copies of this loop would drift, and the drift would be silent in the
# worst way this project keeps rediscovering: an upstream registered with a
# different -env list still registers, still signs, still starts, and
# simply hands its backend nothing.
#
# The caller must already define: j(), ju(), GW, CONFIG, LIBEXEC, SVC_USER
# and DBDIR. The last two became required on 16 Sep 2026, when signing moved
# to root and the database directory has to be handed back afterwards --
# both callers (gateway-serve-provision.sh, vm/gateway-serve-verify.sh)
# already defined them.

# An upstream's registered name is what namespaces its tools
# (casemgmt.list_cases), so these strings are load-bearing: they must match the
# `<upstream>.` prefix every role in the configuration grants.
MOCKS="casemgmt logsearch docsearch threatintel"

# env_flags_for prints the -env flags for one upstream.
#
# -env takes variable NAMES only. The console rejects NAME=value outright
# and elides the value when it does; the registry has no field able to hold
# a secret, which is why this function can be read in a diff at all.
env_flags_for() {
	# Every mock reads the same two names (lab/mockutil/credcheck.go), so
	# the four upstreams necessarily share one MOCK_SECRET value: the vault
	# namespace is flat and keyed by variable name. See
	# deploy/gateway-serve.md, "One vault, one namespace".
	printf '%s' "-env MOCK_SECRET -env MOCK_EXPECT"
	# ...plus one distinct fake credential per backend, named the way that
	# backend's real counterpart would name it. The mocks ignore these; they
	# are here so the per-upstream resolution path is genuinely exercised
	# and so the leak grep has a per-backend value to hunt for.
	case "$1" in
		casemgmt)       printf '%s' " -env CASEMGMT_API_TOKEN" ;;
		logsearch)    printf '%s' " -env LOGSEARCH_API_TOKEN" ;;
		docsearch) printf '%s' " -env DOCSEARCH_PASSWORD" ;;
		threatintel)      printf '%s' " -env THREATINTEL_VT_KEY" ;;
	esac
}

# --print-env-names prints every variable name the upstreams below will be
# registered with, one per line, and exits.
#
# It exists so the provisioner can check the vault covers them BEFORE
# registering anything, without keeping a second copy of the list. A second
# copy is how the lists drift apart, and drifting apart is what produced
# four "vault: secret not found" failures on 12 Sep 2026 after the backends
# were renamed -- from a script that exited 0 saying "provisioned".
if [ "${1:-}" = "--print-env-names" ]; then
	for m in $MOCKS; do
		env_flags_for "$m" | tr " " "\n" | grep -v "^-env$" | grep -v "^$"
	done | sort -u
	exit 0
fi

# register_and_sign_upstreams registers any missing upstream and re-signs
# every one of them.
#
# Register is skipped when the name already exists (the console refuses a
# duplicate on purpose); sign is always re-run, because a signature covers
# the command, args and env var NAMES, so a re-provision that changed any
# of them must re-sign or the gateway will refuse the entry at its next
# start.
register_and_sign_upstreams() {
	for m in $MOCKS; do
		if ju "$GW upstream list -config $CONFIG -json 2>/dev/null | jq -e --arg n $m '.[]|select(.name==\$n)' >/dev/null"; then
			echo "    $m: already registered"
		else
			ju "$GW upstream register -config $CONFIG -name $m -transport stdio \
				-command $LIBEXEC/lab-$m $(env_flags_for "$m")" | sed 's/^/    /'
		fi
		# Signing runs as ROOT, not as the service account, and that is the
		# point rather than an accident.
		#
		# ADR-0010 puts the trust anchor (the public keys) in the config
		# file precisely so that whoever can write the SQLite database
		# cannot also mint signatures for it. Handing the PRIVATE key to
		# the account that runs `serve` -- the account that writes that
		# database -- gives that step back: an attacker with code execution
		# as the service user could sign whatever registry entry they
		# wanted. Root holds the key; the service account never reads it.
		#
		# The cost is the chown below. `sign` opens the database, and
		# SQLite in WAL mode creates -wal and -shm files owned by whoever
		# opened it, so running as root leaves those two owned by root in a
		# directory the service account must write. That is why this
		# function ends by giving the directory back -- and why a
		# provisioning run that dies between the two leaves a gateway that
		# cannot start, loudly, rather than one that starts and cannot
		# audit.
		j "$GW sign -config $CONFIG $m" | sed 's/^/    /'
	done
	j "chown -R $SVC_USER:$SVC_USER $DBDIR"
}

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
# The caller must already define: j(), ju(), GW, CONFIG, LIBEXEC.

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
		ju "$GW sign -config $CONFIG $m" | sed 's/^/    /'
	done
}

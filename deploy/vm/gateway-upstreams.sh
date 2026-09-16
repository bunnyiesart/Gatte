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
#
# # THE NAMES IN THIS REPOSITORY ARE SANITISED, AND THE DEPLOYMENT'S ARE NOT
#
# This repository is public. The four backends it names -- casemgmt,
# logsearch, docsearch, threatintel -- are generic stand-ins; the jail this
# was written for runs four upstreams under the SOC's real service names,
# with real credential variables to match.
#
# So running this script unchanged against that deployment does not work,
# and it must not: it would register four MORE upstreams under the
# sanitised names, needing four vault entries nobody seeded, on top of the
# four that already serve. That is not drift to be fixed by renaming
# something -- it is the cost of publishing the deployment recipe for a
# system whose backend names are not public, and the only honest handling
# is to make the names an input with the sanitised set as the default.
#
# Measured, because it happened: a provisioning run on 16 Sep 2026 against
# the real jail stopped at the vault check with
#
#   !! the vault does not hold: CASEMGMT_API_TOKEN DOCSEARCH_PASSWORD ...
#
# which is the check working. The binaries had already been installed by
# then -- that part is idempotent and harmless -- and the registry was left
# untouched, which is what the check exists to guarantee.
#
# To provision a deployment whose upstreams are named differently, pass
# both variables; neither is in a tracked file:
#
#   UPSTREAM_NAMES="graylog iris opensearch swiss" #   UPSTREAM_CREDS="graylog:GRAYLOG_API_TOKEN iris:IRIS_API_TOKEN #                   opensearch:OPENSEARCH_PASSWORD swiss:SWISS_VT_KEY" #     ./deploy/gateway-serve.sh
#
# The pairs are separate from the names because the credential variable a
# backend reads is the backend's own convention -- API_TOKEN, PASSWORD and
# VT_KEY all appear in one real fleet -- and deriving it from the name
# would be inventing a rule that no vendor follows.
#
# WHAT THE OVERRIDE DOES NOT COVER, measured on 16 Sep 2026 by running it:
# the binary install step stages `mock-<name>` built from `lab/servers/<name>`,
# and those packages exist only under the sanitised names. With
# UPSTREAM_NAMES set to a deployment's real names the run gets as far as
#
#   install: /tmp/mcp-gateway-deploy/mock-graylog: No such file or directory
#
# and stops -- before touching the registry, which is the behaviour to want.
# So these variables make the REGISTRATION and the VAULT CHECK correct for a
# renamed deployment; they do not make this repository able to build that
# deployment's backends, and it should not: past the lab, an upstream points
# at a real MCP server, not at a mock this repository ships.
MOCKS="${UPSTREAM_NAMES:-casemgmt logsearch docsearch threatintel}"

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
	#
	# UPSTREAM_CREDS overrides the pairs for a deployment whose names are
	# not the sanitised ones (see MOCKS above). Format: `name:VAR name:VAR`.
	# An upstream with no pair gets only the two shared names, which is a
	# legitimate shape and not an error -- it just does not exercise the
	# per-upstream resolution path.
	for pair in ${UPSTREAM_CREDS:-}; do
		case "$pair" in
			"$1":*) printf '%s' " -env ${pair#*:}"; return ;;
		esac
	done
	if [ -n "${UPSTREAM_CREDS:-}" ]; then
		return
	fi
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

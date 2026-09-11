# shellcheck shell=sh
# Transport for "run this on the FreeBSD jail host".
#
# Sourced, not executed. Every deploy script that used to say `jm ssh --`
# now says `remote_sh`, and every one that used to open-code `scp -P 2222
# ... root@127.0.0.1:` now says `remote_cp`. Two transports:
#
#   JAILHOST_TRANSPORT=jailmachine   (default) the local jailmachine VM,
#                                    via `jm ssh --` and the jm SSH key.
#                                    Byte-for-byte what the scripts did
#                                    before this file existed.
#   JAILHOST_TRANSPORT=ssh           any host you can ssh to: the Proxmox
#                                    FreeBSD guest, a bare-metal box, or --
#                                    useful for testing -- the jailmachine
#                                    VM again on 127.0.0.1:2222.
#
# See deploy/README.md for the variables and a worked example.
#
# ---------------------------------------------------------------------------
# QUOTING -- read this before adding a call site.
#
# `jm ssh -- a b c` and `ssh host a b c` are NOT two ways of running argv
# on the far side. Both join their arguments with a single space into one
# string and hand that string to a shell on the remote host. Verified
# against this lab's VM, both transports, and they agree exactly:
#
#   remote_sh printf '%s|' 'a b' c   -> the remote shell sees
#                                       `printf %s| a b c`, i.e. a pipeline
#   remote_sh printf '%s' '$HOME'    -> $HOME expands REMOTELY
#   remote_sh printf '%s' '/etc/rc.*'-> the glob expands REMOTELY
#   remote_sh printf '[%s]' '' x     -> the empty argument disappears
#   remote_sh 'exit 7'               -> exit status 7 comes back
#   echo hi | remote_sh cat          -> stdin is passed through
#
# That the two transports flatten identically is the whole reason this
# refactor is safe: `remote_sh` forwards "$@" verbatim to whichever one is
# selected and adds no quoting of its own, so no call site changes meaning.
#
# The rule for call sites, unchanged from what `jm ssh --` already required:
#
#   SAFE    remote_sh mkdir -p "$STAGE"
#           -- plain words. Fine as long as the expansions contain no
#              spaces, quotes, globs or $ -- which is true of every path
#              in this repo.
#   SAFE    remote_sh bastille cmd "$JAIL" env "K=$V" /root/x.sh
#           -- same thing; bastille/jexec are just more words in the
#              string the remote shell parses.
#   SAFE    remote_sh "GW_JAIL=$GW_JAIL STAGE=$STAGE sh $STAGE/run.sh"
#           -- one pre-quoted argument. This is the shape to prefer when
#              the command needs shell syntax; you are writing the remote
#              shell's input directly and you can see exactly what it gets.
#   UNSAFE  remote_sh sh -c "cmd1; cmd2"
#           -- the flattening drops the quotes around the -c argument, so
#              the remote `sh -c` gets only `cmd1` and the rest runs as
#              separate words. This was already broken before the refactor;
#              deploy/openvpn-teardown.sh still contains one such call and
#              is flagged in place. Write it as the single-argument form
#              above instead.
#
# If you need an argument to arrive with its spaces and metacharacters
# intact, quote it into the string yourself -- the transport will not do it
# for you, and deliberately does not, because doing so would change the
# meaning of every call site that exists today.
# ---------------------------------------------------------------------------

JAILHOST_TRANSPORT="${JAILHOST_TRANSPORT:-jailmachine}"

# --- ssh transport -------------------------------------------------------
JAILHOST_HOST="${JAILHOST_HOST:-}"
JAILHOST_USER="${JAILHOST_USER:-root}"
JAILHOST_PORT="${JAILHOST_PORT:-22}"
JAILHOST_KEY="${JAILHOST_KEY:-}"
# Extra ssh/scp options, deliberately word-split (so you can pass more than
# one). Empty by default: the ssh transport uses your normal known_hosts and
# will refuse or prompt on an unknown host key. That is the right default for
# a box on a real network -- opt out explicitly if you mean to:
#   JAILHOST_SSH_OPTS='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
JAILHOST_SSH_OPTS="${JAILHOST_SSH_OPTS:-}"

# --- jailmachine transport -----------------------------------------------
# Unchanged from what each script defined for itself before.
JM_STATE_ROOT="${JM_STATE_ROOT:-$HOME/.jailmachine}"
JM_SSH_KEY="${JM_SSH_KEY:-$JM_STATE_ROOT/machines/jailmachine/ssh/id_ed25519}"
JM_SSH_PORT="${JM_SSH_PORT:-2222}"

case "$JAILHOST_TRANSPORT" in
jailmachine) ;;
ssh)
	if [ -z "$JAILHOST_HOST" ]; then
		echo "JAILHOST_TRANSPORT=ssh needs JAILHOST_HOST set (see deploy/README.md)" >&2
		exit 2
	fi
	;;
*)
	echo "unknown JAILHOST_TRANSPORT '$JAILHOST_TRANSPORT' (want: jailmachine, ssh)" >&2
	exit 2
	;;
esac

# remote_sh <command...>
#
# Run a command on the jail host. Arguments are joined with spaces and
# interpreted by a shell there -- see the QUOTING block above. stdin, stdout,
# stderr and the exit status all pass through.
remote_sh() {
	case "$JAILHOST_TRANSPORT" in
	jailmachine)
		jm ssh -- "$@"
		;;
	ssh)
		# Prepend the connection flags without an array (POSIX sh has none):
		# build the list back-to-front with `set --`.
		set -- "$JAILHOST_USER@$JAILHOST_HOST" "$@"
		set -- -p "$JAILHOST_PORT" "$@"
		if [ -n "$JAILHOST_KEY" ]; then
			set -- -i "$JAILHOST_KEY" "$@"
		fi
		# SC2086: JAILHOST_SSH_OPTS is split on purpose.
		# SC2029: yes, the command expands on the client and is re-parsed by
		# a shell on the server. That is exactly what `jm ssh --` does too,
		# and matching it is the point -- see the QUOTING block above.
		# shellcheck disable=SC2086,SC2029
		ssh $JAILHOST_SSH_OPTS "$@"
		;;
	esac
}

# remote_cp <local>... <remote-path>
#
# Copy one or more local files to the jail host. The last argument is the
# destination, exactly as scp takes it: with more than one source it must be
# a directory (and, as with scp, ending it in "/" is the honest way to say
# so). No recursion -- nothing in this repo stages a directory.
remote_cp() {
	if [ "$#" -lt 2 ]; then
		echo "remote_cp: usage: remote_cp <local>... <remote-path>" >&2
		return 2
	fi

	# Split off the last argument as the destination. `for x in "$@"` expands
	# the list once up front, so rotating through it with `set --` is safe.
	_rcp_n=$#
	_rcp_i=0
	_rcp_dest=
	for _rcp_a in "$@"; do
		_rcp_i=$((_rcp_i + 1))
		if [ "$_rcp_i" -eq "$_rcp_n" ]; then
			_rcp_dest=$_rcp_a
		else
			set -- "$@" "$_rcp_a"
		fi
	done
	shift "$_rcp_n"

	case "$JAILHOST_TRANSPORT" in
	jailmachine)
		# The literal incantation the scripts each carried a copy of. The
		# host is hardcoded because gvproxy always publishes the VM on the
		# Mac's loopback; the port and key are the jm state-root ones.
		set -- "$@" "root@127.0.0.1:$_rcp_dest"
		set -- -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
			-i "$JM_SSH_KEY" -P "$JM_SSH_PORT" "$@"
		scp "$@"
		;;
	ssh)
		set -- "$@" "$JAILHOST_USER@$JAILHOST_HOST:$_rcp_dest"
		set -- -P "$JAILHOST_PORT" "$@"
		if [ -n "$JAILHOST_KEY" ]; then
			set -- -i "$JAILHOST_KEY" "$@"
		fi
		set -- -q "$@"
		# shellcheck disable=SC2086  # JAILHOST_SSH_OPTS is split on purpose
		scp $JAILHOST_SSH_OPTS "$@"
		;;
	esac
}

# remote_target -- a short human label for the jail host, for log lines.
remote_target() {
	case "$JAILHOST_TRANSPORT" in
	jailmachine) echo "the jailmachine VM" ;;
	ssh)         echo "$JAILHOST_USER@$JAILHOST_HOST:$JAILHOST_PORT" ;;
	esac
}

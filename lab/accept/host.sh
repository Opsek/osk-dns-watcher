#!/bin/sh
# Checks of the DNS lab that only the Docker host can make:  lab/accept/host.sh
# It starts two labs of its own, numbers HOST_LAB_A and HOST_LAB_B (default 8 and 9), and stops
# them at the end, also after a failure. It refuses numbers that are in use, so it never stops a
# lab that it did not start. Each check prints "ok <name>" or "FAIL <name>: <what was wanted,
# what came back>"; the exit status is 0 only if every check passed.
# DOCKER may hold options, so it is split into words on purpose.
# shellcheck disable=SC2086

DOCKER=${DOCKER:-docker}
A=${HOST_LAB_A:-8}
B=${HOST_LAB_B:-9}
FAILS=0
cd "$(dirname "$0")/../.." || exit 2

same() { [ "$2" = "$3" ] || echo "$1: want $2, got ${3:-nothing}"; }

# lab <n> <command...>: lab/bin/lab for lab n; its output goes to $LOG, so only check lines
# reach the standard output
lab() { lb_n=$1; shift; LAB_ID=$lb_n lab/bin/lab "$@" >"$LOG" 2>&1; }
last() { tail -n 3 "$LOG" | tr '\n' ' '; }
run() { rn_n=$1; shift; LAB_ID=$rn_n lab/bin/lab run "$@" 2>&1; }
# date counts whole seconds, so "below n" holds for sure only when the count is below n
seconds() { echo $(($(date +%s) - $1)); }

# listing <kind>: "<name> <labels>" for every object of this kind on the machine; the labels are
# separated by commas
listing() {
	case $1 in
	container) $DOCKER ps -a --no-trunc --format '{{.Names}} {{.Labels}}' ;;
	network) $DOCKER network ls --format '{{.Name}} {{.Labels}}' ;;
	volume) $DOCKER volume ls --format '{{.Name}} {{.Labels}}' ;;
	esac
}
labels() { listing "$1" | awk -v n="$2" '$1 == n { print substr($0, length(n) + 2) }' | tr ',' '\n'; }
exists() { listing "$1" | cut -d' ' -f1 | grep -qxF "$2"; }
# objects <n>: "<kind> <name>" for every container, network and volume of lab n. They are found by
# the lab label, by the project name and through the containers, so an object without the label
# still shows.
objects() {
	for ob_f in "label=osk.lab=$1" "label=com.docker.compose.project=osklab$1"; do
		$DOCKER ps -a --no-trunc --filter "$ob_f" --format 'container {{.Names}}
network {{.Networks}}
volume {{.Mounts}}'
		$DOCKER network ls --filter "$ob_f" --format 'network {{.Name}}'
		$DOCKER volume ls --filter "$ob_f" --format 'volume {{.Name}}'
	done | awk '{ k = $1; n = split(substr($0, length(k) + 2), v, ",")
		for (i = 1; i <= n; i++) if (v[i] != "" && v[i] != "none" && v[i] !~ /^\//) print k, v[i] }' | sort -u
}
stop() {
	sp_id=$($DOCKER ps -q --filter "label=com.docker.compose.project=osklab$1" \
		--filter "label=com.docker.compose.service=$2")
	[ -n "$sp_id" ] && $DOCKER stop -t 1 $sp_id >/dev/null 2>&1
}

c_numbers_free() {
	for nf_n in "$A" "$B"; do
		case $nf_n in [0-9]) ;; *) echo "HOST_LAB_A and HOST_LAB_B: want 0 to 9, got $nf_n"; return 0 ;; esac
		nf_objects=$(objects "$nf_n")
		[ -z "$nf_objects" ] || echo "lab $nf_n: want it unused, got $(printf '%s\n' "$nf_objects" | tr '\n' ' ')"
	done
	[ "$A" != "$B" ] || echo "HOST_LAB_A and HOST_LAB_B: want two numbers, got $A twice"
}
c_up() { lab "$1" up || echo "lab up of lab $1: failed: $(last)"; }
c_up_time() { # the first lab built the image, so it is on the machine now
	ut_start=$(date +%s)
	c_up "$1"
	ut_took=$(seconds "$ut_start")
	[ "$ut_took" -lt 30 ] || echo "lab up of lab $1: want below 30 s, took $ut_took s"
}
c_two_labs() { # both labs answer at once, each on its own subnet
	for tl_n in "$A" "$B"; do
		lab "$tl_n" status || echo "lab status of lab $tl_n: want exit 0, got: $(last)"
		same "www.corp.test. A from ns1 of lab $tl_n" "10.53.$tl_n.81" \
			"$(run "$tl_n" dig +short +norec +time=2 +tries=1 @"10.53.$tl_n.11" www.corp.test. A)"
	done
}
c_isolated() { # the runner of each lab reaches its own ns1 but not the ns1 of the other lab
	for li_pair in "$A $B" "$B $A"; do
		li_from=${li_pair% *} li_to=${li_pair#* }
		for li_t in +notcp +tcp; do
			li_dig="dig +norec +time=1 +tries=1 $li_t"
			case $(run "$li_from" $li_dig @"10.53.$li_from.11" corp.test. SOA) in
			*"status: NOERROR"*) ;;
			*) echo "lab $li_from to its own ns1 ($li_t): want an answer, got none" ;;
			esac
			case $(run "$li_from" $li_dig @"10.53.$li_to.11" corp.test. SOA) in
			*"status: "*) echo "lab $li_from to ns1 of lab $li_to ($li_t): want no answer, got one" ;;
			esac
		done
	done
}
c_reset_time() { # reset after a change, so that it has work to do
	run "$A" labctl set both www.corp.test. 300 A "10.53.$A.66" >/dev/null || echo "labctl set in lab $A: failed"
	rt_start=$(date +%s)
	lab "$A" reset || echo "lab reset of lab $A: failed: $(last)"
	rt_took=$(seconds "$rt_start")
	[ "$rt_took" -lt 5 ] || echo "lab reset of lab $A: want below 5 s, took $rt_took s"
	same "serial of corp.test. on ns1 of lab $A after lab reset" 1 "$(run "$A" labctl serial ns1 corp.test.)"
}
c_labels() { # c_labels <n> <objects>
	for lb_need in container network; do
		printf '%s\n' "$2" | grep -q "^$lb_need " || echo "lab $1: want a $lb_need, got none"
	done
	printf '%s\n' "$2" | while read -r lb_kind lb_name; do
		[ -n "$lb_name" ] || continue
		same "labels osk.* of $lb_kind $lb_name" "osk.lab=$1" "$(labels "$lb_kind" "$lb_name" | grep '^osk\.' | sort | tr '\n' ' ' | sed 's/ $//')"
	done
}
c_unpublished() { # c_unpublished <n>: no port on the host, and no container in the host network
	for up_f in "label=osk.lab=$1" "label=com.docker.compose.project=osklab$1"; do
		$DOCKER ps -a --no-trunc --filter "$up_f" --format '{{.Names}}|{{.Ports}}|,{{.Networks}},'
	done | sort -u | while IFS='|' read -r up_name up_ports up_nets; do
		case $up_ports in *'->'*) echo "container $up_name: want no published port, got $up_ports" ;; esac
		case $up_nets in *,host,*) echo "container $up_name: want no host network, got it" ;; esac
	done
}
c_status_stopped() { # the last check before lab down, so nothing has to start again
	for ss_pair in "$A ns2" "$B receiver"; do
		ss_lab=${ss_pair% *} ss_service=${ss_pair#* }
		stop "$ss_lab" "$ss_service" || echo "lab $ss_lab: could not stop $ss_service"
		lab "$ss_lab" status
		same "exit status of lab status of lab $ss_lab with $ss_service stopped" 1 "$?"
	done
}
c_down() { # c_down <objects seen while the labs ran>
	for dn_n in "$A" "$B"; do
		lab "$dn_n" down || echo "lab down of lab $dn_n: failed: $(last)"
	done
	{ printf '%s\n' "$1"; objects "$A"; objects "$B"; } | sort -u | while read -r dn_kind dn_name; do
		[ -n "$dn_name" ] && exists "$dn_kind" "$dn_name" && echo "$dn_kind $dn_name: want it gone, got it still there"
	done
}

check() {
	ck_name=$1
	shift
	ck_out=$("$@" 2>&1)
	if [ -z "$ck_out" ]; then
		echo "ok $ck_name"
	else
		echo "FAIL $ck_name: $(printf '%s\n' "$ck_out" | awk 'NR > 1 { printf "; " } { printf "%s", $0 } END { print "" }')"
		FAILS=$((FAILS + 1))
	fi
}

main() {
	check lab-numbers-free c_numbers_free
	[ "$FAILS" -eq 0 ] || exit 1
	LOG=$(mktemp "${TMPDIR:-/tmp}/labhost.XXXXXX") || exit 1
	trap 'for n in "$A" "$B"; do LAB_ID=$n lab/bin/lab down >/dev/null 2>&1; done; rm -f "$LOG"' EXIT
	trap 'exit 1' INT TERM

	# The first lab may have to build the image, so its start is not timed.
	check lab-up c_up "$A"
	[ "$FAILS" -eq 0 ] || exit 1
	check lab-up-time c_up_time "$B"
	check two-labs-at-once c_two_labs
	check labs-isolated c_isolated
	check lab-reset-time c_reset_time
	OBJECTS_A=$(objects "$A") OBJECTS_B=$(objects "$B")
	check labels-lab-a c_labels "$A" "$OBJECTS_A"
	check labels-lab-b c_labels "$B" "$OBJECTS_B"
	check nothing-published-lab-a c_unpublished "$A"
	check nothing-published-lab-b c_unpublished "$B"
	check lab-status-server-stopped c_status_stopped
	check lab-down-leaves-nothing c_down "$(printf '%s\n%s\n' "$OBJECTS_A" "$OBJECTS_B")"

	[ "$FAILS" -eq 0 ] && exit 0
	exit 1
}

main

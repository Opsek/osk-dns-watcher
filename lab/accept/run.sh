#!/bin/sh
# Acceptance checks of the DNS lab, run in the runner of a started lab:
#   lab/bin/lab run /src/lab/accept/run.sh
# Each check prints "ok <name>" or "FAIL <name>: <what was wanted, what came back>"; the exit
# status is 0 only if every check passed. The run starts from the base state and leaves it: each
# check undoes its changes. No check waits after labctl, because labctl returns only when the
# change is served.

DIG="dig +time=2 +tries=1 +nosplit"
XFR_KEY_FILE=/lab/xfr.key
WRONG_SECRET=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU=
DS1="11111 13 2 1111111111111111111111111111111111111111111111111111111111111111"
DS2="22222 13 2 2222222222222222222222222222222222222222222222222222222222222222"
FAILS=0

# ---- reading dig output (stdin) ----

status() { sed -n 's/^;; ->>HEADER<<-.* status: \([A-Z]*\),.*/\1/p'; }
flags() { sed -n 's/^;; flags:\([^;]*\);.*/\1/p'; }
section() { awk -v h=";; $1 SECTION:" '$0 == h { on = 1; next } on && $0 == "" { exit } on'; }
# records: each record as "name ttl type rdata", single spaces, no class
records() { grep -v -e '^;' -e '^$' | tr '\t' ' ' | tr -s ' ' | cut -d' ' -f1,2,4-; }
pick() { awk -v n="$1" -v t="$2" '$1 == n && $3 == t'; }
rdata() { cut -d' ' -f4-; }
# sigs <type>: the RRSIG records that cover this type, with the signature in one piece
sigs() {
	awk -v t="$1" '$3 == "RRSIG" && $4 == t {
		s = $1 " " $2 " RRSIG"; for (i = 4; i <= 11; i++) s = s " " $i
		s = s " "; for (i = 12; i <= NF; i++) s = s $i; print s }'
}
# set_of: the lines as one sorted set "{a, b}"
set_of() { sort | awk 'BEGIN { printf "{" } NR > 1 { printf ", " } { printf "%s", $0 } END { print "}" }'; }
list() { printf '%s\n' "$@" | set_of; }

# ---- queries; the dig output goes to R ----

aq() { aq_ip=$1 aq_name=$2 aq_type=$3; shift 3; R=$($DIG +norec "$@" @"$aq_ip" "$aq_name" "$aq_type" 2>&1); }
rq() { rq_ip=$1 rq_name=$2 rq_type=$3; shift 3; R=$($DIG "$@" @"$rq_ip" "$rq_name" "$rq_type" 2>&1); }
out() { printf '%s\n' "$R"; }
# rr <section> <name> <type>: the records of this name and type in a section of R
rr() { out | section "$1" | records | pick "$2" "$3"; }
has_flag() { case " $(out | flags) " in *" $1 "*) return 0 ;; esac; return 1; }
got() { # a short account of R
	if [ -z "$(out | status)" ]; then echo "no answer ($(out | grep '^;;' | head -n 1))"
	else echo "$(out | status), flags:$(out | flags)"; fi
}

# ---- expectations; each prints one line for each problem ----

same() { [ "$2" = "$3" ] || echo "$1: want $2, got ${3:-nothing}"; }
auth() { # auth <where>: R is an authoritative answer without error
	[ "$(out | status)" = NOERROR ] && has_flag aa && return 0
	echo "$1: want NOERROR with AA, got $(got)"; return 1
}
referral() { # referral <where>: R is a referral (no error, no AA, empty answer)
	[ "$(out | status)" = NOERROR ] && ! has_flag aa && [ -z "$(out | section ANSWER)" ] && return 0
	echo "$1: want a referral (NOERROR, no AA, no answer), got $(got)"; return 1
}
# want_rr <ip> <name> <type> <rdata>...: an authoritative answer with exactly these records
# (no rdata: an empty answer)
want_rr() {
	wr_ip=$1 wr_name=$2 wr_type=$3; shift 3
	aq "$wr_ip" "$wr_name" "$wr_type"
	auth "$wr_name $wr_type @$wr_ip" || return 0
	same "$wr_name $wr_type @$wr_ip" "$(list "$@")" "$(rr ANSWER "$wr_name" "$wr_type" | rdata | set_of)"
}
want_nx() { # want_nx <ip> <name> <type>: an authoritative "no such name"
	aq "$1" "$2" "$3"
	[ "$(out | status)" = NXDOMAIN ] && has_flag aa && return 0
	echo "$2 $3 @$1: want NXDOMAIN with AA, got $(got)"
}
want_ref() { # want_ref <ip> <zone> <ns>...: a referral to exactly these nameservers
	wf_ip=$1 wf_zone=$2; shift 2
	aq "$wf_ip" "$wf_zone" NS
	referral "$wf_zone NS @$wf_ip" || return 0
	same "$wf_zone NS @$wf_ip" "$(list "$@")" "$(rr AUTHORITY "$wf_zone" NS | rdata | set_of)"
}
# want_glue <ip> <zone> <ns-name> <address>...: the referral for the zone carries exactly these
# addresses for the nameserver name (no address: no glue)
want_glue() {
	wg_ip=$1 wg_zone=$2 wg_ns=$3; shift 3
	aq "$wg_ip" "$wg_zone" NS
	referral "$wg_zone NS @$wg_ip" || return 0
	same "glue of $wg_ns in $wg_zone NS @$wg_ip" "$(list "$@")" "$(rr ADDITIONAL "$wg_ns" A | rdata | set_of)"
}
want_rec() { # want_rec <ip> <name> <type> <rdata>...: the resolver answers exactly these records
	wc_ip=$1 wc_name=$2 wc_type=$3; shift 3
	rq "$wc_ip" "$wc_name" "$wc_type"
	if [ "$(out | status)" != NOERROR ]; then echo "$wc_name $wc_type @$wc_ip: want NOERROR, got $(got)"; return 0; fi
	same "$wc_name $wc_type @$wc_ip" "$(list "$@")" "$(rr ANSWER "$wc_name" "$wc_type" | rdata | set_of)"
}
not_served() { # not_served <ip> <zone>: no authoritative answer for the zone
	aq "$1" "$2" SOA
	if has_flag aa; then echo "$2 SOA @$1: want no authoritative answer, got $(got)"; fi
}
want_refused() { # want_refused <ip> <zone>: the server answers REFUSED for the zone
	aq "$1" "$2" SOA
	[ "$(out | status)" = REFUSED ] || echo "$2 SOA @$1: want REFUSED, got $(got)"
}
both() { b_fn=$1; shift; "$b_fn" "$NS1" "$@"; "$b_fn" "$NS2" "$@"; }
# seconds_in <what> <from> <below> <seconds>: from <= seconds < below
seconds_in() {
	awk -v t="$4" -v lo="$2" -v hi="$3" 'BEGIN { exit !(t != "" && t + 0 >= lo && t + 0 < hi) }' ||
		echo "$1: want $2 s to $3 s, got ${4:-nothing} s"
}

# ---- serials and labctl ----

addr() { case $1 in ns1) echo "$NS1" ;; ns2) echo "$NS2" ;; esac; }
serial_of() { aq "$1" "$2" SOA; rr ANSWER "$2" SOA | cut -d' ' -f6; }
plus() { case $1 in '' | *[!0-9]*) echo "?" ;; *) echo $(($1 + $2)) ;; esac; }
want_serial() { # want_serial <server> <zone> <n>: the SOA answer and labctl serial show n
	same "serial of $2 @$1" "$3" "$(serial_of "$(addr "$1")" "$2")"
	same "labctl serial $1 $2" "$3" "$(labctl serial "$1" "$2" 2>&1)"
}
lc() {
	lc_out=$(labctl "$@" 2>&1) && return 0
	lc_rc=$?
	echo "labctl $*: exit $lc_rc: $(printf '%s\n' "$lc_out" | head -n 1)"
}
code() { labctl "$@" >/dev/null 2>&1; echo $?; }

# ---- base state ----

# base_records <zone>: the records of a base child zone, as "name ttl type rdata". The TTL is "-"
# where the base state leaves it open. Only corp.test. fixes the fields of its SOA; want_zone
# checks the serial of every zone.
base_records() {
	case $1 in
	corp.test.) cat <<EOF
corp.test. 300 SOA ns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300
corp.test. 300 NS ns1.corp.test.
corp.test. 300 NS ns2.corp.test.
ns1.corp.test. 300 A $NET.11
ns2.corp.test. 300 A $NET.12
corp.test. 300 A $NET.80
corp.test. 300 AAAA $V6
corp.test. 300 MX 10 mail.corp.test.
corp.test. 300 TXT "v=spf1 mx -all"
corp.test. 300 CAA 0 issue "ca.test"
www.corp.test. 300 A $NET.81
mail.corp.test. 300 A $NET.82
cdn.corp.test. 300 CNAME edge.dnshost.test.
_dmarc.corp.test. 300 TXT "v=DMARC1; p=reject"
EOF
		;;
	dnshost.test.) cat <<EOF
dnshost.test. - NS ns1.dnshost.test.
dnshost.test. - NS ns2.dnshost.test.
ns1.dnshost.test. - A $NET.11
ns2.dnshost.test. - A $NET.12
edge.dnshost.test. - A $NET.83
EOF
		;;
	shop.test.) cat <<EOF
shop.test. - NS ns1.dnshost.test.
shop.test. - NS ns2.dnshost.test.
shop.test. - A $NET.84
EOF
		;;
	esac
}

want_zone() { # want_zone <server> <zone>: every listed record set exactly, and serial 1
	wz_ip=$(addr "$1")
	base_records "$2" >"$TMP/want"
	cut -d' ' -f1,3 "$TMP/want" | sort -u >"$TMP/sets"
	while read -r wz_name wz_type; do
		wz_lines=$(pick "$wz_name" "$wz_type" <"$TMP/want")
		wz_cut=2,4- # TTL and data
		case $wz_lines in *" - $wz_type "*) wz_cut=4- ;; esac # TTL left open: data only
		aq "$wz_ip" "$wz_name" "$wz_type"
		auth "$wz_name $wz_type @$1" || continue
		same "$wz_name $wz_type @$1" "$(printf '%s\n' "$wz_lines" | cut -d' ' -f"$wz_cut" | set_of)" \
			"$(rr ANSWER "$wz_name" "$wz_type" | cut -d' ' -f"$wz_cut" | set_of)"
	done <"$TMP/sets"
	same "serial of $2 @$1" 1 "$(serial_of "$wz_ip" "$2")"
}
# only_listed <server> <zone>: a transfer of the zone holds no record beyond the listed ones. The
# SOA is left out, since only corp.test. fixes its fields.
only_listed() {
	ol_ip=$(addr "$1")
	R=$($DIG +time=5 -k "$XFR_KEY_FILE" @"$ol_ip" "$2" AXFR 2>&1)
	if [ "$(out | records | pick "$2" SOA | wc -l | tr -d ' ')" -lt 2 ]; then
		echo "AXFR $2 @$1: want the zone, got $(out | grep '^;' | tail -n 1)"
		return 0
	fi
	base_records "$2" | awk '$3 != "SOA"' | cut -d' ' -f1,3- >"$TMP/listed"
	ol_extra=$(out | records | awk '$3 != "SOA" && $3 != "TSIG"' | cut -d' ' -f1,3- | grep -vxF -f "$TMP/listed")
	[ -z "$ol_extra" ] || echo "AXFR $2 @$1: want only the listed records, got also $(printf '%s\n' "$ol_extra" | set_of)"
}
c_only_listed() {
	for co_s in ns1 ns2; do
		for co_z in corp.test. dnshost.test. shop.test.; do only_listed "$co_s" "$co_z"; done
	done
}
redelegate_corp() {
	lc delegate corp.test. ns1.corp.test. ns2.corp.test.
	lc glue ns1.corp.test. "$NET.11"
	lc glue ns2.corp.test. "$NET.12"
}
corp_at_parent() { # the base delegation of corp.test.
	want_ref "$TLD" corp.test. ns1.corp.test. ns2.corp.test.
	want_glue "$TLD" corp.test. ns1.corp.test. "$NET.11"
	want_glue "$TLD" corp.test. ns2.corp.test. "$NET.12"
}
# sign <zone> <file> [dnssec-signzone options]: sign the file (in the current directory) into
# <file>.signed, with a KSK and a ZSK of the zone made on first use; also writes dsset-<zone>
sign() {
	sg_zone=$1 sg_file=$2
	shift 2
	if ! ls K"$sg_zone"+* >/dev/null 2>&1; then
		dnssec-keygen -q -a ECDSAP256SHA256 -f KSK "$sg_zone" &&
			dnssec-keygen -q -a ECDSAP256SHA256 "$sg_zone" || return 1
	fi
	dnssec-signzone -q -S -O full "$@" -o "$sg_zone" -f "$sg_file.signed" "$sg_file"
}

# ---- hosts ----

c_runner_address() {
	case ${LAB_ID:-} in
	[0-9]) ;;
	*) echo "LAB_ID: want 0 to 9 in the environment, got ${LAB_ID:-nothing}"; return 0 ;;
	esac
	cat /proc/net/fib_trie /etc/hosts 2>/dev/null | tr -c '0-9.\n' '\n' | grep -qxF "$NET.100" ||
		echo "want the address $NET.100 on the runner, got none"
}
c_runner_tools() {
	for t in dig delv nsupdate dnssec-keygen dnssec-signzone curl labctl; do
		command -v "$t" >/dev/null 2>&1 || echo "$t: want it on the PATH, got nothing"
	done
	[ -r /lab/ca.pem ] || echo "/lab/ca.pem: want a readable file, got nothing"
}
c_src_read_only() { # a test must not be able to change the tree that it tests
	if (: >"/src/.write-check.$$") 2>/dev/null; then
		rm -f "/src/.write-check.$$"
		echo "/src: want a read-only mount, got a writable one"
	fi
}
# c_host <ip> <name> <type> <flag>: the host answers over UDP and over TCP, with EDNS and with
# the flag (aa: authoritative, ra: recursive)
c_host() {
	for ch_t in udp tcp; do
		ch_opt=+notcp
		[ "$ch_t" = tcp ] && ch_opt=+tcp
		if [ "$4" = aa ]; then aq "$1" "$2" "$3" $ch_opt; else rq "$1" "$2" "$3" $ch_opt; fi
		ch_where="$2 $3 @$1 over $ch_t"
		if [ "$(out | status)" != NOERROR ] || ! has_flag "$4"; then
			echo "$ch_where: want NOERROR with flag $4, got $(got)"
			continue
		fi
		[ -n "$(rr ANSWER "$2" "$3")" ] || echo "$ch_where: want a $3 record, got none"
		out | grep -q '^; EDNS: version: 0' || echo "$ch_where: want EDNS version 0 in the answer, got none"
	done
}
c_silent() {
	for cs_opt in +notcp +tcp; do
		aq "$NET.99" corp.test. SOA +time=1 $cs_opt
		[ -z "$(out | status)" ] || echo "$NET.99 $cs_opt: want no answer, got $(got)"
	done
}
c_resolver() { # c_resolver <ip>: the resolver uses the lab root and resolves base names
	want_rec "$1" . NS root-ns.
	want_rec "$1" www.corp.test. A "$NET.81"
	want_rec "$1" corp.test. MX "10 mail.corp.test."
	want_rec "$1" shop.test. A "$NET.84"
	rq "$1" cdn.corp.test. A
	same "cdn.corp.test. A @$1 (alias)" "{edge.dnshost.test.}" "$(rr ANSWER cdn.corp.test. CNAME | rdata | set_of)"
	same "cdn.corp.test. A @$1 (target)" "{$NET.83}" "$(rr ANSWER edge.dnshost.test. A | rdata | set_of)"
}
# xfr <ip> <type> [dig options]: a transfer of corp.test.; the dig output goes to R
xfr() { xf_ip=$1 xf_type=$2; shift 2; R=$($DIG +time=5 "$@" @"$xf_ip" corp.test. "$xf_type" 2>&1); }
soas() { out | records | pick corp.test. SOA | wc -l | tr -d ' '; }
# refused <where>: the server answered and refused the transfer (not: no server reached)
refused() {
	[ "$(soas)" = 0 ] && out | grep -q '^; Transfer failed' && return 0
	echo "$1: want a refused transfer, got $(soas) SOA records ($(out | grep '^;' | tail -n 1))"
}
c_xfr_key() {
	if [ ! -r "$XFR_KEY_FILE" ]; then
		echo "xfr-key: want a key file at $XFR_KEY_FILE, got none"
		return 0
	fi
	for cx_ip in "$NS1" "$NS2"; do
		xfr "$cx_ip" AXFR -k "$XFR_KEY_FILE"
		same "AXFR corp.test. @$cx_ip with xfr-key (SOA records)" 2 "$(soas)"
		xfr "$cx_ip" IXFR=0 -k "$XFR_KEY_FILE"
		[ "$(soas)" -ge 1 ] || echo "IXFR corp.test. @$cx_ip with xfr-key: want the zone, got no SOA record"
	done
}
c_xfr_nokey() {
	for cn_ip in "$NS1" "$NS2"; do
		for cn_t in AXFR IXFR=0; do
			xfr "$cn_ip" "$cn_t"
			refused "$cn_t corp.test. @$cn_ip without a key"
		done
	done
}
c_xfr_wrongkey() {
	for cw_ip in "$NS1" "$NS2"; do
		xfr "$cw_ip" AXFR -y "hmac-sha256:xfr-key:$WRONG_SECRET"
		refused "AXFR corp.test. @$cw_ip with a wrong secret for xfr-key"
	done
}
# any_one <ip> <name>: an ANY query gets exactly one record set of the name, and for a base child
# zone it is one of the listed sets. Large providers trim ANY answers over UDP only, so the query
# goes over UDP and nothing is asked over TCP.
any_one() {
	aq "$1" "$2" ANY +notcp
	auth "$2 ANY @$1" || return 0
	ao_types=$(out | section ANSWER | records | awk -v n="$2" '$1 == n && $3 != "RRSIG" { print $3 }' | sort -u)
	if [ "$(printf '%s\n' "$ao_types" | grep -c .)" != 1 ]; then
		echo "$2 ANY @$1: want one record set, got the types $(printf '%s\n' "$ao_types" | set_of)"
		return 0
	fi
	[ -n "$(base_records "$2")" ] || return 0
	same "$2 ANY @$1 ($ao_types records)" "$(base_records "$2" | pick "$2" "$ao_types" | rdata | set_of)" \
		"$(rr ANSWER "$2" "$ao_types" | rdata | set_of)"
}
c_any_minimal() {
	any_one "$ROOT" .
	any_one "$TLD" test.
	both any_one corp.test.
}

# ---- base state ----

c_base_root() {
	aq "$ROOT" . SOA
	auth ". SOA @$ROOT" && same ". SOA @$ROOT (records)" 1 "$(rr ANSWER . SOA | wc -l | tr -d ' ')"
	want_rr "$ROOT" . NS root-ns.
	want_rr "$ROOT" root-ns. A "$NET.2"
	want_ref "$ROOT" test. ns.test.
	want_glue "$ROOT" test. ns.test. "$NET.3"
}
c_base_parent() {
	corp_at_parent
	want_ref "$TLD" dnshost.test. ns1.dnshost.test. ns2.dnshost.test.
	want_glue "$TLD" dnshost.test. ns1.dnshost.test. "$NET.11"
	want_glue "$TLD" dnshost.test. ns2.dnshost.test. "$NET.12"
	# A referral for shop.test. may carry the addresses of ns1/ns2.dnshost.test. (the glue of
	# dnshost.test.), so its additional section is not checked.
	want_ref "$TLD" shop.test. ns1.dnshost.test. ns2.dnshost.test.
}
c_base_no_ds() {
	want_rr "$ROOT" test. DS
	want_rr "$TLD" corp.test. DS
	want_rr "$TLD" dnshost.test. DS
	want_rr "$TLD" shop.test. DS
}
# c_base_services: the resolvers give the true and current answers, the receiver holds no request
# and has no pending reply, and no zone that a check adds is left
c_base_services() {
	want_rec "$RESOLVER" www.corp.test. A "$NET.81"
	want_rec "$LIAR" www.corp.test. A "$NET.81"
	want_rec "$LIAR" corp.test. MX "10 mail.corp.test."
	bs_hooks=$(labctl hooks list 2>&1)
	[ -z "$bs_hooks" ] || echo "labctl hooks list: want no output, got $bs_hooks"
	bs_post=$(hit "/accept/base-$TOKEN" '%{http_code}|%header{retry-after}|%{time_total}')
	same "POST (status|Retry-After)" "200|" "${bs_post%|*}"
	seconds_in "time of POST" 0 1 "${bs_post##*|}"
	lc hooks clear
	for bs_z in accept fixed drop sec extra; do both want_refused "$bs_z.test."; done
}
base_checks() { # base_checks <prefix of the check names>
	check "${1}base-root" c_base_root
	check "${1}base-parent" c_base_parent
	check "${1}base-no-ds" c_base_no_ds
	for bc_z in corp dnshost shop; do
		check "${1}base-$bc_z-ns1" want_zone ns1 "$bc_z.test."
		check "${1}base-$bc_z-ns2" want_zone ns2 "$bc_z.test."
	done
	check "${1}base-zones-only-listed" c_only_listed
	check "${1}base-services" c_base_services
}

# ---- receiver ----

# post <path> [curl options]: POST to the receiver (the options come last, so -X PUT wins);
# prints the HTTP status and the answering address
post() {
	po_path=$1
	shift
	curl -sS -o /dev/null -w '%{http_code} %{remote_ip}' --max-time 5 -X POST \
		-H "X-Accept-Check: hdr-$TOKEN" -H 'Content-Type: text/plain' --data "body-$TOKEN" \
		"$@" "https://hooks.lab.test$po_path" 2>&1
}
# hit <path> <format>: POST to the receiver, print what the curl --write-out format names, and
# leave the response body in $TMP/body. curl does not follow redirects here.
hit() {
	rm -f "$TMP/body"
	curl -sS -o "$TMP/body" -w "$2" --max-time 10 -X POST --data "body-$TOKEN" \
		"https://hooks.lab.test$1" 2>&1
}
body() { cat "$TMP/body" 2>/dev/null; }
stored() { labctl hooks list 2>&1 | grep "/accept/$1"; }
has_status() { printf '%s\n' "$1" | grep -Eq "\"status\" *: *\"?$2"; }
c_receiver() {
	same "POST https://hooks.lab.test/ (runner trust store)" "200 $RECEIVER" "$(post "/accept/trust-$TOKEN")"
	same "POST https://hooks.lab.test/ (--cacert /lab/ca.pem)" "200 $RECEIVER" \
		"$(post "/accept/cafile-$TOKEN" --cacert /lab/ca.pem)"
	lc hooks clear
}

# ---- labctl ----

c_serial() {
	for cs_s in ns1 ns2; do
		for cs_z in corp.test. dnshost.test. shop.test.; do
			same "labctl serial $cs_s $cs_z" "$(serial_of "$(addr "$cs_s")" "$cs_z")" "$(labctl serial "$cs_s" "$cs_z" 2>&1)"
		done
	done
}
c_set_one() {
	so_serial1=$(serial_of "$NS1" corp.test.) so_serial2=$(serial_of "$NS2" corp.test.)
	lc set ns1 www.corp.test. 300 A "$NET.66"
	want_rr "$NS1" www.corp.test. A "$NET.66"
	want_rr "$NS2" www.corp.test. A "$NET.81"
	want_serial ns1 corp.test. "$(plus "$so_serial1" 1)"
	want_serial ns2 corp.test. "$so_serial2"
	lc set ns1 www.corp.test. 300 A "$NET.81"
	want_rr "$NS1" www.corp.test. A "$NET.81"
}
c_set_both() {
	sb_serial1=$(serial_of "$NS1" corp.test.) sb_serial2=$(serial_of "$NS2" corp.test.)
	lc set both www.corp.test. 120 A "$NET.66"
	both want_rr www.corp.test. A "$NET.66"
	same "TTL of www.corp.test. A @$NS2" "{120}" "$(rr ANSWER www.corp.test. A | cut -d' ' -f2 | set_of)"
	want_serial ns1 corp.test. "$(plus "$sb_serial1" 1)"
	want_serial ns2 corp.test. "$(plus "$sb_serial2" 1)"
	lc set both www.corp.test. 300 A "$NET.81"
	both want_rr www.corp.test. A "$NET.81"
}
c_set_unchanged() { # set with the data that is already there still adds exactly 1
	su_serial1=$(serial_of "$NS1" corp.test.) su_serial2=$(serial_of "$NS2" corp.test.)
	lc set both www.corp.test. 300 A "$NET.81"
	both want_rr www.corp.test. A "$NET.81"
	want_serial ns1 corp.test. "$(plus "$su_serial1" 1)"
	want_serial ns2 corp.test. "$(plus "$su_serial2" 1)"
}
c_set_replace() {
	lc set both corp.test. 300 A "$NET.66" "$NET.67"
	lc set both corp.test. 300 MX "10 mail.corp.test." "20 www.corp.test."
	both want_rr corp.test. A "$NET.66" "$NET.67"
	both want_rr corp.test. MX "10 mail.corp.test." "20 www.corp.test."
	lc set both corp.test. 300 A "$NET.80"
	lc set both corp.test. 300 MX "10 mail.corp.test."
	both want_rr corp.test. A "$NET.80"
	both want_rr corp.test. MX "10 mail.corp.test."
}
c_del() {
	dl_serial1=$(serial_of "$NS1" corp.test.) dl_serial2=$(serial_of "$NS2" corp.test.)
	lc del both corp.test. TXT
	both want_rr corp.test. TXT
	both want_rr corp.test. A "$NET.80"
	both want_rr _dmarc.corp.test. TXT '"v=DMARC1; p=reject"'
	want_serial ns1 corp.test. "$(plus "$dl_serial1" 1)"
	want_serial ns2 corp.test. "$(plus "$dl_serial2" 1)"
	lc del both www.corp.test. A
	both want_nx www.corp.test. A
	lc set both corp.test. 300 TXT '"v=spf1 mx -all"'
	lc set both www.corp.test. 300 A "$NET.81"
	both want_rr corp.test. TXT '"v=spf1 mx -all"'
	both want_rr www.corp.test. A "$NET.81"
}
c_immediate() { # five changes in a row, each seen at once on both servers
	for ci_i in 1 2 3 4 5; do
		lc set both www.corp.test. 300 A "$NET.7$ci_i"
		both want_rr www.corp.test. A "$NET.7$ci_i"
	done
	lc set both www.corp.test. 300 A "$NET.81"
	both want_rr www.corp.test. A "$NET.81"
}
c_delegate() {
	lc delegate corp.test. ns1.corp.test. ns1.dnshost.test.
	want_ref "$TLD" corp.test. ns1.corp.test. ns1.dnshost.test.
	want_glue "$TLD" corp.test. ns1.corp.test. "$NET.11"
	want_ref "$TLD" dnshost.test. ns1.dnshost.test. ns2.dnshost.test.
	lc delegate corp.test. ns1.corp.test. ns2.corp.test.
	corp_at_parent
}
c_glue() {
	lc glue ns1.corp.test. "$NET.66" "$NET.67"
	lc glue ns2.corp.test.
	want_ref "$TLD" corp.test. ns1.corp.test. ns2.corp.test.
	want_glue "$TLD" corp.test. ns1.corp.test. "$NET.66" "$NET.67"
	want_glue "$TLD" corp.test. ns2.corp.test.
	want_glue "$TLD" dnshost.test. ns1.dnshost.test. "$NET.11"
	lc glue ns1.corp.test. "$NET.11"
	lc glue ns2.corp.test. "$NET.12"
	corp_at_parent
}
c_ds() {
	lc ds corp.test. "$DS1" "$DS2"
	want_rr "$TLD" corp.test. DS "$DS1" "$DS2"
	want_rr "$TLD" dnshost.test. DS
	lc ds corp.test. none
	want_rr "$TLD" corp.test. DS
}
c_undelegate() {
	lc undelegate corp.test.
	want_nx "$TLD" corp.test. NS
	want_nx "$TLD" www.corp.test. A
	want_nx "$TLD" ns1.corp.test. A # the glue is gone too
	want_nx "$TLD" ns2.corp.test. A
	want_ref "$TLD" dnshost.test. ns1.dnshost.test. ns2.dnshost.test.
	want_rr "$NS1" www.corp.test. A "$NET.81"
	lc delegate corp.test. ns1.corp.test. ns2.corp.test. # makes the delegation again, with no glue
	want_ref "$TLD" corp.test. ns1.corp.test. ns2.corp.test.
	want_glue "$TLD" corp.test. ns1.corp.test.
	lc glue ns1.corp.test. "$NET.11"
	lc glue ns2.corp.test. "$NET.12"
	corp_at_parent
}
c_lie() {
	lc lie corp.test. A "$NET.66" "$NET.67"
	want_rec "$LIAR" corp.test. A "$NET.66" "$NET.67"
	want_rec "$RESOLVER" corp.test. A "$NET.80"
	want_rec "$LIAR" corp.test. MX "10 mail.corp.test."
	want_rec "$LIAR" www.corp.test. A "$NET.81"
	lc lie clear
}
c_lie_clear() {
	lc lie www.corp.test. A "$NET.66"
	lc lie mail.corp.test. A "$NET.67"
	want_rec "$LIAR" www.corp.test. A "$NET.66"
	lc lie clear
	want_rec "$LIAR" www.corp.test. A "$NET.81"
	want_rec "$LIAR" mail.corp.test. A "$NET.82"
}
c_hooks_list() {
	same "POST /accept/list-$TOKEN" "200 $RECEIVER" "$(post "/accept/list-$TOKEN")"
	post "/accept/put-$TOKEN" -X PUT >/dev/null
	hl_req=$(stored "list-$TOKEN")
	same "stored requests with path /accept/list-$TOKEN" 1 "$(printf '%s\n' "$hl_req" | grep -c .)"
	for hl_want in '"time"' '"method"' '"POST"' '"path"' '"headers"' "hdr-$TOKEN" '"body"' "body-$TOKEN" '"status"'; do
		case $hl_req in *"$hl_want"*) ;; *) echo "stored request: want $hl_want in it, got ${hl_req:-nothing}" ;; esac
	done
	printf '%s\n' "$hl_req" | grep -qi 'x-accept-check' || echo "stored request: want the header X-Accept-Check in it, got ${hl_req:-nothing}"
	has_status "$hl_req" 200 || echo "stored request: want status 200 in it, got ${hl_req:-nothing}"
	hl_req=$(stored "put-$TOKEN")
	case $hl_req in *'"PUT"'*) ;; *) echo "stored PUT request: want \"PUT\" in it, got ${hl_req:-nothing}" ;; esac
	lc hooks clear
}
c_hooks_clear() {
	same "POST /accept/clear-$TOKEN" "200 $RECEIVER" "$(post "/accept/clear-$TOKEN")"
	lc hooks clear
	hc_hooks=$(labctl hooks list 2>&1)
	[ -z "$hc_hooks" ] || echo "labctl hooks list after hooks clear: want no output, got $hc_hooks"
}
c_hooks_fail() {
	lc hooks fail 503 2
	hf_codes=$(post "/accept/fail1-$TOKEN" | cut -d' ' -f1)
	hf_codes="$hf_codes $(post "/accept/fail2-$TOKEN" | cut -d' ' -f1)"
	hf_codes="$hf_codes $(post "/accept/fail3-$TOKEN" | cut -d' ' -f1)"
	same "HTTP status of three POSTs after hooks fail 503 2" "503 503 200" "$hf_codes"
	for hf_i in 1 2 3; do
		hf_want=503
		[ "$hf_i" = 3 ] && hf_want=200
		hf_req=$(stored "fail$hf_i-$TOKEN")
		has_status "$hf_req" "$hf_want" || echo "stored request /accept/fail$hf_i-$TOKEN: want status $hf_want, got ${hf_req:-nothing}"
	done
	lc hooks clear
}
c_hooks_rate_limit() { # a rate limit: the status, both headers and the body, for exactly 2 requests
	lc hooks reply 429 2 --header 'Retry-After: 30' --header 'X-RateLimit-Remaining: 0' --body 'slow down'
	for hr_i in 1 2 3; do
		hr_want='429|30|0' hr_status=429
		[ "$hr_i" = 3 ] && hr_want='200||' hr_status=200
		same "POST $hr_i after hooks reply 429 2 (status|Retry-After|X-RateLimit-Remaining)" "$hr_want" \
			"$(hit "/accept/limit$hr_i-$TOKEN" '%{http_code}|%header{retry-after}|%header{x-ratelimit-remaining}')"
		if [ "$hr_i" = 3 ]; then
			[ "$(body)" != 'slow down' ] || echo "body of POST 3: want another body than the reply's, got slow down"
		else
			same "body of POST $hr_i" 'slow down' "$(body)"
		fi
		hr_req=$(stored "limit$hr_i-$TOKEN")
		has_status "$hr_req" "$hr_status" || echo "stored request /accept/limit$hr_i-$TOKEN: want status $hr_status, got ${hr_req:-nothing}"
	done
	lc hooks clear
}
c_hooks_delay() { # a slow service: only the next request waits
	lc hooks reply 200 1 --delay 2
	hd_post=$(hit "/accept/slow1-$TOKEN" '%{http_code} %{time_total}')
	same "HTTP status of POST 1 after hooks reply 200 1 --delay 2" 200 "${hd_post%% *}"
	seconds_in "time of POST 1 after hooks reply 200 1 --delay 2" 2 9 "${hd_post#* }"
	hd_post=$(hit "/accept/slow2-$TOKEN" '%{http_code} %{time_total}')
	same "HTTP status of POST 2" 200 "${hd_post%% *}"
	seconds_in "time of POST 2" 0 1 "${hd_post#* }"
	lc hooks clear
}
c_hooks_redirect() {
	hd_to="https://hooks.lab.test/accept/moved-$TOKEN"
	lc hooks reply 302 1 --header "Location: $hd_to"
	same "POST 1 after hooks reply 302 1 (status|Location)" "302|$hd_to" \
		"$(hit "/accept/redirect1-$TOKEN" '%{http_code}|%header{location}')"
	same "POST 2 (status|Location)" "200|" "$(hit "/accept/redirect2-$TOKEN" '%{http_code}|%header{location}')"
	lc hooks clear
}
c_exit_codes() {
	ec_serial=$(serial_of "$NS1" corp.test.)
	same "exit code of labctl serial ns1 corp.test." 0 "$(code serial ns1 corp.test.)"
	same "exit code of labctl with no arguments" 2 "$(code)"
	same "exit code of labctl no-such-command" 2 "$(code no-such-command)"
	same "exit code of labctl set ns3 www.corp.test. 300 A $NET.66" 2 "$(code set ns3 www.corp.test. 300 A "$NET.66")"
	same "exit code of labctl serial both corp.test." 2 "$(code serial both corp.test.)"
	# A name in no zone of the lab: well formed, so the lab itself must refuse it.
	same "exit code of labctl set ns1 www.example.org. 300 A 192.0.2.1" 1 "$(code set ns1 www.example.org. 300 A 192.0.2.1)"
	want_rr "$NS1" www.corp.test. A "$NET.81"
	want_serial ns1 corp.test. "$ec_serial"
}

# ---- attacks: put the lab into the state and back ----

c_ns_replaced() {
	lc delegate corp.test. ns1.dnshost.test. ns2.dnshost.test.
	want_ref "$TLD" corp.test. ns1.dnshost.test. ns2.dnshost.test.
	lc delegate corp.test. ns1.corp.test. ns2.corp.test.
	corp_at_parent
}
c_glue_swapped() {
	lc glue ns1.corp.test. "$NET.66"
	want_ref "$TLD" corp.test. ns1.corp.test. ns2.corp.test.
	want_glue "$TLD" corp.test. ns1.corp.test. "$NET.66"
	lc glue ns1.corp.test. "$NET.11"
	corp_at_parent
}
c_ds_changed() { # the DS is added, replaced and removed
	lc ds corp.test. "$DS1"
	want_rr "$TLD" corp.test. DS "$DS1"
	lc ds corp.test. "$DS2"
	want_rr "$TLD" corp.test. DS "$DS2"
	lc ds corp.test. none
	want_rr "$TLD" corp.test. DS
}
c_domain_deleted() { # the parent says "no such name" (lock, transfer and expiry are RDAP data)
	lc undelegate corp.test.
	want_nx "$TLD" corp.test. NS
	redelegate_corp
	corp_at_parent
}
c_record_changed() { # a record is changed at the provider, and the serial moves
	rc_serial1=$(serial_of "$NS1" corp.test.) rc_serial2=$(serial_of "$NS2" corp.test.)
	lc set both www.corp.test. 300 A "$NET.66"
	both want_rr www.corp.test. A "$NET.66"
	want_serial ns1 corp.test. "$(plus "$rc_serial1" 1)"
	want_serial ns2 corp.test. "$(plus "$rc_serial2" 1)"
	lc set both www.corp.test. 300 A "$NET.81"
	both want_rr www.corp.test. A "$NET.81"
}
c_changed_and_put_back() { # the data is as before, the serial moved by 2
	cb_serial1=$(serial_of "$NS1" corp.test.) cb_serial2=$(serial_of "$NS2" corp.test.)
	lc set both www.corp.test. 300 A "$NET.66"
	lc set both www.corp.test. 300 A "$NET.81"
	both want_rr www.corp.test. A "$NET.81"
	want_serial ns1 corp.test. "$(plus "$cb_serial1" 2)"
	want_serial ns2 corp.test. "$(plus "$cb_serial2" 2)"
}
c_one_server_differs() {
	lc set ns2 www.corp.test. 300 A "$NET.66"
	want_rr "$NS1" www.corp.test. A "$NET.81"
	want_rr "$NS2" www.corp.test. A "$NET.66"
	lc set ns2 www.corp.test. 300 A "$NET.81"
	want_rr "$NS2" www.corp.test. A "$NET.81"
}
c_alias_target_gone() {
	lc del both edge.dnshost.test. A
	both want_rr cdn.corp.test. CNAME edge.dnshost.test.
	both want_nx edge.dnshost.test. A
	lc set both edge.dnshost.test. 300 A "$NET.83"
	both want_rr edge.dnshost.test. A "$NET.83"
}
c_ns_domain_gone() { # the domain of the nameserver names of shop.test. is no longer registered
	lc undelegate dnshost.test.
	want_nx "$TLD" ns1.dnshost.test. A
	want_ref "$TLD" shop.test. ns1.dnshost.test. ns2.dnshost.test.
	lc delegate dnshost.test. ns1.dnshost.test. ns2.dnshost.test.
	lc glue ns1.dnshost.test. "$NET.11"
	lc glue ns2.dnshost.test. "$NET.12"
	want_ref "$TLD" dnshost.test. ns1.dnshost.test. ns2.dnshost.test.
	want_glue "$TLD" dnshost.test. ns1.dnshost.test. "$NET.11"
	want_glue "$TLD" dnshost.test. ns2.dnshost.test. "$NET.12"
}
c_mx_target_gone() {
	lc del both mail.corp.test. A
	both want_rr corp.test. MX "10 mail.corp.test."
	both want_nx mail.corp.test. A
	lc set both mail.corp.test. 300 A "$NET.82"
	both want_rr mail.corp.test. A "$NET.82"
}
c_caa_weakened() { # the CAA policy is weakened, then removed
	lc set both corp.test. 300 CAA '0 issue "ca.test"' '0 issue "evil.test"'
	both want_rr corp.test. CAA '0 issue "ca.test"' '0 issue "evil.test"'
	lc del both corp.test. CAA
	both want_rr corp.test. CAA
	lc set both corp.test. 300 CAA '0 issue "ca.test"'
	both want_rr corp.test. CAA '0 issue "ca.test"'
}
c_resolver_lies() {
	lc lie corp.test. MX "10 mail.evil.test."
	want_rec "$LIAR" corp.test. MX "10 mail.evil.test."
	want_rec "$RESOLVER" corp.test. MX "10 mail.corp.test."
	lc lie clear
	want_rec "$LIAR" corp.test. MX "10 mail.corp.test."
}
c_acme_challenge() {
	lc set both _acme-challenge.corp.test. 300 TXT '"accept-check"'
	both want_rr _acme-challenge.corp.test. TXT '"accept-check"'
	lc del both _acme-challenge.corp.test. TXT
	both want_nx _acme-challenge.corp.test. TXT
}
c_wildcard() {
	lc set both '*.corp.test.' 300 A "$NET.66"
	both want_rr "rnd-$TOKEN.corp.test." A "$NET.66"
	both want_rr www.corp.test. A "$NET.81"
	lc del both '*.corp.test.' A
	both want_nx "rnd-$TOKEN.corp.test." A
}

# ---- load-zone and drop-zone; a check that replaces a base zone ends with labctl reset ----

c_load_signed() {
	mkdir "$TMP/sign" && cd "$TMP/sign" || { echo "cannot make $TMP/sign"; return 0; }
	cat >accept.zone <<EOF
accept.test. 300 SOA ns1.accept.test. hostmaster.accept.test. 2026111001 3600 600 604800 300
accept.test. 300 NS ns1.accept.test.
ns1.accept.test. 300 A $NET.11
accept.test. 300 A $NET.85
EOF
	# The signatures are valid only in January 2020, so the zone is also broken (expired): the
	# server must serve them as they are. -P skips the signer's own check, which would refuse them.
	if ! sign accept.test. accept.zone -P -s 20200101000000 -e 20200201000000 >/dev/null 2>&1; then
		echo "signing accept.test. with dnssec-keygen and dnssec-signzone: failed"
		return 0
	fi
	lc load-zone ns1 accept.test. "$TMP/sign/accept.zone.signed"
	same "serial of accept.test. @$NS1" 2026111001 "$(serial_of "$NS1" accept.test.)"
	for cl_t in SOA A DNSKEY; do
		cl_want=$(records <accept.zone.signed | pick accept.test. RRSIG | sigs "$cl_t" | set_of)
		[ "$cl_want" != "{}" ] || echo "signed file: want RRSIG $cl_t, got none"
		aq "$NS1" accept.test. "$cl_t" +dnssec
		same "RRSIG $cl_t of accept.test. @$NS1" "$cl_want" "$(rr ANSWER accept.test. RRSIG | sigs "$cl_t" | set_of)"
	done
	not_served "$NS2" accept.test.
	lc drop-zone ns1 accept.test.
}
c_drop_zone() {
	cat >"$TMP/drop.zone" <<EOF
drop.test. 300 SOA ns1.drop.test. hostmaster.drop.test. 7 3600 600 604800 300
drop.test. 300 NS ns1.drop.test.
ns1.drop.test. 300 A $NET.11
EOF
	dz_soa="ns1.drop.test. hostmaster.drop.test. 7 3600 600 604800 300"
	lc load-zone both drop.test. "$TMP/drop.zone"
	both want_rr drop.test. SOA "$dz_soa"
	lc drop-zone ns1 drop.test.
	want_refused "$NS1" drop.test.
	want_rr "$NS2" drop.test. SOA "$dz_soa"
	lc drop-zone ns2 drop.test.
	want_refused "$NS2" drop.test.
}
c_loaded_refuses() { # set and del are refused on a zone that load-zone made, and change nothing
	cat >"$TMP/fixed.zone" <<EOF
fixed.test. 300 SOA ns1.fixed.test. hostmaster.fixed.test. 5 3600 600 604800 300
fixed.test. 300 NS ns1.fixed.test.
ns1.fixed.test. 300 A $NET.11
www.fixed.test. 300 A $NET.88
EOF
	lc load-zone ns1 fixed.test. "$TMP/fixed.zone"
	same "exit code of labctl set ns1 www.fixed.test. 300 A $NET.66" 1 "$(code set ns1 www.fixed.test. 300 A "$NET.66")"
	same "exit code of labctl del ns1 www.fixed.test. A" 1 "$(code del ns1 www.fixed.test. A)"
	want_rr "$NS1" www.fixed.test. A "$NET.88"
	same "serial of fixed.test. @$NS1" 5 "$(serial_of "$NS1" fixed.test.)"
	lc drop-zone ns1 fixed.test.
}
c_load_replace() {
	lc set ns2 www.corp.test. 300 A "$NET.66" # the serial on ns2 is now above 1
	lr_serial1=$(serial_of "$NS1" corp.test.)
	cat >"$TMP/corp-small.zone" <<EOF
corp.test. 300 SOA ns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300
corp.test. 300 NS ns1.corp.test.
corp.test. 300 NS ns2.corp.test.
ns1.corp.test. 300 A $NET.11
ns2.corp.test. 300 A $NET.12
www.corp.test. 300 A $NET.67
EOF
	lc load-zone ns2 corp.test. "$TMP/corp-small.zone"
	want_serial ns2 corp.test. 1 # the serial of the file, also when it is lower
	want_rr "$NS2" www.corp.test. A "$NET.67"
	want_nx "$NS2" mail.corp.test. A
	want_rr "$NS1" www.corp.test. A "$NET.81"
	want_serial ns1 corp.test. "$lr_serial1"
	lc reset
	want_rr "$NS2" mail.corp.test. A "$NET.82"
}
c_serial_still() { # a provider that never moves the serial: the data changes, the serial does not
	ss_serial=$(serial_of "$NS1" corp.test.)
	for ss_host in 66 67; do
		cat >"$TMP/still.zone" <<EOF
corp.test. 300 SOA ns1.corp.test. hostmaster.corp.test. $ss_serial 3600 600 604800 300
corp.test. 300 NS ns1.corp.test.
corp.test. 300 NS ns2.corp.test.
ns1.corp.test. 300 A $NET.11
ns2.corp.test. 300 A $NET.12
www.corp.test. 300 A $NET.$ss_host
EOF
		lc load-zone ns1 corp.test. "$TMP/still.zone"
		want_rr "$NS1" www.corp.test. A "$NET.$ss_host"
		want_serial ns1 corp.test. "$ss_serial"
	done
	lc reset
}
# chain: once, sign a root zone, a test. zone and sec.test. into $TMP/chain, where
# sec-expired.zone.signed holds signatures that expired in 2020
chain() {
	[ -s "$TMP/chain/root.zone.signed" ] && return 0
	mkdir -p "$TMP/chain" && cd "$TMP/chain" || return 1
	cat >sec.zone <<EOF
\$TTL 300
sec.test. SOA ns1.dnshost.test. hostmaster.sec.test. 1 3600 600 604800 300
sec.test. NS ns1.dnshost.test.
sec.test. NS ns2.dnshost.test.
www.sec.test. A $NET.86
late.sec.test. A $NET.87
plain.sec.test. A $NET.88
EOF
	cp sec.zone sec-expired.zone
	cat >test.zone <<EOF
\$TTL 300
test. SOA ns.test. hostmaster.test. 1 3600 600 604800 300
test. NS ns.test.
ns.test. A $NET.3
dnshost.test. NS ns1.dnshost.test.
dnshost.test. NS ns2.dnshost.test.
ns1.dnshost.test. A $NET.11
ns2.dnshost.test. A $NET.12
sec.test. NS ns1.dnshost.test.
sec.test. NS ns2.dnshost.test.
EOF
	cat >root.zone <<EOF
\$TTL 300
. SOA root-ns. hostmaster.root-ns. 1 3600 600 604800 300
. NS root-ns.
root-ns. A $NET.2
test. NS ns.test.
ns.test. A $NET.3
EOF
	sign sec.test. sec.zone &&
		sign sec.test. sec-expired.zone -P -s 20200101000000 -e 20200201000000 &&
		cat dsset-sec.test. >>test.zone && sign test. test.zone &&
		cat dsset-test. >>root.zone && sign . root.zone || return 1
	{
		echo 'trust-anchors {'
		awk '$3 == "DNSKEY" && $4 == 257 { k = ""; for (i = 7; i <= NF; i++) k = k $i
			printf "\t. static-key %s %s %s \"%s\";\n", $4, $5, $6, k }' K.+*.key
		echo '};'
	} >anchor.conf
}
load_chain() { # load_chain <signed sec.test. file>
	lc load-zone both sec.test. "$TMP/chain/$1"
	lc load-zone tld test. "$TMP/chain/test.zone.signed"
	lc load-zone root . "$TMP/chain/root.zone.signed"
}
# delv_through <name>: validate the A record of the name with delv through the resolver, from
# the root key of the chain as the only trust anchor
delv_through() { delv @"$RESOLVER" -a "$TMP/chain/anchor.conf" +root=. "$1" A 2>&1; }
c_dnssec_broken() { # a signed chain root, test., sec.test. validates; an expired signature does not
	if ! chain >/dev/null 2>&1; then
		echo "signing root, test. and sec.test. with dnssec-keygen and dnssec-signzone: failed"
		return 0
	fi
	load_chain sec.zone.signed
	db_delv=$(delv_through www.sec.test.)
	case $db_delv in *"; fully validated"*) ;; *) echo "delv www.sec.test. A @$RESOLVER: want fully validated, got $db_delv" ;; esac
	lc load-zone both sec.test. "$TMP/chain/sec-expired.zone.signed"
	# late.sec.test. was not asked before, so no valid signature of it is in a cache.
	db_delv=$(delv_through late.sec.test.)
	case $db_delv in *"fully validated"*) echo "delv late.sec.test. A @$RESOLVER (expired signature): want no validation, got $db_delv" ;; esac
	lc reset
	c_base_root
	c_base_parent
	c_base_no_ds
	want_nx "$TLD" sec.test. NS
	both want_refused sec.test.
}
c_no_validation() { # a broken signature does not hide the answer: tests can see what they break
	if ! chain >/dev/null 2>&1; then
		echo "signing root, test. and sec.test. with dnssec-keygen and dnssec-signzone: failed"
		return 0
	fi
	load_chain sec-expired.zone.signed
	want_rec "$RESOLVER" plain.sec.test. A "$NET.88"
	lc reset
}
# c_reset_dirty: reset from a lab where every kind of change is still in place gives the base state
c_reset_dirty() {
	cat >"$TMP/extra.zone" <<EOF
extra.test. 300 SOA ns1.extra.test. hostmaster.extra.test. 1 3600 600 604800 300
extra.test. 300 NS ns1.extra.test.
ns1.extra.test. 300 A $NET.11
EOF
	cat >"$TMP/corp-static.zone" <<EOF
corp.test. 300 SOA ns1.corp.test. hostmaster.corp.test. 9 3600 600 604800 300
corp.test. 300 NS ns1.corp.test.
corp.test. 300 NS ns2.corp.test.
ns1.corp.test. 300 A $NET.11
ns2.corp.test. 300 A $NET.12
www.corp.test. 300 A $NET.67
EOF
	rd_new=new-$TOKEN.corp.test. # a name that no check asked before, so no cache holds it
	lc set both www.corp.test. 300 A "$NET.66"
	lc set both "$rd_new" 300 A "$NET.66"
	want_rec "$RESOLVER" "$rd_new" A "$NET.66" # now in the cache of the resolver
	lc load-zone ns2 corp.test. "$TMP/corp-static.zone"
	lc load-zone both extra.test. "$TMP/extra.zone"
	lc ds corp.test. "$DS1"
	lc lie corp.test. MX "10 mail.evil.test."
	post "/accept/dirty-$TOKEN" >/dev/null
	lc hooks reply 503 5 --header 'Retry-After: 9' --delay 3 --body pending
	lc reset
	rq "$RESOLVER" "$rd_new" A
	[ "$(out | status)" = NXDOMAIN ] || echo "$rd_new A @$RESOLVER after reset: want NXDOMAIN, got $(got)"
	c_base_root
	c_base_parent
	c_base_no_ds
	for rd_z in corp.test. dnshost.test. shop.test.; do
		want_zone ns1 "$rd_z"
		want_zone ns2 "$rd_z"
	done
	c_only_listed
	c_base_services
}
c_set_after_reset() { # reset makes the base zones open to set again; a second reset undoes it
	lc set both www.corp.test. 300 A "$NET.66"
	both want_rr www.corp.test. A "$NET.66"
	want_serial ns1 corp.test. 2
	want_serial ns2 corp.test. 2
	lc reset
	both want_rr www.corp.test. A "$NET.81"
	want_serial ns1 corp.test. 1
	want_serial ns2 corp.test. 1
}
# c_reset_zone_gone: a zone that the file _default.nzf lists but the server no longer has, and a zone
# that the file lists twice, are no reason for reset to fail
c_reset_zone_gone() {
	rg_nzf=/lab/ns2/_default.nzf
	rndc -s "$NS2" -k /lab/ctl.key delzone -clean corp.test. >/dev/null 2>&1
	rg_line=$(grep '^zone "shop.test."' "$rg_nzf")
	printf '%s\n' "$rg_line" >>"$rg_nzf"
	lc reset
	c_only_listed
	want_zone ns2 corp.test.
	[ "$(grep -c '^zone ' "$rg_nzf")" = 3 ] || echo "$rg_nzf after reset: want 3 zones, got $(grep -c '^zone ' "$rg_nzf")"
}
# c_reset_twice: a reset right after a reset, and right after a change of Unbound, gives the base state
c_reset_twice() {
	lc lie corp.test. MX "10 mail.evil.test."
	lc reset
	lc reset
	both want_rr www.corp.test. A "$NET.81"
	c_only_listed
	c_base_services
}
# c_reset_after_failed_load: a load that labctl refuses leaves the zone as it was, and reset still works
c_reset_after_failed_load() {
	printf 'not a zone file\n' >"$TMP/broken.zone"
	same "exit code of labctl load-zone ns1 corp.test. with a broken file" 1 "$(code load-zone ns1 corp.test. "$TMP/broken.zone")"
	want_zone ns1 corp.test.
	lc reset
	c_only_listed
}
c_reset() { lc reset; }

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
	NET=10.53.${LAB_ID:-}
	check runner-address c_runner_address
	case ${LAB_ID:-} in [0-9]) ;; *) exit 1 ;; esac
	ROOT=$NET.2 TLD=$NET.3 NS1=$NET.11 NS2=$NET.12 RESOLVER=$NET.20 LIAR=$NET.21 RECEIVER=$NET.30
	V6=fd53:0:0:$LAB_ID::80
	[ "$LAB_ID" = 0 ] && V6=fd53::80 # how dig prints fd53:0:0:0::80
	TOKEN=acc$$
	TMP=$(mktemp -d /tmp/labaccept.XXXXXX) || exit 1
	trap 'rm -rf "$TMP"' EXIT
	trap 'labctl reset >/dev/null 2>&1; exit 1' INT TERM

	check runner-tools c_runner_tools
	check runner-src-read-only c_src_read_only
	check host-root c_host "$ROOT" . SOA aa
	check host-tld c_host "$TLD" test. SOA aa
	check host-ns1 c_host "$NS1" corp.test. SOA aa
	check host-ns2 c_host "$NS2" corp.test. SOA aa
	check host-resolver c_host "$RESOLVER" www.corp.test. A ra
	check host-liar c_host "$LIAR" www.corp.test. A ra
	check silent-99 c_silent
	check resolver-via-lab-root c_resolver "$RESOLVER"
	check liar-via-lab-root c_resolver "$LIAR"
	check xfr-with-key c_xfr_key
	check xfr-without-key c_xfr_nokey
	check xfr-wrong-key c_xfr_wrongkey
	check any-minimal c_any_minimal
	check receiver-https c_receiver

	base_checks ""

	check labctl-serial c_serial
	check labctl-set-one-server c_set_one
	check labctl-set-both c_set_both
	check labctl-set-unchanged c_set_unchanged
	check labctl-set-replaces-set c_set_replace
	check labctl-del c_del
	check labctl-immediate c_immediate
	check labctl-delegate c_delegate
	check labctl-glue c_glue
	check labctl-ds c_ds
	check labctl-undelegate c_undelegate
	check labctl-lie c_lie
	check labctl-lie-clear c_lie_clear
	check labctl-hooks-list c_hooks_list
	check labctl-hooks-clear c_hooks_clear
	check labctl-hooks-fail c_hooks_fail
	check labctl-hooks-reply-rate-limit c_hooks_rate_limit
	check labctl-hooks-reply-delay c_hooks_delay
	check labctl-hooks-reply-redirect c_hooks_redirect
	check labctl-exit-codes c_exit_codes

	check attack-ns-replaced c_ns_replaced
	check attack-glue-swapped c_glue_swapped
	check attack-ds-changed c_ds_changed
	check attack-domain-deleted c_domain_deleted
	check attack-record-changed c_record_changed
	check attack-changed-and-put-back c_changed_and_put_back
	check attack-one-server-differs c_one_server_differs
	check attack-alias-target-gone c_alias_target_gone
	check attack-ns-domain-gone c_ns_domain_gone
	check attack-mx-target-gone c_mx_target_gone
	check attack-caa-weakened c_caa_weakened
	check attack-resolver-lies c_resolver_lies
	check attack-acme-challenge c_acme_challenge
	check attack-wildcard c_wildcard

	check labctl-load-zone-signed c_load_signed
	check labctl-drop-zone c_drop_zone
	check labctl-loaded-zone-refuses-set c_loaded_refuses
	check labctl-load-zone-replace c_load_replace
	check attack-serial-does-not-move c_serial_still
	check attack-dnssec-broken c_dnssec_broken
	check resolver-does-not-validate c_no_validation
	check reset-from-dirty c_reset_dirty
	check reset-zone-gone c_reset_zone_gone
	check reset-twice c_reset_twice
	check reset-after-failed-load c_reset_after_failed_load

	check end-reset c_reset
	base_checks end-
	check end-set-after-reset c_set_after_reset

	[ "$FAILS" -eq 0 ] && exit 0
	exit 1
}

main

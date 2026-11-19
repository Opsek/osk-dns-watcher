#!/bin/sh
# build/version.sh <text> exits 0 when the text is a version of osk-dns-watcher, and 2
# otherwise. A version is three numbers with no leading zero, then optionally
# "-" and words of ASCII letters and digits separated by dots, where a word
# of digits only is a number with no leading zero: 0.1.0, 0.1.0-rc.1. The
# text goes into a link flag, file names and commands, so nothing else may
# pass; and versions order by their numbers.
LC_ALL=C
export LC_ALL

case ${1-} in
'' | *[!0-9A-Za-z.-]*) ;;
*)
	# grep matches each line; the pattern above has already refused a newline.
	printf '%s\n' "$1" |
		grep -Eqx '(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z][0-9A-Za-z]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z][0-9A-Za-z]*))*)?' &&
		exit 0
	;;
esac
echo "not a version: want three numbers and an optional label, such as 0.1.0 or 0.1.0-rc.1" >&2
exit 2

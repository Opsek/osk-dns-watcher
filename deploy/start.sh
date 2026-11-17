#!/bin/sh
# Sets up and starts osk with Docker Compose. The first run asks two
# questions; "start.sh update" pulls the new code first. Both end with a
# test message through the running service, so a broken webhook shows at once.
set -eu

stop() {
	echo "$1" >&2
	exit 1
}

cd "$(dirname "$0")" || stop "start.sh cannot enter its own folder."
case ${1:-} in
'') ;;
update)
	git pull --ff-only || stop "git pull failed (see above), so osk was not updated."
	# The pull may have changed this file: the new one does the rest.
	exec ./start.sh
	;;
*)
	echo "usage: start.sh [update]" >&2
	exit 2
	;;
esac
docker compose version >/dev/null 2>&1 ||
	stop "start.sh needs Docker with the Compose plugin: 'docker compose version' does not work here."
docker compose --profile setup build </dev/null ||
	stop "The build of osk failed (see above)."
docker compose run --rm init ||
	stop "The setup was not written (see above), so osk was not started. Fix what is said above, then run start.sh again."
docker compose up --detach --wait </dev/null ||
	stop "osk did not start or is not healthy. Its log: docker compose logs osk"
docker compose exec -T osk osk test-alert --config /data/osk.json </dev/null || {
	echo "The test message did not get through. Find out why with:" >&2
	echo "  docker compose exec osk osk doctor --config /data/osk.json" >&2
	exit 1
}
echo "osk is running. Your channel has a test message from it."

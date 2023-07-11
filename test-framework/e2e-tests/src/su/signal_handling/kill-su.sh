#!/usr/bin/env sh
#
# because the su process is `spawn`-ed it may not be immediately visible so
# retry `pidof` until it becomes visible
for _ in $(seq 1 20); do
    # when su runs with `use_pty` there are two su processes as su spawns
    # a monitor process. We want the PID of the su process so we assume it
    # must be the smallest of the returned PIDs.
    supid="-1"
    pids="$(pidof su)"
    for pid in $pids; do
        if [ "$pid" -le "$supid" ] || [ "$supid" -eq -1 ]; then
            supid=$pid
        fi
    done

    if [ "$supid" -ne -1 ]; then
        # give `expects-signal.sh ` some time to execute the `trap` command
        # otherwise it'll be terminated before the signal handler is installed
        sleep 0.1
        kill "$1" "$supid"
        exit 0
    fi
    sleep 0.1
done

echo >&2 timeout
exit 1

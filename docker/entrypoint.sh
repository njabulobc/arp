#!/bin/sh
set -e

CMD="python"
ARGS="-m arp_detector.cli"

set -- $CMD $ARGS

if [ -n "$MONITOR_INTERFACE" ]; then
  set -- "$@" --interface "$MONITOR_INTERFACE"
fi
if [ -n "$MONITOR_WINDOW" ]; then
  set -- "$@" --window "$MONITOR_WINDOW"
fi
if [ -n "$MONITOR_DETECT_THRESHOLD" ]; then
  set -- "$@" --detect "$MONITOR_DETECT_THRESHOLD"
fi
if [ -n "$MONITOR_HIGH_THRESHOLD" ]; then
  set -- "$@" --high "$MONITOR_HIGH_THRESHOLD"
fi
if [ -n "$MONITOR_WARN_ALERT" ]; then
  set -- "$@" --warn-alert "$MONITOR_WARN_ALERT"
fi
if [ -n "$MONITOR_CRITICAL_ALERT" ]; then
  set -- "$@" --critical-alert "$MONITOR_CRITICAL_ALERT"
fi
if [ "$DISABLE_TELEMETRY" = "1" ]; then
  set -- "$@" --disable-telemetry
fi
if [ "$SIMULATE_TRAFFIC" = "1" ]; then
  set -- "$@" --simulate
fi

exec "$@"

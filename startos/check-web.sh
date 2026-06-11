#!/bin/sh
# StartOS health check: the dashboard answers on the API port.
# Injected into the main container (inject: true in the manifest).
DURATION=$(cat)
if [ "$DURATION" -lt 30000 ] 2>/dev/null; then
  echo '{"result":"starting"}'
  exit 0
fi
if curl -sf -o /dev/null -m 10 http://localhost:9100/health; then
  echo '{"result":null}'
else
  echo '{"result":"The dashboard is not responding yet — large nodes can take a couple of minutes after a restart."}'
fi

#!/usr/bin/env bash
# Throwaway host-level (WSL2/Linux) proof that PR_SET_PDEATHSIG genuinely
# orphan-protects the tun2socks-child binary. Not committed as part of the
# app; source only, for provenance alongside host_proof.go.
set -u
CHILD_BIN="$1"
SOCK=/tmp/b46-3b-pdeathsig-proof.sock
rm -f "$SOCK"

python3 -c '
import socket, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind("/tmp/b46-3b-pdeathsig-proof.sock")
s.listen(1)
conn, _ = s.accept()
time.sleep(30)
' >/tmp/b46-3b-listener.log 2>&1 &
LISTENER_PID=$!
sleep 0.5

setsid "$CHILD_BIN" "$SOCK" &
PARENT_PID=$!
sleep 0.3
CPID=$(pgrep -f "$(basename "$CHILD_BIN")")
echo "parent(setsid) pid=$PARENT_PID  child pid=$CPID"

if [ -z "$CPID" ]; then
  echo "PROOF_FAILED: could not find child pid"
  kill -9 "$LISTENER_PID" 2>/dev/null
  exit 1
fi

kill -9 "$PARENT_PID" 2>/dev/null

START=$(date +%s%N)
for i in $(seq 1 40); do
  if ! kill -0 "$CPID" 2>/dev/null; then
    END=$(date +%s%N)
    echo "PROOF_RESULT: child GONE after $(((END - START) / 1000000))ms - PASS"
    kill -9 "$LISTENER_PID" 2>/dev/null
    exit 0
  fi
  sleep 0.1
done
echo "PROOF_RESULT: child STILL ALIVE after 4s - FAIL"
kill -9 "$CPID" "$LISTENER_PID" 2>/dev/null
exit 1

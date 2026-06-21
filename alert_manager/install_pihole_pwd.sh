#!/bin/bash
# One-shot installer that moves PIHOLE_PASSWORD from the inline
# Environment= line in dashboard.service into /etc/nemesis.env,
# then installs the cleaned-up unit file. Idempotent.
set -e

UNIT_LIVE=/etc/systemd/system/dashboard.service
UNIT_SRC=/home/paul/dashboard/alert_manager/dashboard.service
NEMESIS_ENV=/etc/nemesis.env

echo "Before install:"
echo "  inline Environment= in unit: $(grep -c '^Environment=' "$UNIT_LIVE" 2>/dev/null || echo 0)"
echo "  PIHOLE_PASSWORD= in nemesis.env: $(grep -c '^PIHOLE_PASSWORD=' "$NEMESIS_ENV" 2>/dev/null || echo 0)"

# Capture the existing inline password before we overwrite the unit
PWD_LINE=$(grep -E '^Environment="PIHOLE_PASSWORD=' "$UNIT_LIVE" 2>/dev/null || true)
PWD_VAL=$(printf '%s' "$PWD_LINE" | sed -E 's/^Environment="PIHOLE_PASSWORD=//; s/"$//')

# Ensure PIHOLE_PASSWORD lives in /etc/nemesis.env
if grep -q '^PIHOLE_PASSWORD=' "$NEMESIS_ENV" 2>/dev/null; then
  echo "PIHOLE_PASSWORD already present in $NEMESIS_ENV (left as-is)"
elif [ -n "$PWD_VAL" ]; then
  printf 'PIHOLE_PASSWORD=%s\n' "$PWD_VAL" >> "$NEMESIS_ENV"
  echo "Appended PIHOLE_PASSWORD to $NEMESIS_ENV"
else
  echo "WARNING: no PIHOLE_PASSWORD found in unit file; add it manually to $NEMESIS_ENV"
fi

# Install the cleaned-up unit and reload
install -m 644 -o root -g root "$UNIT_SRC" "$UNIT_LIVE"
systemctl daemon-reload
systemctl restart dashboard.service
sleep 1
systemctl is-active dashboard.service

echo
echo "After install:"
echo "  inline Environment= in unit: $(grep -c '^Environment=' "$UNIT_LIVE" 2>/dev/null || echo 0)"
echo "  PIHOLE_PASSWORD= in nemesis.env: $(grep -c '^PIHOLE_PASSWORD=' "$NEMESIS_ENV" 2>/dev/null || echo 0)"

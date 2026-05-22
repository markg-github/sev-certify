#!/bin/bash
set -euo pipefail

TTY="tty1"

# Print prompt to tty1
echo "(debug build) Dropping into root shell..." > /dev/$TTY

# Stop existing getty so we can take over tty1
systemctl stop getty@$TTY.service || true

# Drop straight into root shell on tty1
exec /sbin/agetty --autologin root --noclear $TTY $TERM

#!/usr/bin/bash

# Enable strict mode
set -euo pipefail

# must run as root  

# Detect, don't assume, package manager
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
elif command -v apt >/dev/null 2>&1; then
    PKG_MGR="apt"
else
    echo "No supported package manager found."
    exit 1
fi

echo "Using $PKG_MGR as package manager."

# Example usage:
if [ "$PKG_MGR" = "apt" ]; then
    apt update
fi

$PKG_MGR install -y openssh-server sudo less iproute

# assume systemd
systemctl enable sshd
systemctl start sshd

useradd -m markg

usermod -aG wheel markg

# Check for the existence of the wheel or sudo group
if getent group wheel >/dev/null; then
    GROUP="wheel"
elif getent group sudo >/dev/null; then
    GROUP="sudo"
else
    echo "Neither 'wheel' nor 'sudo' group exists. Exiting."
    exit 1
fi

# Add the user to the identified group
usermod -aG "$GROUP" markg

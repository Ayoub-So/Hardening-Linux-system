#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

# Update the system
apt update
apt upgrade -y

# Set kernel parameters
cat <<EOL >> /etc/sysctl.conf
# IPv4 network hardening
net.ipv4.conf.all.arp_ignore=2
net.ipv4.conf.all.route_localnet=0
net.ipv4.conf.all.drop_gratuitous_arp=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_local_port_range=32768 65535
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_syncookies=1

# Disable IPv6
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.all.disable_ipv6=1

# Disable coredump for setuid executables
fs.suid_dumpable=0

# File system options
fs.protected_fifos=2
fs.protected_regular=2
fs.protected_symlinks=1
fs.protected_hardlinks=1
EOL

# Disable unused kernel modules
echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf
echo "install freevxfs /bin/true" > /etc/modprobe.d/freevxfs.conf
echo "install jffs2 /bin/true" > /etc/modprobe.d/jffs2.conf

# Harden compiler options
cat <<EOL >> /etc/sysctl.conf
# Harden compiler options
CONFIG_GCC_PLUGINS=y
CONFIG_GCC_PLUGIN_LATENT_ENTROPY=y
CONFIG_GCC_PLUGIN_STACKLEAK=y
CONFIG_GCC_PLUGIN_STRUCTLEAK=y
CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL=y
CONFIG_GCC_PLUGIN_RANDSTRUCT=y
EOL

# Apply sysctl changes
sysctl -p

echo "Security configurations applied successfully."

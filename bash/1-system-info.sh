#!/bin/bash

# Script to display system information
# Usage: ./1-system-info.sh

echo "=== System Information ==="
echo

# OS Information
echo "OS Information:"
echo "---------------"
uname -a
echo

# CPU Information
echo "CPU Information:"
echo "---------------"
sysctl -n machdep.cpu.brand_string
sysctl -n machdep.cpu.core_count
echo

# Memory Information
echo "Memory Information:"
echo "------------------"
vm_stat | grep "Pages free:" | awk '{print "Free Memory: " $3 * 4096 / 1024 / 1024 / 1024 " GB"}'
vm_stat | grep "Pages active:" | awk '{print "Active Memory: " $3 * 4096 / 1024 / 1024 / 1024 " GB"}'
echo

# Disk Information
echo "Disk Information:"
echo "----------------"
df -h /
echo

# Network Information
echo "Network Information:"
echo "-------------------"
ifconfig | grep "inet " | grep -v 127.0.0.1
echo

# Battery Information (if available)
echo "Battery Information:"
echo "-------------------"
pmset -g batt 2>/dev/null || echo "Battery information not available"
echo

# System Uptime
echo "System Uptime:"
echo "--------------"
uptime
echo

echo "=== End of System Information ===" 
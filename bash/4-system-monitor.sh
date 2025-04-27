#!/bin/bash

# Script to monitor system resources and processes
# Usage: ./4-system-monitor.sh [interval_in_seconds]

# Default interval is 5 seconds
INTERVAL=${1:-5}

# Function to get CPU usage
get_cpu_usage() {
    top -l 1 | grep "CPU usage" | awk '{print $3}' | tr -d '%'
}

# Function to get memory usage
get_memory_usage() {
    vm_stat | awk '/Pages active:/ {active=$3} /Pages free:/ {free=$3} END {print (active/(active+free))*100}'
}

# Function to get disk usage
get_disk_usage() {
    df -h / | awk 'NR==2 {print $5}' | tr -d '%'
}

# Function to get top processes
get_top_processes() {
    ps -eo pid,pcpu,pmem,comm --sort=-pcpu | head -n 6
}

# Function to check if a process is using too much CPU
check_cpu_usage() {
    local threshold=80
    local cpu_usage=$(get_cpu_usage)
    if (( $(echo "$cpu_usage > $threshold" | bc -l) )); then
        echo "WARNING: High CPU usage detected: ${cpu_usage}%"
        get_top_processes
    fi
}

# Function to check if memory usage is high
check_memory_usage() {
    local threshold=80
    local memory_usage=$(get_memory_usage)
    if (( $(echo "$memory_usage > $threshold" | bc -l) )); then
        echo "WARNING: High memory usage detected: ${memory_usage}%"
        get_top_processes
    fi
}

# Function to check if disk usage is high
check_disk_usage() {
    local threshold=80
    local disk_usage=$(get_disk_usage)
    if (( $(echo "$disk_usage > $threshold" | bc -l) )); then
        echo "WARNING: High disk usage detected: ${disk_usage}%"
    fi
}

# Main monitoring loop
echo "Starting system monitoring (Press Ctrl+C to stop)..."
echo "Monitoring interval: $INTERVAL seconds"
echo

while true; do
    clear
    echo "=== System Resource Monitor ==="
    echo "Time: $(date)"
    echo
    
    echo "CPU Usage: $(get_cpu_usage)%"
    echo "Memory Usage: $(get_memory_usage)%"
    echo "Disk Usage: $(get_disk_usage)%"
    echo
    
    echo "=== Top Processes ==="
    get_top_processes
    echo
    
    echo "=== Warnings ==="
    check_cpu_usage
    check_memory_usage
    check_disk_usage
    echo
    
    echo "Next update in $INTERVAL seconds..."
    sleep "$INTERVAL"
done 
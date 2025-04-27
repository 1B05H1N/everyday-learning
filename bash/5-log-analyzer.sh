#!/bin/bash

# Script to analyze log files
# Usage: ./5-log-analyzer.sh [log_file]

# Check if log file is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 [log_file]"
    exit 1
fi

LOG_FILE="$1"

# Check if log file exists
if [ ! -f "$LOG_FILE" ]; then
    echo "Error: Log file '$LOG_FILE' does not exist!"
    exit 1
fi

# Function to count total lines
count_total_lines() {
    wc -l < "$LOG_FILE"
}

# Function to count unique IP addresses
count_unique_ips() {
    grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" "$LOG_FILE" | sort -u | wc -l
}

# Function to count HTTP status codes
count_status_codes() {
    echo "HTTP Status Code Distribution:"
    grep -o "HTTP/[0-9.]* [0-9]*" "$LOG_FILE" | awk '{print $2}' | sort | uniq -c | sort -nr
}

# Function to find most common URLs
find_common_urls() {
    echo "Most Common URLs:"
    grep -o "GET [^ ]*" "$LOG_FILE" | sort | uniq -c | sort -nr | head -n 10
}

# Function to find error messages
find_errors() {
    echo "Error Messages:"
    grep -i "error\|fail\|exception" "$LOG_FILE" | sort | uniq -c | sort -nr
}

# Function to analyze time distribution
analyze_time_distribution() {
    echo "Time Distribution:"
    grep -o "[0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}" "$LOG_FILE" | awk -F: '{print $1":00"}' | sort | uniq -c
}

# Main analysis
echo "=== Log File Analysis ==="
echo "File: $LOG_FILE"
echo "Analysis Time: $(date)"
echo

echo "=== Basic Statistics ==="
echo "Total Lines: $(count_total_lines)"
echo "Unique IP Addresses: $(count_unique_ips)"
echo

echo "=== Status Codes ==="
count_status_codes
echo

echo "=== Common URLs ==="
find_common_urls
echo

echo "=== Errors ==="
find_errors
echo

echo "=== Time Distribution ==="
analyze_time_distribution
echo

echo "=== Analysis Complete ===" 
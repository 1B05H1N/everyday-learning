#!/bin/bash

# SSL Certificate Checker
# This script checks SSL certificates for security issues and expiration

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required commands
for cmd in openssl date bc; do
    if ! command_exists "$cmd"; then
        echo -e "${RED}Error: Required command '$cmd' not found.${NC}"
        exit 1
    fi
done

# Function to check SSL certificate
check_certificate() {
    local host="$1"
    local port="${2:-443}"
    local timeout=10
    
    echo -e "\n=== Checking SSL Certificate for ${GREEN}$host${NC} ==="
    
    # Get certificate information
    cert_info=$(openssl s_client -connect "$host:$port" -servername "$host" </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer -serial)
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Could not retrieve certificate for $host${NC}"
        return 1
    fi
    
    # Extract dates
    not_before=$(echo "$cert_info" | grep "notBefore=" | cut -d'=' -f2)
    not_after=$(echo "$cert_info" | grep "notAfter=" | cut -d'=' -f2)
    
    # Convert dates to timestamps
    not_before_ts=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$not_before" "+%s" 2>/dev/null)
    not_after_ts=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$not_after" "+%s" 2>/dev/null)
    current_ts=$(date "+%s")
    
    # Calculate days until expiration
    days_until_expiry=$(( ($not_after_ts - $current_ts) / 86400 ))
    
    # Check certificate expiration
    echo -e "\nCertificate Validity:"
    echo "-------------------"
    echo "Valid From: $not_before"
    echo "Valid Until: $not_after"
    
    if [ $days_until_expiry -lt 0 ]; then
        echo -e "${RED}Status: EXPIRED${NC}"
    elif [ $days_until_expiry -lt 30 ]; then
        echo -e "${RED}Status: EXPIRING SOON (in $days_until_expiry days)${NC}"
    elif [ $days_until_expiry -lt 90 ]; then
        echo -e "${YELLOW}Status: EXPIRING SOON (in $days_until_expiry days)${NC}"
    else
        echo -e "${GREEN}Status: VALID (expires in $days_until_expiry days)${NC}"
    fi
    
    # Check certificate details
    echo -e "\nCertificate Details:"
    echo "-------------------"
    echo "$cert_info" | grep "subject=" | sed 's/subject=//'
    echo "$cert_info" | grep "issuer=" | sed 's/issuer=//'
    echo "$cert_info" | grep "serial=" | sed 's/serial=//'
    
    # Check for weak SSL/TLS protocols
    echo -e "\nSecurity Checks:"
    echo "----------------"
    
    # Check for SSLv3
    if openssl s_client -connect "$host:$port" -ssl3 </dev/null 2>/dev/null | grep -q "Connected"; then
        echo -e "${RED}WARNING: SSLv3 is supported (INSECURE)${NC}"
    else
        echo -e "${GREEN}SSLv3 is not supported (GOOD)${NC}"
    fi
    
    # Check for TLS 1.0
    if openssl s_client -connect "$host:$port" -tls1 </dev/null 2>/dev/null | grep -q "Connected"; then
        echo -e "${YELLOW}WARNING: TLS 1.0 is supported (WEAK)${NC}"
    else
        echo -e "${GREEN}TLS 1.0 is not supported (GOOD)${NC}"
    fi
    
    # Check for TLS 1.1
    if openssl s_client -connect "$host:$port" -tls1_1 </dev/null 2>/dev/null | grep -q "Connected"; then
        echo -e "${YELLOW}WARNING: TLS 1.1 is supported (WEAK)${NC}"
    else
        echo -e "${GREEN}TLS 1.1 is not supported (GOOD)${NC}"
    fi
    
    # Check for TLS 1.2
    if openssl s_client -connect "$host:$port" -tls1_2 </dev/null 2>/dev/null | grep -q "Connected"; then
        echo -e "${GREEN}TLS 1.2 is supported (GOOD)${NC}"
    else
        echo -e "${RED}WARNING: TLS 1.2 is not supported (WEAK)${NC}"
    fi
    
    # Check for TLS 1.3
    if openssl s_client -connect "$host:$port" -tls1_3 </dev/null 2>/dev/null | grep -q "Connected"; then
        echo -e "${GREEN}TLS 1.3 is supported (EXCELLENT)${NC}"
    else
        echo -e "${YELLOW}TLS 1.3 is not supported (GOOD)${NC}"
    fi
}

# Main script
echo "SSL Certificate Checker"
echo "======================"

# Check if host is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <hostname> [port]"
    echo "Example: $0 example.com 443"
    exit 1
fi

# Check certificate
check_certificate "$1" "$2" 
#!/bin/bash

# Script to create timestamped backups
# Usage: ./3-backup.sh [source_directory] [backup_directory]

# Check if source directory is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 [source_directory] [backup_directory]"
    echo "If backup_directory is not specified, backups will be created in ./backups"
    exit 1
fi

# Set source and backup directories
SOURCE_DIR="$1"
BACKUP_DIR="${2:-./backups}"

# Check if source directory exists
if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: Source directory '$SOURCE_DIR' does not exist!"
    exit 1
fi

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Generate timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Get the base name of the source directory
SOURCE_NAME=$(basename "$SOURCE_DIR")

# Create backup filename
BACKUP_NAME="${SOURCE_NAME}_backup_${TIMESTAMP}.tar.gz"

# Create the backup
echo "Creating backup of $SOURCE_DIR..."
tar -czf "$BACKUP_DIR/$BACKUP_NAME" -C "$(dirname "$SOURCE_DIR")" "$(basename "$SOURCE_DIR")"

# Check if backup was successful
if [ $? -eq 0 ]; then
    echo "Backup created successfully: $BACKUP_NAME"
    echo "Backup size: $(du -h "$BACKUP_DIR/$BACKUP_NAME" | cut -f1)"
else
    echo "Error: Backup failed!"
    exit 1
fi

# List recent backups
echo
echo "Recent backups:"
ls -lh "$BACKUP_DIR" | grep "$SOURCE_NAME" | tail -n 5

# Cleanup old backups (keep last 5)
echo
echo "Cleaning up old backups..."
ls -t "$BACKUP_DIR"/*"$SOURCE_NAME"* | tail -n +6 | xargs -r rm

echo "Backup process completed!" 
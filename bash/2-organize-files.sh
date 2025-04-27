#!/bin/bash

# Script to organize files by extension
# Usage: ./2-organize-files.sh [directory]

# Default to current directory if no argument provided
target_dir="${1:-.}"

# Create directories for different file types
mkdir -p "$target_dir"/{Images,Documents,Music,Videos,Archives,Others}

# Function to move files to appropriate directories
organize_files() {
    local file="$1"
    local ext="${file##*.}"
    ext=$(echo "$ext" | tr '[:upper:]' '[:lower:]')
    
    case "$ext" in
        jpg|jpeg|png|gif|bmp|svg)
            mv "$file" "$target_dir/Images/" 2>/dev/null
            ;;
        pdf|doc|docx|txt|rtf|odt)
            mv "$file" "$target_dir/Documents/" 2>/dev/null
            ;;
        mp3|wav|flac|m4a|aac)
            mv "$file" "$target_dir/Music/" 2>/dev/null
            ;;
        mp4|avi|mkv|mov|wmv)
            mv "$file" "$target_dir/Videos/" 2>/dev/null
            ;;
        zip|rar|7z|tar|gz)
            mv "$file" "$target_dir/Archives/" 2>/dev/null
            ;;
        *)
            # Only move if it's a file (not a directory)
            if [ -f "$file" ]; then
                mv "$file" "$target_dir/Others/" 2>/dev/null
            fi
            ;;
    esac
}

echo "Starting file organization in $target_dir..."
echo "Creating directories..."

# Process all files in the target directory
for file in "$target_dir"/*; do
    if [ -e "$file" ]; then
        organize_files "$file"
    fi
done

echo "File organization complete!"
echo
echo "Directory structure:"
tree "$target_dir" --dirsfirst 
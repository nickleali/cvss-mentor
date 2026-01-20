#!/bin/bash

# Define the base URL and file details
BASE_URL="https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
FILE_EXT=".json.gz"
TARGET_DIR="./data"

# Create the target directory if it doesn't exist
mkdir -p "$TARGET_DIR"

# Loop through the years 2020 to 2026
for year in {2020..2026}
do
    FILENAME="report_${year}${FILE_EXT}"
    FILE_URL="${BASE_URL}${year}${FILE_EXT}"
    
    echo "Fetching $FILENAME..."
    
    # Download the file
    # -L follows redirects; -o specifies the output filename
    curl -L "$FILE_URL" -o "$FILENAME"
    
    # Check if the file was downloaded successfully before moving
    if [ -f "$FILENAME" ]; then
        echo "Moving $FILENAME to $TARGET_DIR/"
        mv "$FILENAME" "$TARGET_DIR/"
    else
        echo "Warning: $FILENAME was not downloaded, skipping move."
    fi
done

echo "Process completed. Files are located in $TARGET_DIR"
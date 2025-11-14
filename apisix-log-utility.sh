#!/usr/bin/env bash
set -euo pipefail
umask 022

# -------- CONFIG --------
LOG_DIR="/var/logs"                          # Directory to monitor for log files
HDFS_BASE_DIR="/user/hdfs/apisix/logs"       # Base HDFS directory
FLUSH_WAIT=5                                 # seconds to let logger flush
BASE_SLEEP=900                               # 15 minutes base sleep (900 seconds)
JITTER_MAX=300                               # add 0..300 sec random jitter (5 min)
LOG_PATTERN="*.log"                          # Pattern to match log files

# Absolute paths
HDFS_BIN="$(command -v hdfs || true)"
: "${HDFS_BIN:?hdfs CLI not found in PATH}"

# -------- PRECHECKS --------
# Ensure log directory exists
if [ ! -d "$LOG_DIR" ]; then
    echo "[$(date -Is)] ERROR: Log directory $LOG_DIR does not exist. Creating it."
    mkdir -p "$LOG_DIR"
fi

# Ensure HDFS base dir exists
$HDFS_BIN dfs -mkdir -p "$HDFS_BASE_DIR" || true
$HDFS_BIN dfs -chmod 755 "$HDFS_BASE_DIR" || true

cleanup() { 
    rm -f /tmp/combined_log_*.log 2>/dev/null || true 
}
trap cleanup EXIT

# Function to discover log files
discover_log_files() {
    local log_files=()
    
    # Find all .log files in the log directory
    while IFS= read -r -d '' file; do
        log_files+=("$file")
    done < <(find "$LOG_DIR" -maxdepth 1 -name "$LOG_PATTERN" -type f -print0 2>/dev/null)
    
    printf '%s\n' "${log_files[@]}"
}

# Function to generate unique filename to prevent overwrites
generate_unique_hdfs_filename() {
    local base_ts="$1"
    local counter=0
    local hdfs_file="${HDFS_BASE_DIR}/combined_${base_ts}.log"
    
    # Check if file already exists, if yes, add counter
    while $HDFS_BIN dfs -test -e "$hdfs_file" 2>/dev/null; do
        counter=$((counter + 1))
        hdfs_file="${HDFS_BASE_DIR}/combined_${base_ts}_${counter}.log"
    done
    
    echo "$hdfs_file"
}

# Function to combine all log files into one
combine_and_process_logs() {
    # Generate base timestamp for this cycle
    local base_ts=$(date -u +%Y%m%dT%H%M%SZ)
    
    # Generate unique HDFS filename to prevent overwrites
    local hdfs_file=$(generate_unique_hdfs_filename "$base_ts")
    local hdfs_tmp="${hdfs_file}.tmp"
    
    local combined_snap="/tmp/combined_log_${base_ts}.log"
    local total_size=0
    local files_with_content=0
    
    # Wait for flush
    sleep "$FLUSH_WAIT"
    
    # Discover log files
    mapfile -t current_log_files < <(discover_log_files)
    
    # Create combined snapshot
    touch "$combined_snap"
    
    # Add header with cycle information
    echo "=== CYCLE_START: $(date -Is), LOG_FILES_FOUND: ${#current_log_files[@]} ===" >> "$combined_snap"
    
    # Process each log file and combine content
    for log_file in "${current_log_files[@]}"; do
        if [ -r "$log_file" ]; then
            local size=$(wc -c < "$log_file" 2>/dev/null || echo 0)
            local log_name=$(basename "$log_file")
            
            if [ $size -gt 0 ]; then
                # File has content
                echo "=== [FILE: $log_name, SIZE: ${size} bytes] ===" >> "$combined_snap"
                cat "$log_file" >> "$combined_snap"
                echo -e "\n" >> "$combined_snap"
                files_with_content=$((files_with_content + 1))
            else
                # File is empty
                echo "=== [FILE: $log_name, STATUS: EMPTY] ===" >> "$combined_snap"
            fi
            
            # Always truncate the source log file (whether empty or not)
            : > "$log_file"
            total_size=$((total_size + size))
            
            echo "[$(date -Is)] Processed $log_name: ${size} bytes"
        else
            echo "[$(date -Is)] ERROR: Cannot read log file $log_file"
        fi
    done
    
    # Add footer with summary
    echo "=== CYCLE_END: $(date -Is), TOTAL_SIZE: ${total_size} bytes, FILES_WITH_CONTENT: ${files_with_content} ===" >> "$combined_snap"
    
    # ALWAYS upload to HDFS, even if empty
    echo "[$(date -Is)] Uploading to HDFS: ${total_size} bytes from ${files_with_content} files with content"
    
    if $HDFS_BIN dfs -put "$combined_snap" "$hdfs_tmp" && $HDFS_BIN dfs -mv "$hdfs_tmp" "$hdfs_file"; then
        $HDFS_BIN dfs -chmod 644 "$hdfs_file" || true
        echo "[$(date -Is)] SUCCESS: Created hdfs://$hdfs_file (${total_size} bytes)"
        rm -f "$combined_snap"
        return 0
    else
        echo "[$(date -Is)] ERROR: HDFS upload failed; snapshot kept at $combined_snap"
        return 1
    fi
}

echo "[$(date -Is)] starting 15-minute combined log copy loop for log files in: $LOG_DIR"
echo "[$(date -Is)] Configuration: Check every $((BASE_SLEEP/60)) minutes + up to $((JITTER_MAX/60)) minutes jitter"

while true; do
    cycle_start=$(date +%s)
    echo "[$(date -Is)] === Starting new cycle ==="
    
    # Discover log files
    mapfile -t current_log_files < <(discover_log_files)
    
    if [ ${#current_log_files[@]} -eq 0 ]; then
        echo "[$(date -Is)] WARNING: No log files found in $LOG_DIR matching pattern $LOG_PATTERN"
    else
        echo "[$(date -Is)] Found ${#current_log_files[@]} log files to combine"
    fi
    
    # Process all logs combined - THIS WILL NOW ALWAYS CREATE HDFS FILE
    if combine_and_process_logs; then
        echo "[$(date -Is)] Combined processing completed successfully"
    else
        echo "[$(date -Is)] Combined processing encountered errors"
    fi
    
    echo "[$(date -Is)] === Cycle completed ==="
    
    # Calculate dynamic sleep to maintain ~15 minute intervals
    cycle_end=$(date +%s)
    cycle_duration=$((cycle_end - cycle_start))
    total_sleep=$((BASE_SLEEP + (RANDOM % (JITTER_MAX + 1))))
    
    # Adjust sleep time based on how long the cycle took
    if [ $cycle_duration -lt $total_sleep ]; then
        actual_sleep=$((total_sleep - cycle_duration))
        echo "[$(date -Is)] next cycle in $((actual_sleep/60)) minutes, $((actual_sleep%60)) seconds"
        sleep $actual_sleep
    else
        echo "[$(date -Is)] cycle took longer than sleep interval, starting immediately"
    fi
done

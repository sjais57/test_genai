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

# Function to check if file has non-empty content (excluding whitespace)
has_content() {
    local file="$1"
    if [ -s "$file" ] && [ -n "$(tr -d '[:space:]' < "$file" 2>/dev/null)" ]; then
        return 0  # has content
    else
        return 1  # empty or only whitespace
    fi
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
    local has_content_flag=0
    local total_size=0
    
    # Wait for flush
    sleep "$FLUSH_WAIT"
    
    # Discover log files
    mapfile -t current_log_files < <(discover_log_files)
    
    # Create combined snapshot
    touch "$combined_snap"
    
    # Process each log file and combine content
    for log_file in "${current_log_files[@]}"; do
        if [ -r "$log_file" ] && has_content "$log_file"; then
            local size=$(wc -c < "$log_file" 2>/dev/null || echo 0)
            local log_name=$(basename "$log_file")
            
            # Add separator with log file name and timestamp
            echo "=== [FILE: $log_name, TIMESTAMP: $(date -Is), SIZE: ${size} bytes] ===" >> "$combined_snap"
            
            # Append the actual log content
            cat "$log_file" >> "$combined_snap"
            
            # Add newline separator between files
            echo -e "\n" >> "$combined_snap"
            
            # Truncate the source log file
            : > "$log_file"
            
            total_size=$((total_size + size))
            has_content_flag=1
            
            echo "[$(date -Is)] Added $log_name: ${size} bytes"
        else
            echo "[$(date -Is)] $log_file: no content, skipping"
            # Still truncate empty files to clean any whitespace
            : > "$log_file" 2>/dev/null || true
        fi
    done
    
    if [ $has_content_flag -eq 1 ]; then
        # Upload combined file to HDFS
        echo "[$(date -Is)] Combined total: ${total_size} bytes from ${#current_log_files[@]} files"
        
        # Use simple put without overwrite protection (it will fail if file exists, but our unique naming prevents this)
        if $HDFS_BIN dfs -put "$combined_snap" "$hdfs_tmp" && $HDFS_BIN dfs -mv "$hdfs_tmp" "$hdfs_file"; then
            $HDFS_BIN dfs -chmod 644 "$hdfs_file" || true
            echo "[$(date -Is)] Shipped combined logs to hdfs://$hdfs_file (${total_size} bytes)"
            rm -f "$combined_snap"
            return 0
        else
            echo "[$(date -Is)] ERROR: HDFS upload failed for combined logs; snapshot kept at $combined_snap"
            return 1
        fi
    else
        # No content in any files
        echo "[$(date -Is)] No content in any log files, skipping HDFS upload"
        rm -f "$combined_snap"
        return 0
    fi
}

# Function to create cycle marker
create_cycle_marker() {
    local ts=$(date -u +%Y%m%dT%H%M%SZ)
    local marker_file="${HDFS_BASE_DIR}/.cycle_${ts}.marker"
    
    echo "cycle_completed: $ts, files_processed: $1" > /tmp/cycle_marker.txt
    if $HDFS_BIN dfs -put /tmp/cycle_marker.txt "$marker_file" 2>/dev/null; then
        echo "[$(date -Is)] Cycle marker created: hdfs://$marker_file"
        rm -f /tmp/cycle_marker.txt
    else
        echo "[$(date -Is)] WARNING: Could not create cycle marker"
        rm -f /tmp/cycle_marker.txt
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
    
    # Process all logs combined
    if combine_and_process_logs; then
        echo "[$(date -Is)] Combined processing completed successfully"
    else
        echo "[$(date -Is)] Combined processing encountered errors"
    fi
    
    # Create cycle marker in HDFS
    create_cycle_marker "${#current_log_files[@]}"
    
    echo "[$(date -Is)] === Cycle completed: ${#current_log_files[@]} files processed ==="
    
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

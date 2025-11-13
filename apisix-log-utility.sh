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
    rm -f /tmp/hdfs_log_*.log 2>/dev/null || true 
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

# Function to process a single log file
process_log_file() {
    local local_file="$1"
    local log_name=$(basename "$local_file" .log)
    local hdfs_dir="${HDFS_BASE_DIR}/${log_name}"
    
    # Create HDFS directory for this specific log
    $HDFS_BIN dfs -mkdir -p "$hdfs_dir" || true
    $HDFS_BIN dfs -chmod 755 "$hdfs_dir" || true
    
    # Wait for flush
    sleep "$FLUSH_WAIT"
    
    # Generate timestamp for this cycle
    local ts=$(date -u +%Y%m%dT%H%M%SZ)
    local snap="/tmp/hdfs_log_${log_name}_${ts}.log"
    local hdfs_tmp="${hdfs_dir}/.${log_name}_${ts}.log.tmp"
    local hdfs_file="${hdfs_dir}/${log_name}_${ts}.log"
    
    if has_content "$local_file"; then
        # File has content - copy and truncate
        local size=$(wc -c < "$local_file" 2>/dev/null || echo 0)
        
        if cp -f "$local_file" "$snap"; then
            : > "$local_file"   # truncate local log
            echo "[$(date -Is)] $log_name: ${size} bytes to process"
        else
            echo "[$(date -Is)] ERROR: cp failed from $local_file to $snap"
            return 1
        fi

        # Upload to HDFS
        if $HDFS_BIN dfs -put -f "$snap" "$hdfs_tmp" && $HDFS_BIN dfs -mv "$hdfs_tmp" "$hdfs_file"; then
            $HDFS_BIN dfs -chmod 644 "$hdfs_file" || true
            echo "[$(date -Is)] $log_name: shipped to hdfs://$hdfs_file (${size} bytes)"
            rm -f "$snap"
            return 0
        else
            echo "[$(date -Is)] ERROR: HDFS upload failed for $log_name; snapshot kept at $snap"
            return 1
        fi
    else
        # File is empty or has only whitespace - skip HDFS creation
        echo "[$(date -Is)] $log_name: no content (empty or whitespace only), skipping HDFS upload"
        # Still truncate the local file to clean any whitespace
        : > "$local_file"
        return 0
    fi
}

# Function to check if we should create a marker for this cycle
create_cycle_marker() {
    local ts=$(date -u +%Y%m%dT%H%M%SZ)
    local marker_file="${HDFS_BASE_DIR}/.cycle_${ts}.marker"
    local marker_tmp="${HDFS_BASE_DIR}/.cycle_${ts}.marker.tmp"
    
    echo "cycle_completed: $ts" > /tmp/cycle_marker.txt
    if $HDFS_BIN dfs -put -f /tmp/cycle_marker.txt "$marker_tmp" && $HDFS_BIN dfs -mv "$marker_tmp" "$marker_file" 2>/dev/null; then
        echo "[$(date -Is)] Cycle marker created: hdfs://$marker_file"
        rm -f /tmp/cycle_marker.txt
    else
        echo "[$(date -Is)] WARNING: Could not create cycle marker"
        rm -f /tmp/cycle_marker.txt
    fi
}

echo "[$(date -Is)] starting 15-minute log copy loop for log files in: $LOG_DIR"
echo "[$(date -Is)] Configuration: Check every $((BASE_SLEEP/60)) minutes + up to $((JITTER_MAX/60)) minutes jitter"

while true; do
    cycle_start=$(date +%s)
    echo "[$(date -Is)] === Starting new cycle ==="
    
    # Discover log files dynamically
    mapfile -t current_log_files < <(discover_log_files)
    
    if [ ${#current_log_files[@]} -eq 0 ]; then
        echo "[$(date -Is)] WARNING: No log files found in $LOG_DIR matching pattern $LOG_PATTERN"
    else
        echo "[$(date -Is)] Found ${#current_log_files[@]} log files:"
        printf '[$(date -Is)]   - %s\n' "${current_log_files[@]}"
    fi
    
    processed_count=0
    skipped_count=0
    error_count=0
    
    # Process each discovered log file
    for log_file in "${current_log_files[@]}"; do
        if [ -r "$log_file" ]; then
            if process_log_file "$log_file"; then
                # Check if the file had content before processing
                if has_content "/tmp/hdfs_log_$(basename "$log_file" .log)_*.log" 2>/dev/null; then
                    processed_count=$((processed_count + 1))
                else
                    skipped_count=$((skipped_count + 1))
                fi
            else
                error_count=$((error_count + 1))
            fi
        else
            echo "[$(date -Is)] ERROR: Cannot read log file $log_file"
            error_count=$((error_count + 1))
        fi
        sleep 1  # Small gap between processing different log files
    done
    
    # Create cycle marker in HDFS
    create_cycle_marker
    
    echo "[$(date -Is)] === Cycle completed: ${#current_log_files[@]} files found, $processed_count processed, $skipped_count skipped, $error_count errors ==="
    
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

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
KERBEROS_KEYTAB="/path/to/user.keytab"       # Keytab path - UPDATE THIS
KERBEROS_PRINCIPAL="user@REALM.COM"          # Principal - UPDATE THIS

# Absolute paths
HDFS_BIN="$(command -v hdfs || true)"
KINIT_BIN="$(command -v kinit || true)"
KLIST_BIN="$(command -v klist || true)"
: "${HDFS_BIN:?hdfs CLI not found in PATH}"

# -------- KERBEROS FUNCTIONS --------
check_kerberos_ticket() {
    if $KLIST_BIN -s 2>/dev/null; then
        echo "[$(date -Is)] Kerberos TGT is valid"
        return 0
    else
        echo "[$(date -Is)] Kerberos TGT is expired or not found"
        return 1
    fi
}

renew_kerberos_ticket() {
    echo "[$(date -Is)] Renewing Kerberos TGT..."
    if [[ -f "$KERBEROS_KEYTAB" ]]; then
        if $KINIT_BIN -kt "$KERBEROS_KEYTAB" "$KERBEROS_PRINCIPAL"; then
            echo "[$(date -Is)] Successfully renewed TGT using keytab"
            return 0
        else
            echo "[$(date -Is)] ERROR: Failed to renew TGT using keytab"
            return 1
        fi
    else
        echo "[$(date -Is)] ERROR: Keytab not found at $KERBEROS_KEYTAB"
        return 1
    fi
}

ensure_kerberos_ticket() {
    if ! check_kerberos_ticket; then
        renew_kerberos_ticket
    fi
}

# -------- PRECHECKS --------
# Ensure log directory exists
if [ ! -d "$LOG_DIR" ]; then
    echo "[$(date -Is)] ERROR: Log directory $LOG_DIR does not exist. Creating it."
    mkdir -p "$LOG_DIR"
    chmod 755 "$LOG_DIR"
fi

# Initial Kerberos authentication
ensure_kerberos_ticket

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
    if [ -d "$LOG_DIR" ]; then
        while IFS= read -r -d '' file; do
            log_files+=("$file")
        done < <(find "$LOG_DIR" -maxdepth 1 -name "$LOG_PATTERN" -type f -print0 2>/dev/null)
    fi
    
    printf '%s\n' "${log_files[@]}"
}

# Function to combine all log files into one
combine_and_process_logs() {
    # Generate base timestamp for this cycle
    local base_ts=$(date -u +%Y%m%dT%H%M%SZ)
    local hdfs_file="${HDFS_BASE_DIR}/combined_${base_ts}.log"
    local hdfs_tmp="${hdfs_file}.tmp"
    local combined_snap="/tmp/combined_log_${base_ts}.log"
    
    local total_size=0
    local files_with_content=0
    
    echo "[$(date -Is)] Starting log processing cycle $base_ts"
    
    # Wait for flush
    sleep "$FLUSH_WAIT"
    
    # Discover log files
    mapfile -t current_log_files < <(discover_log_files)
    
    # Create fresh combined snapshot file
    > "$combined_snap"
    
    # Add header with cycle information
    echo "=== CYCLE_START: $(date -Is), LOG_FILES_FOUND: ${#current_log_files[@]} ===" >> "$combined_snap"
    
    # Process each log file
    for log_file in "${current_log_files[@]}"; do
        if [ -r "$log_file" ] && [ -f "$log_file" ]; then
            local size=0
            size=$(wc -c < "$log_file" 2>/dev/null || echo 0)
            local log_name=$(basename "$log_file")
            
            if [ "$size" -gt 0 ]; then
                # File has content
                echo "=== [FILE: $log_name, SIZE: ${size} bytes] ===" >> "$combined_snap"
                cat "$log_file" >> "$combined_snap" 2>/dev/null || echo "ERROR: Failed to read $log_name" >> "$combined_snap"
                echo "" >> "$combined_snap"  # Add newline separator
                files_with_content=$((files_with_content + 1))
                echo "[$(date -Is)] Added content from $log_name: ${size} bytes"
            else
                # File is empty
                echo "=== [FILE: $log_name, STATUS: EMPTY] ===" >> "$combined_snap"
                echo "[$(date -Is)] $log_name: empty, no content to add"
            fi
            
            # Always truncate the source log file
            > "$log_file" 2>/dev/null || echo "[$(date -Is)] WARNING: Could not truncate $log_file"
            total_size=$((total_size + size))
            
        else
            echo "[$(date -Is)] ERROR: Cannot read log file $log_file"
            echo "=== [FILE: $(basename "$log_file" 2>/dev/null || echo "unknown"), STATUS: UNREADABLE] ===" >> "$combined_snap"
        fi
    done
    
    # Add footer with summary
    echo "=== CYCLE_END: $(date -Is), TOTAL_SIZE: ${total_size} bytes, FILES_WITH_CONTENT: ${files_with_content}/${#current_log_files[@]} ===" >> "$combined_snap"
    
    # ALWAYS upload to HDFS, even if all files were empty
    echo "[$(date -Is)] Uploading to HDFS: ${total_size} bytes from ${files_with_content} files with content"
    
    # Check if the snapshot file exists and has some content (at least headers)
    if [ -f "$combined_snap" ]; then
        local final_size=$(wc -c < "$combined_snap" 2>/dev/null || echo 0)
        echo "[$(date -Is)] Combined file size: ${final_size} bytes"
        
        if $HDFS_BIN dfs -put "$combined_snap" "$hdfs_tmp" 2>/dev/null; then
            if $HDFS_BIN dfs -mv "$hdfs_tmp" "$hdfs_file" 2>/dev/null; then
                $HDFS_BIN dfs -chmod 644 "$hdfs_file" 2>/dev/null || true
                echo "[$(date -Is)] SUCCESS: Created hdfs://$hdfs_file"
                rm -f "$combined_snap"
                return 0
            else
                echo "[$(date -Is)] ERROR: Failed to rename temporary HDFS file"
                $HDFS_BIN dfs -rm "$hdfs_tmp" 2>/dev/null || true
                return 1
            fi
        else
            echo "[$(date -Is)] ERROR: HDFS upload failed"
            return 1
        fi
    else
        echo "[$(date -Is)] ERROR: Combined snapshot file was not created"
        return 1
    fi
}

echo "[$(date -Is)] Starting 15-minute log copy loop for directory: $LOG_DIR"
echo "[$(date -Is)] Configuration: Check every $((BASE_SLEEP/60)) minutes"

while true; do
    cycle_start=$(date +%s)
    echo "[$(date -Is)] === Starting new processing cycle ==="
    
    # Check Kerberos ticket before each cycle
    ensure_kerberos_ticket
    
    # Process all logs
    if combine_and_process_logs; then
        echo "[$(date -Is)] Cycle completed successfully"
    else
        echo "[$(date -Is)] Cycle completed with errors"
    fi
    
    # Calculate sleep time
    cycle_end=$(date +%s)
    cycle_duration=$((cycle_end - cycle_start))
    total_sleep=$((BASE_SLEEP + (RANDOM % (JITTER_MAX + 1))))
    
    # Adjust sleep time based on cycle duration
    if [ $cycle_duration -lt $total_sleep ]; then
        actual_sleep=$((total_sleep - cycle_duration))
        echo "[$(date -Is)] Next cycle in $((actual_sleep / 60)) minutes, $((actual_sleep % 60)) seconds"
        sleep $actual_sleep
    else
        echo "[$(date -Is)] Cycle took longer than interval, starting next cycle immediately"
    fi
done

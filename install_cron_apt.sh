#!/bin/bash

# cron-apt - Enhanced Installation script for Automatic Update System
# Created by Krishnendu Paul (@bidhata)
# Repository: https://github.com/bidhata/cron-apt
# Run this script as root to set up automatic weekly updates

set -euo pipefail

# Version and metadata
readonly SCRIPT_VERSION="2.2.0"
readonly SCRIPT_NAME="cron-apt"
readonly GITHUB_REPO="bidhata/cron-apt"
readonly MIN_DISK_SPACE_MB=100
readonly MIN_BOOT_DISK_SPACE_MB=50
readonly MIN_VAR_DISK_SPACE_MB=200
readonly SUPPORTED_DISTRIBUTIONS=("ubuntu" "debian" "kali" "mint" "pop")

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Global variables
DRY_RUN=false
UNINSTALL=false
LOG_LEVEL=1 # 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR
AUTO_REBOOT_SETTING="false"
UPDATE_FREQUENCY="weekly"
EMAIL_RECIPIENT=""

# Logging function with levels
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Map levels to numeric values
    local level_num=1
    case "$level" in
        "DEBUG") level_num=0 ;;
        "INFO")  level_num=1 ;;
        "WARN")  level_num=2 ;;
        "ERROR") level_num=3 ;;
    esac
    
    # Only log if level is >= configured log level
    if [[ $level_num -ge $LOG_LEVEL ]]; then
        case "$level" in
            "INFO")  echo -e "${GREEN}[INFO]${NC}  [$timestamp] $message" ;;
            "WARN")  echo -e "${YELLOW}[WARN]${NC}  [$timestamp] $message" ;;
            "ERROR") echo -e "${RED}[ERROR]${NC} [$timestamp] $message" ;;
            "DEBUG") echo -e "${CYAN}[DEBUG]${NC} [$timestamp] $message" ;;
        esac
    fi
}

# Set log level from command line or environment
set_log_level() {
    local level="${1:-INFO}"
    case "$level" in
        "DEBUG") LOG_LEVEL=0 ;;
        "INFO")  LOG_LEVEL=1 ;;
        "WARN")  LOG_LEVEL=2 ;;
        "ERROR") LOG_LEVEL=3 ;;
        *)       LOG_LEVEL=1 ;;
    esac
}

# Function to check internet connectivity
check_internet_connectivity() {
    log "INFO" "Checking internet connectivity..."
    
    if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1 && ! ping -c 1 -W 5 google.com >/dev/null 2>&1; then
        log "WARN" "No internet connectivity detected. Some features may not work properly."
        log "WARN" "Please ensure your system has internet access for full functionality."
        return 1
    fi
    
    log "INFO" "Internet connectivity confirmed"
    return 0
}

# Enhanced disk space check for multiple partitions
check_disk_space() {
    log "INFO" "Checking available disk space..."
    
    # Check root partition
    local available_mb
    available_mb=$(df / --output=avail --block-size=1M | tail -n1 | tr -d ' ')
    
    if [[ $available_mb -lt $MIN_DISK_SPACE_MB ]]; then
        log "ERROR" "Insufficient disk space on root partition. Required: ${MIN_DISK_SPACE_MB}MB, Available: ${available_mb}MB"
        exit 1
    fi
    
    log "INFO" "Root partition disk space: ${available_mb}MB (OK)"
    
    # Check /boot partition if it exists
    if df /boot >/dev/null 2>&1; then
        local boot_available_mb
        boot_available_mb=$(df /boot --output=avail --block-size=1M | tail -n1 | tr -d ' ')
        
        if [[ $boot_available_mb -lt $MIN_BOOT_DISK_SPACE_MB ]]; then
            log "WARN" "Low disk space on /boot partition. Recommended: ${MIN_BOOT_DISK_SPACE_MB}MB, Available: ${boot_available_mb}MB"
            log "WARN" "Kernel updates may fail due to insufficient space in /boot"
        else
            log "INFO" "/boot partition disk space: ${boot_available_mb}MB (OK)"
        fi
    fi
    
    # Check /var partition if it exists
    if df /var >/dev/null 2>&1; then
        local var_available_mb
        var_available_mb=$(df /var --output=avail --block-size=1M | tail -n1 | tr -d ' ')
        
        if [[ $var_available_mb -lt $MIN_VAR_DISK_SPACE_MB ]]; then
            log "WARN" "Low disk space on /var partition. Recommended: ${MIN_VAR_DISK_SPACE_MB}MB, Available: ${var_available_mb}MB"
            log "WARN" "Package management operations may be affected"
        else
            log "INFO" "/var partition disk space: ${var_available_mb}MB (OK)"
        fi
    fi
}

# Enhanced system compatibility check
check_system_compatibility() {
    log "INFO" "Checking system compatibility..."
    
    # Check if systemd is available
    if ! command -v systemctl >/dev/null 2>&1; then
        log "ERROR" "systemd is required but not found on this system."
        log "ERROR" "cron-apt requires systemd for service management."
        exit 1
    fi
    
    # Check if apt is available
    if ! command -v apt-get >/dev/null 2>&1; then
        log "ERROR" "apt package manager is required but not found."
        log "ERROR" "cron-apt is designed for Ubuntu/Debian/Kali systems with apt."
        exit 1
    fi
    
    # Check for required commands
    local required_commands=("systemctl" "apt-get" "cron" "logrotate")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log "WARN" "Command '$cmd' not found but may be installed later"
        fi
    done
    
    # Check distribution with expanded support
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        log "INFO" "Detected system: $PRETTY_NAME"
        
        local supported=false
        for dist in "${SUPPORTED_DISTRIBUTIONS[@]}"; do
            if [[ "$ID" == "$dist" ]]; then
                supported=true
                break
            fi
        done
        
        if [[ "$supported" == true ]]; then
            log "INFO" "✓ Compatible distribution detected"
            if [[ "$ID" == "kali" ]]; then
                log "INFO" "  Kali Linux specific optimizations will be applied"
            fi
        else
            log "WARN" "Untested distribution ($ID). cron-apt is designed for ${SUPPORTED_DISTRIBUTIONS[*]}."
            log "WARN" "Continue at your own risk."
            read -p "Do you want to continue? [y/N]: " -n 1 -r
            echo ""
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 0
            fi
        fi
    else
        log "WARN" "Cannot detect distribution. Proceeding with installation..."
    fi
    
    # Check kernel version for security features
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1-2)
    log "INFO" "Kernel version: $kernel_version"
    
    # Check kernel version compatibility
    check_kernel_version
    
    echo ""
}

# Kernel version compatibility check
check_kernel_version() {
    local min_kernel="3.10"
    local current_kernel=$(uname -r | cut -d. -f1-2)
    
    if (( $(echo "$current_kernel < $min_kernel" | bc -l) )); then
        log "WARN" "Kernel version $current_kernel is older than recommended $min_kernel"
        log "WARN" "Some security features may not be available"
    fi
}

# Enhanced privilege check with more detailed feedback
check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This installation script must be run as root or with sudo privileges!"
        echo ""
        log "INFO" "The installer needs root access to:"
        echo "  • Create system files in /usr/local/bin and /etc"
        echo "  • Install required packages (needrestart, mailutils)"
        echo "  • Configure systemd services and timers"
        echo "  • Set up log rotation and permissions"
        echo "  • Modify system security settings"
        echo ""
        log "INFO" "Please run with:"
        echo "  sudo bash $0"
        echo "  or"
        echo "  curl -fsSL https://raw.githubusercontent.com/$GITHUB_REPO/main/install_cron_apt.sh | sudo bash"
        echo ""
        exit 1
    fi
    
    # Show execution context
    if [[ -n "${SUDO_USER:-}" ]]; then
        log "INFO" "Running installation as root via sudo (original user: $SUDO_USER)"
        # Validate that SUDO_USER exists
        if ! getent passwd "$SUDO_USER" >/dev/null 2>&1; then
            log "WARN" "SUDO_USER '$SUDO_USER' not found in passwd database"
        fi
    else
        log "INFO" "Running installation as root user"
    fi
    echo ""
}

# Enhanced auto-reboot preference with validation
ask_auto_reboot_preference() {
    echo -e "${BLUE}AUTO-REBOOT CONFIGURATION${NC}"
    echo "========================="
    echo ""
    echo "Some system updates require a reboot to take effect (kernel updates, etc.)."
    echo "You can configure cron-apt to automatically reboot the system when needed."
    echo ""
    echo -e "${RED}WARNING: Auto-reboot will restart your server automatically without manual intervention!${NC}"
    echo ""
    echo "Options:"
    echo "  Y. Enable auto-reboot (recommended for development/testing servers)"
    echo "  N. Disable auto-reboot (recommended for production servers)"
    echo ""
    echo "You can always change this later by editing /etc/cron-apt/config"
    echo ""
    
    while true; do
        read -p "Enable automatic reboot when required? [Y/n]: " -n 1 -r
        echo ""
        # Clear the input buffer
        while read -r -t 0; do read -r; done
        echo ""
        
        case $REPLY in
            [Yy]|"")
                AUTO_REBOOT_SETTING="true"
                log "INFO" "✓ Auto-reboot ENABLED"
                echo "  The system will automatically reboot when updates require it."
                break
                ;;
            [Nn])
                AUTO_REBOOT_SETTING="false"
                log "INFO" "✓ Auto-reboot DISABLED"
                echo "  The system will send notifications but won't reboot automatically."
                break
                ;;
            *)
                log "WARN" "Please answer Y (yes) or N (no)."
                ;;
        esac
    done
    echo ""
}

# Ask for email notification preference
ask_email_preference() {
    echo -e "${BLUE}EMAIL NOTIFICATION CONFIGURATION${NC}"
    echo "===================================="
    echo ""
    echo "cron-apt can send email notifications after updates complete or if issues occur."
    echo "You'll need to have a working mail system configured on your server."
    echo ""
    echo "Enter an email address to receive notifications, or leave blank to disable:"
    echo ""
    
    read -p "Email address (leave blank to disable): " EMAIL_RECIPIENT
    echo ""
    
    if [[ -n "$EMAIL_RECIPIENT" ]]; then
        # Basic email validation
        if [[ "$EMAIL_RECIPIENT" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            log "INFO" "✓ Email notifications enabled for: $EMAIL_RECIPIENT"
        else
            log "WARN" "Email format appears invalid. Notifications may not work."
            log "INFO" "You can manually configure email in /etc/cron-apt/config later"
        fi
    else
        log "INFO" "✓ Email notifications DISABLED"
    fi
    echo ""
}

# Ask for update frequency
ask_update_frequency() {
    echo -e "${BLUE}UPDATE FREQUENCY CONFIGURATION${NC}"
    echo "================================"
    echo ""
    echo "How often should cron-apt check for and apply updates?"
    echo ""
    echo "Options:"
    echo "  1. Daily (recommended for security-critical systems)"
    echo "  2. Weekly (default - good balance between security and stability)"
    echo "  3. Monthly (for stable systems with less frequent updates)"
    echo ""
    
    while true; do
        read -p "Select update frequency [1-3, default 2]: " -n 1 -r
        echo ""
        
        case $REPLY in
            "1")
                UPDATE_FREQUENCY="daily"
                log "INFO" "✓ Daily updates selected"
                break
                ;;
            "2"|"")
                UPDATE_FREQUENCY="weekly"
                log "INFO" "✓ Weekly updates selected"
                break
                ;;
            "3")
                UPDATE_FREQUENCY="monthly"
                log "INFO" "✓ Monthly updates selected"
                break
                ;;
            *)
                log "WARN" "Please select 1, 2, or 3."
                ;;
        esac
    done
    echo ""
}

# Enhanced installation check with better status reporting
check_existing_installation() {
    local already_installed=false
    local installed_files=()
    local config_backup_created=false
    
    # Check for main script
    if [[ -f "/usr/local/bin/cron-apt" ]]; then
        already_installed=true
        installed_files+=("/usr/local/bin/cron-apt")
    fi
    
    # Check for systemd service files
    if [[ -f "/etc/systemd/system/cron-apt.service" ]]; then
        already_installed=true
        installed_files+=("/etc/systemd/system/cron-apt.service")
    fi
    
    if [[ -f "/etc/systemd/system/cron-apt.timer" ]]; then
        already_installed=true
        installed_files+=("/etc/systemd/system/cron-apt.timer")
    fi
    
    # Check for configuration
    if [[ -f "/etc/cron-apt/config" ]]; then
        already_installed=true
        installed_files+=("/etc/cron-apt/config")
    fi
    
    # Check if timer is enabled
    local timer_enabled=false
    local timer_active=false
    if systemctl is-enabled cron-apt.timer >/dev/null 2>&1; then
        timer_enabled=true
    fi
    if systemctl is-active cron-apt.timer >/dev/null 2>&1; then
        timer_active=true
    fi
    
    if [[ "$already_installed" == true ]]; then
        log "WARN" "cron-apt appears to be already installed!"
        echo ""
        echo "Found existing files:"
        for file in "${installed_files[@]}"; do
            echo "  • $file"
        done
        echo ""
        
        if [[ "$timer_enabled" == true ]]; then
            if [[ "$timer_active" == true ]]; then
                log "INFO" "Status: cron-apt timer is currently ENABLED and ACTIVE"
            else
                log "WARN" "Status: cron-apt timer is ENABLED but INACTIVE"
            fi
            systemctl list-timers cron-apt.timer --no-pager 2>/dev/null || true
        else
            log "WARN" "Status: cron-apt timer is currently DISABLED"
        fi
        echo ""
        
        # Show current log if exists
        if [[ -f "/var/log/cron-apt.log" ]]; then
            echo "Recent log entries:"
            tail -5 /var/log/cron-apt.log 2>/dev/null | sed 's/^/  | /' || true
            echo ""
        fi
        
        echo "Options:"
        echo "  1. Continue installation (will overwrite existing files)"
        echo "  2. Exit and keep current installation"
        echo "  3. Backup current configuration first"
        echo ""
        read -p "Select option [1-3, default 1]: " -n 1 -r
        echo ""
        
        case $REPLY in
            "2")
                log "INFO" "Installation cancelled. Your existing cron-apt installation remains unchanged."
                echo ""
                echo "To manage your current installation:"
                echo "  • View status: systemctl status cron-apt.timer"
                echo "  • View logs: tail -f /var/log/cron-apt.log"
                echo "  • Run manually: sudo /usr/local/bin/cron-apt"
                echo ""
                exit 0
                ;;
            "3")
                backup_existing_config
                log "INFO" "Proceeding with reinstallation..."
                ;;
            *)
                log "INFO" "Proceeding with reinstallation..."
                ;;
        esac
        
        log "INFO" "Stopping existing services..."
        
        # Stop existing services gracefully
        if systemctl is-active --quiet cron-apt.timer 2>/dev/null; then
            systemctl stop cron-apt.timer
            log "INFO" "  • Stopped cron-apt.timer"
        fi
        
        if systemctl is-active --quiet cron-apt.service 2>/dev/null; then
            systemctl stop cron-apt.service
            log "INFO" "  • Stopped cron-apt.service"
        fi
        
        echo ""
    fi
}

# Backup existing configuration
backup_existing_config() {
    local backup_dir="/etc/cron-apt/backup/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    log "INFO" "Backing up existing configuration to $backup_dir"
    
    # Backup files
    local files_to_backup=(
        "/usr/local/bin/cron-apt"
        "/etc/systemd/system/cron-apt.service"
        "/etc/systemd/system/cron-apt.timer"
        "/etc/cron-apt/config"
        "/var/lib/cron-apt/status"
        "/var/lib/cron-apt/metrics"
    )
    
    for file in "${files_to_backup[@]}"; do
        if [[ -f "$file" ]]; then
            cp "$file" "$backup_dir/" 2>/dev/null && log "INFO" "  • Backed up $file" || log "WARN" "  • Failed to backup $file"
        fi
    done
    
    # Create a restore script
    cat > "$backup_dir/restore.sh" << 'EOF'
#!/bin/bash
# cron-apt configuration restore script
# Created on $(date)

set -e

echo "Restoring cron-apt configuration from backup..."
cp -f cron-apt.service /etc/systemd/system/ 2>/dev/null || echo "Warning: Failed to restore service file"
cp -f cron-apt.timer /etc/systemd/system/ 2>/dev/null || echo "Warning: Failed to restore timer file"
cp -f cron-apt /usr/local/bin/ 2>/dev/null || echo "Warning: Failed to restore main script"
cp -f config /etc/cron-apt/ 2>/dev/null || echo "Warning: Failed to restore config"
cp -f status /var/lib/cron-apt/ 2>/dev/null || echo "Warning: Failed to restore status"
cp -f metrics /var/lib/cron-apt/ 2>/dev/null || echo "Warning: Failed to restore metrics"

echo "Reloading systemd..."
systemctl daemon-reload

echo "Restore completed. You may need to restart services manually."
EOF
    
    chmod +x "$backup_dir/restore.sh"
    log "INFO" "Backup completed. To restore, run: $backup_dir/restore.sh"
}

# Function to create enhanced main script with additional features
create_main_script() {
    log "INFO" "Creating enhanced cron-apt script..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "Dry run: Would create /usr/local/bin/cron-apt"
        return 0
    fi
    
cat > /usr/local/bin/cron-apt << 'EOF'
#!/bin/bash

# cron-apt - Enhanced Automatic Update System for Ubuntu/Debian/Kali Linux Servers
# This script automatically updates the system weekly and restarts services as needed
# Created and Maintained by Krishnendu Paul (@bidhata)
# Repository: https://github.com/bidhata/cron-apt

set -euo pipefail

# VersionV
readonly SCRIPT_VERSION="2.2.1"

# Security: Set secure PATH to prevent hijacking
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Security: Set secure umask
umask 077

# Configuration - Use absolute paths for security
readonly LOG_FILE="/var/log/cron-apt.log"
readonly LOCK_FILE="/var/run/cron-apt.lock"
readonly REBOOT_REQUIRED_FILE="/var/run/reboot-required"
readonly CONFIG_FILE="/etc/cron-apt/config"
readonly STATUS_FILE="/var/lib/cron-apt/status"
readonly METRICS_FILE="/var/lib/cron-apt/metrics"

# Default configuration
EMAIL_RECIPIENT=""
MAX_LOG_SIZE="10M"
AUTO_REBOOT="false"
CUSTOM_SERVICES=""
EXCLUDE_PACKAGES=""
VERBOSE_LOGGING="false"
UPDATE_TIMEOUT="3600"
PRE_UPDATE_HOOK=""
POST_UPDATE_HOOK=""

# Create required directories
mkdir -p /var/lib/cron-apt

# Function to detect Linux distribution
detect_distribution() {
    if [[ -f /etc/os-release ]]; then
        # Use a subshell to source without affecting parent environment
        (source /etc/os-release && echo "$ID")
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/kali-version ]]; then
        echo "kali"
    else
        echo "unknown"
    fi
}

# Enhanced logging function with levels
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Always log to file
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Log to console based on verbosity
    if [[ "$VERBOSE_LOGGING" == "true" || "$level" == "ERROR" || "$level" == "WARNING" ]]; then
        echo "[$timestamp] [$level] $message"
    fi
}

# Function to send enhanced email notifications
send_email() {
    local subject="$1"
    local body="$2"
    local priority="${3:-normal}"
    
    if [[ -n "$EMAIL_RECIPIENT" ]] && command -v mail >/dev/null 2>&1; then
        {
            echo "cron-apt Update Report"
            echo "====================="
            echo "Hostname: $(hostname -f)"
            echo "Date: $(date)"
            echo "Distribution: $(detect_distribution)"
            echo "Priority: $priority"
            echo ""
            echo "$body"
            echo ""
            echo "Log file: $LOG_FILE"
            if [[ -f "$METRICS_FILE" ]]; then
                echo ""
                echo "Metrics:"
                cat "$METRICS_FILE"
            fi
        } | mail -s "[$priority] $subject - $(hostname -f)" "$EMAIL_RECIPIENT"
    fi
}

# Enhanced lock management
acquire_lock() {
    local max_wait=10
    local wait_time=0
    
    while [[ -f "$LOCK_FILE" ]] && [[ $wait_time -lt $max_wait ]]; do
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "unknown")
        
        if [[ "$pid" != "unknown" ]] && kill -0 "$pid" 2>/dev/null; then
            log_message "INFO" "Another instance is running (PID: $pid), waiting..."
            sleep 1
            ((wait_time++))
        else
            log_message "WARNING" "Stale lock file found. Removing and continuing..."
            rm -f "$LOCK_FILE"
            break
        fi
    done
    
    if [[ $wait_time -ge $max_wait ]]; then
        log_message "ERROR" "Could not acquire lock after ${max_wait}s"
        exit 1
    fi
    
    echo $$ > "$LOCK_FILE"
    log_message "INFO" "Lock acquired (PID: $$)"
}

# Function to release lock
release_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        rm -f "$LOCK_FILE"
        log_message "INFO" "Lock released"
    fi
}

# Enhanced error handler with cleanup
error_handler() {
    local exit_code=$?
    local line_no=${1:-}
    
    log_message "ERROR" "Script failed at line $line_no with exit code $exit_code"
    
    # Update status file
    echo "FAILED" > "$STATUS_FILE"
    echo "$(date): Update failed at line $line_no with exit code $exit_code" >> "$STATUS_FILE"
    
    send_email "Update Failed" "cron-apt update process failed. Check logs for details." "high"
    
    release_lock
    exit $exit_code
}

# Set error trap
trap 'error_handler ${BASH_LINENO[0]}' ERR
trap 'release_lock' EXIT

# Enhanced configuration loader with validation
load_configuration() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_message "INFO" "No configuration file found, using defaults"
        return 0
    fi
    
    if [[ ! -r "$CONFIG_FILE" ]]; then
        log_message "WARNING" "Configuration file exists but is not readable"
        return 1
    fi
    
    # Check file permissions
    local file_perms
    file_perms=$(stat -c %a "$CONFIG_FILE")
    if [[ "$file_perms" -gt 644 ]]; then
        log_message "WARNING" "Config file has unsafe permissions ($file_perms), using defaults"
        return 1
    fi
    
    # Safer configuration loading
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        # Skip comments and empty lines
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        
        # Clean key and value
        key=$(echo "$key" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
        value=$(echo "$value" | sed -e 's/^["'\'']//' -e 's/["'\'']$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        
        case "$key" in
            "EMAIL_RECIPIENT") EMAIL_RECIPIENT="$value" ;;
            "MAX_LOG_SIZE") MAX_LOG_SIZE="$value" ;;
            "AUTO_REBOOT") AUTO_REBOOT="$value" ;;
            "CUSTOM_SERVICES") CUSTOM_SERVICES="$value" ;;
            "EXCLUDE_PACKAGES") EXCLUDE_PACKAGES="$value" ;;
            "VERBOSE_LOGGING") VERBOSE_LOGGING="$value" ;;
            "UPDATE_TIMEOUT") UPDATE_TIMEOUT="$value" ;;
            "PRE_UPDATE_HOOK") PRE_UPDATE_HOOK="$value" ;;
            "POST_UPDATE_HOOK") POST_UPDATE_HOOK="$value" ;;
        esac
    done < "$CONFIG_FILE"
    
    log_message "INFO" "Configuration loaded from $CONFIG_FILE"
}

# Function to run hooks safely
run_hook() {
    local hook_type="$1"
    local hook_script="$2"
    
    if [[ -z "$hook_script" ]]; then
        return 0
    fi
    
    if [[ -x "$hook_script" ]]; then
        log_message "INFO" "Running $hook_type hook: $hook_script"
        if timeout 300 "$hook_script"; then
            log_message "INFO" "$hook_type hook completed successfully"
        else
            log_message "WARNING" "$hook_type hook failed or timed out"
        fi
    else
        log_message "WARNING" "$hook_type hook script not found or not executable: $hook_script"
    fi
}

# Enhanced package update function with metrics
update_packages() {
    local start_time
    local end_time
    local packages_upgraded=0
    
    start_time=$(date +%s)
    
    # Update package lists
    log_message "INFO" "Updating package lists..."
    if timeout "$UPDATE_TIMEOUT" apt-get update -qq 2>/dev/null; then
        log_message "INFO" "Package lists updated successfully"
    else
        log_message "ERROR" "Failed to update package lists"
        return 1
    fi
    
    # Check for upgradable packages
    local upgradable
    upgradable=$(apt list --upgradable 2>/dev/null | wc -l)
    if [[ $upgradable -gt 1 ]]; then
        packages_upgraded=$((upgradable - 1))
        log_message "INFO" "Found $packages_upgraded upgradable packages"
    fi
    
    # Upgrade packages
    log_message "INFO" "Upgrading packages..."
    if timeout "$UPDATE_TIMEOUT" apt-get upgrade -y -qq 2>/dev/null; then
        log_message "INFO" "Packages upgraded successfully"
    else
        log_message "ERROR" "Failed to upgrade packages"
        return 1
    fi
    
    # Perform dist-upgrade
    log_message "INFO" "Performing dist-upgrade..."
    if timeout "$UPDATE_TIMEOUT" apt-get dist-upgrade -y -qq 2>/dev/null; then
        log_message "INFO" "Dist-upgrade completed successfully"
    else
        log_message "WARNING" "Dist-upgrade failed, but continuing..."
    fi
    
    # Remove unnecessary packages
    log_message "INFO" "Removing unnecessary packages..."
    apt-get autoremove -y -qq 2>/dev/null && \
    apt-get autoclean -y -qq 2>/dev/null && \
    log_message "INFO" "Cleanup completed successfully"
    
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Save metrics
    {
        echo "last_update=$(date)"
        echo "duration_seconds=$duration"
        echo "packages_upgraded=$packages_upgraded"
        echo "update_status=success"
    } > "$METRICS_FILE"
    
    log_message "INFO" "Update completed in ${duration}s, $packages_upgraded packages upgraded"
}

# Enhanced reboot check with notification
check_reboot_required() {
    if [[ -f "$REBOOT_REQUIRED_FILE" ]]; then
        local reboot_reason=""
        if [[ -s "$REBOOT_REQUIRED_FILE" ]]; then
            reboot_reason=$(cat "$REBOOT_REQUIRED_FILE")
        fi
        
        log_message "INFO" "Reboot required: $reboot_reason"
        
        if [[ "$AUTO_REBOOT" == "true" ]]; then
            log_message "INFO" "Auto-reboot enabled. System will reboot in 5 minutes..."
            send_email "System Reboot Scheduled" "The system will reboot in 5 minutes to complete updates.\nReason: $reboot_reason" "high"
            
            # Create a file to indicate planned reboot
            echo "Planned reboot by cron-apt at $(date)" > /tmp/cron-apt-reboot
            
            shutdown -r +5 "System reboot required to complete updates: $reboot_reason"
        else
            send_email "Manual Reboot Required" "A reboot is required but auto-reboot is disabled.\nReason: $reboot_reason\nPlease reboot manually when convenient." "medium"
            log_message "INFO" "Manual reboot required - auto-reboost disabled"
        fi
        return 0
    else
        return 1
    fi
}

# Enhanced service restart with better error handling
restart_services() {
    log_message "INFO" "Checking and restarting services..."
    
    # Use needrestart if available
    if command -v needrestart >/dev/null 2>&1; then
        log_message "INFO" "Running needrestart..."
        if needrestart -r a -q 2>/dev/null; then
            log_message "INFO" "needrestart completed successfully"
        else
            log_message "WARNING" "needrestart encountered issues"
        fi
    fi
    
    # Restart custom services
    if [[ -n "${CUSTOM_SERVICES:-}" ]]; then
        for service in $CUSTOM_SERVICES; do
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                log_message "INFO" "Restarting service: $service"
                if systemctl restart "$service"; then
                    log_message "INFO" "Successfully restarted: $service"
                else
                    log_message "WARNING" "Failed to restart: $service"
                fi
            else
                log_message "INFO" "Service $service is not active, skipping restart"
            fi
        done
    fi
}

# Main execution function
main() {
    log_message "INFO" "Starting cron-apt v$SCRIPT_VERSION automatic update process"
    log_message "INFO" "Distribution: $(detect_distribution)"
    log_message "INFO" "Hostname: $(hostname -f)"
    
    # Acquire lock
    acquire_lock
    
    # Load configuration
    load_configuration
    
    # Update status
    echo "RUNNING" > "$STATUS_FILE"
    echo "$(date): Update process started" >> "$STATUS_FILE"
    
    # Run pre-update hook
    run_hook "pre-update" "$PRE_UPDATE_HOOK"
    
    # Perform updates
    if update_packages; then
        log_message "INFO" "Package updates completed successfully"
    else
        log_message "ERROR" "Package updates failed"
        echo "FAILED" > "$STATUS_FILE"
        exit 1
    fi
    
    # Restart services
    restart_services
    
    # Run post-update hook
    run_hook "post-update" "$POST_UPDATE_HOOK"
    
    # Check for reboot requirement
    if check_reboot_required; then
        log_message "INFO" "Reboot process initiated"
        echo "REBOOT_REQUIRED" > "$STATUS_FILE"
    else
        log_message "INFO" "No reboot required"
        echo "COMPLETED" > "$STATUS_FILE"
    fi
    
    # Send success notification
    local report="Update process completed successfully on $(hostname -f)"
    if [[ -f "$METRICS_FILE" ]]; then
        report="$report\n\n$(cat "$METRICS_FILE")"
    fi
    send_email "Update Completed Successfully" "$report" "normal"
    
    log_message "INFO" "cron-apt update process completed successfully"
}

# Handle command line arguments
case "${1:-}" in
    --version|-v)
        echo "cron-apt version $SCRIPT_VERSION"
        exit 0
        ;;
    --help|-h)
        echo "cron-apt - Automatic Update System"
        echo "Usage: $0 [--version|--help]"
        echo ""
        echo "This script automatically updates the system packages."
        echo "Configuration: $CONFIG_FILE"
        echo "Log file: $LOG_FILE"
        exit 0
        ;;
esac

# Start main execution
main "$@"
EOF

    chmod +x /usr/local/bin/cron-apt
    log "INFO" "Main script created successfully"
}

# Function to create enhanced systemd service
create_systemd_service() {
    log "INFO" "Creating enhanced systemd service..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "Dry run: Would create /etc/systemd/system/cron-apt.service"
        return 0
    fi
    
cat > /etc/systemd/system/cron-apt.service << 'EOF'
[Unit]
Description=cron-apt - Automatic System Update Service for Ubuntu/Debian/Kali
Documentation=https://github.com/bidhata/cron-apt
After=network-online.target time-sync.target
Wants=network-online.target
StartLimitIntervalSec=3600
StartLimitBurst=3

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cron-apt
User=root
Group=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cron-apt

# Security settings - Enhanced hardening
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=full
ProtectHome=true
ProtectHostname=true
ProtectClock=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false
RemoveIPC=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallFilter=@system-service
SystemCallArchitectures=native
SystemCallErrorNumber=EPERM

# Capabilities - minimal set needed for package management
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETUID CAP_SETGID CAP_SYS_ADMIN CAP_KILL CAP_SYS_BOOT
AmbientCapabilities=

# Resource limits
TasksMax=200
MemoryMax=2G
CPUQuota=75%

# Timeout settings - increased for large updates
TimeoutStartSec=7200
TimeoutStopSec=60

# Environment
Environment="DEBIAN_FRONTEND=noninteractive"
Environment="APT_LISTCHANGES_FRONTEND=none"

# Restart policy
Restart=no
RestartSec=300

[Install]
WantedBy=multi-user.target
EOF

    log "INFO" "Systemd service created successfully"
}

# Function to create enhanced systemd timer
create_systemd_timer() {
    log "INFO" "Creating enhanced systemd timer..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "Dry run: Would create /etc/systemd/system/cron-apt.timer"
        return 0
    fi
    
    local calendar
    case "$UPDATE_FREQUENCY" in
        "daily")
            calendar="*-*-* 02:00:00"
            ;;
        "weekly")
            calendar="Sun *-*-* 02:00:00"
            ;;
        "monthly")
            calendar="*-*-01 02:00:00"
            ;;
    esac
    
cat > /etc/systemd/system/cron-apt.timer << EOF
[Unit]
Description=cron-apt - Run automatic updates ($UPDATE_FREQUENCY)
Documentation=https://github.com/bidhata/cron-apt
Requires=cron-apt.service

[Timer]
OnCalendar=$calendar
Persistent=true
RandomizedDelaySec=1800
AccuracySec=15min

[Install]
WantedBy=timers.target
EOF

    log "INFO" "Systemd timer created successfully with frequency: $UPDATE_FREQUENCY"
}

# Function to create enhanced configuration files
create_configuration_files() {
    log "INFO" "Creating configuration files..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "Dry run: Would create configuration files in /etc/cron-apt/"
        return 0
    fi
    
    # Create configuration directory
    mkdir -p /etc/cron-apt
    
    # Create main configuration file with email if provided
    local email_config=""
    if [[ -n "$EMAIL_RECIPIENT" ]]; then
        email_config="EMAIL_RECIPIENT=\"$EMAIL_RECIPIENT\""
    fi
    
    cat > /etc/cron-apt/config << EOF
# cron-apt Configuration File
# Created by installation script v$SCRIPT_VERSION on $(date)
# Repository: https://github.com/$GITHUB_REPO

# Email notifications (optional)
# Uncomment and set your email to receive update notifications
$email_config

# Maximum log file size before rotation
MAX_LOG_SIZE="10M"

# Enable automatic reboot when required (use with caution in production)
AUTO_REBOOT="$AUTO_REBOOT_SETTING"

# Update timeout in seconds (default: 3600 = 1 hour)
UPDATE_TIMEOUT="3600"

# Additional services to restart after updates (space-separated)
# Example: CUSTOM_SERVICES="nginx apache2 mysql"
# CUSTOM_SERVICES=""

# Skip certain package upgrades (space-separated package names)
# Example: EXCLUDE_PACKAGES="kernel-image-* mysql-server"
# EXCLUDE_PACKAGES=""

# Enable verbose logging (true/fable)
VERBOSE_LOGGING="false"

# Pre-update hook script (runs before updates)
# Must be executable file with full path
# PRE_UPDATE_HOOK="/etc/cron-apt/hooks/pre-update.sh"

# Post-update hook script (runs after updates)
# Must be executable file with full path
# POST_UPDATE_HOOK="/etc/cron-apt/hooks/post-update.sh"

# Distribution-specific settings
# For Kali Linux, you might want to exclude certain packages:
# EXCLUDE_PACKAGES="kali-linux-everything kali-tools-top10"

# For production servers, consider these settings:
# AUTO_REBOOT="false"
# VERBOSE_LOGGING="true"
EOF

    chmod 644 /etc/cron-apt/config
    
    # Create example hooks directory
    mkdir -p /etc/cron-apt/hooks
    
    # Create example pre-update hook
    cat > /etc/cron-apt/hooks/pre-update.sh.example << 'EOF'
#!/bin/bash
# Example pre-update hook script
# This script runs before the update process begins
# Make it executable: chmod +x /etc/cron-apt/hooks/pre-update.sh

# Example: Stop resource-intensive services
# systemctl stop some-heavy-service

# Example: Create database backup
# mysqldump --all-databases > /backup/mysql-$(date +%Y%m%d).sql

# Example: Send notification
# echo "Starting system updates on $(hostname)" | mail -s "Updates Starting" admin@example.com

echo "Pre-update hook executed at $(date)"
EOF

    # Create example post-update hook
    cat > /etc/cron-apt/hooks/post-update.sh.example << 'EOF'
#!/bin/bash
# Example post-update hook script
# This script runs after the update process completes
# Make it executable: chmod +x /etc/cron-apt/hooks/post-update.sh

# Example: Restart services that were stopped in pre-update
# systemctl start some-heavy-service

# Example: Clean up old backups
# find /backup -name "mysql-*.sql" -mtime +7 -delete

# Example: Update custom applications
# /opt/myapp/update.sh

# Example: Send completion notification
# echo "System updates completed on $(hostname)" | mail -s "Updates Complete" admin@example.com

echo "Post-update hook executed at $(date)"
EOF

    chmod 644 /etc/cron-apt/hooks/*.example
    
    log "INFO" "Configuration files created successfully"
}

# Function to create log rotation with enhanced settings
create_log_rotation() {
    log "INFO" "Creating enhanced log rotation configuration..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "Dry run: Would create /etc/logrotate.d/cron-apt"
        return 0
    fi
    
    cat > /etc/logrotate.d/cron-apt << 'EOF'
/var/log/cron-apt.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    maxsize 50M
    
    postrotate
        # Send SIGHUP to rsyslog if it's running
        /bin/systemctl reload rsyslog > /dev/null 2>&1 || true
        # Log rotation event
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Log rotated" >> /var/log/cron-apt.log
    endscript
    
    # Compress old logs immediately if they're larger than 10M
    prerotate
        if [ -f /var/log/cron-apt.log ]; then
            size=$(stat -c%s /var/log/cron-apt.log)
            if [ $size -gt 10485760 ]; then
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Large log file detected, forcing rotation" >> /var/log/cron-apt.log
            fi
        fi
    endscript
}

# Rotate metrics and status files
/var/lib/cron-apt/metrics /var/lib/cron-apt/status {
    monthly
    rotate 6
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    maxsize 1M
}
EOF

    log "INFO" "Log rotation configured successfully"
}

# Function to create enhanced uninstaller
create_uninstaller() {
    log "INFO" "Creating enhanced uninstaller..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "Dry run: Would create /usr/local/bin/uninstall-cron-apt"
        return 0
    fi
    
    cat > /usr/local/bin/uninstall-cron-apt << 'EOF'
#!/bin/bash
# cron-apt Enhanced Uninstaller
# Created by Krishnendu Paul (@bidhata)
# Supports Ubuntu/Debian/Kali Linux with comprehensive cleanup

set -euo pipefail

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

log() {
    local level="$1"
    shift
    local message="$*"
    case "$level" in
        "INFO")  echo -e "${GREEN}[INFO]${NC}  $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC}  $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
    esac
}

echo "cron-apt Enhanced Uninstaller for Ubuntu/Debian/Kali Linux"
echo "=========================================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log "ERROR" "This script must be run as root"
    echo "Usage: sudo /usr/local/bin/uninstall-cron-apt"
    exit 1
fi

echo "This will completely remove cron-apt from your system."
echo "All configuration files, logs, hooks, and scheduled updates will be removed."
echo ""

# Show current status with enhanced information
log "INFO" "Current cron-apt status:"

if systemctl is-enabled cron-apt.timer >/dev/null 2>&1; then
    echo "  • Timer: ENABLED"
    if systemctl is-active cron-apt.timer >/dev/null 2>&1; then
        echo "  • Status: ACTIVE"
        echo ""
        systemctl list-timers cron-apt.timer --no-pager 2>/dev/null || true
    else
        echo "  • Status: INACTIVE"
    fi
else
    echo "  • Timer: DISABLED"
    echo "  • Status: INACTIVE"
fi

# Show last update information
if [[ -f "/var/lib/cron-apt/status" ]]; then
    echo ""
    echo "Last status:"
    tail -3 /var/lib/cron-apt/status | sed 's/^/  | /'
fi

if [[ -f "/var/log/cron-apt.log" ]]; then
    echo ""
    echo "Recent log entries:"
    tail -3 /var/log/cron-apt.log | sed 's/^/  | /'
fi

echo ""
read -p "Are you sure you want to continue? [y/N]: " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log "INFO" "Uninstallation cancelled."
    exit 0
fi

log "INFO" "Uninstalling cron-apt..."

# Stop and disable services
log "INFO" "Stopping and disabling services..."
systemctl stop cron-apt.timer 2>/dev/null || true
systemctl stop cron-apt.service 2>/dev/null || true
systemctl disable cron-apt.timer 2>/dev/null || true

# Remove systemd files
log "INFO" "Removing systemd files..."
rm -f /etc/systemd/system/cron-apt.service
rm -f /etc/systemd/system/cron-apt.timer
systemctl daemon-reload

# Remove scripts and configuration
log "INFO" "Removing scripts and configuration..."
rm -f /usr/local/bin/cron-apt
rm -rf /etc/cron-apt

# Remove data directory
log "INFO" "Removing data directory..."
rm -rf /var/lib/cron-apt

# Remove logs and temporary files
log "INFO" "Removing logs and temporary files..."
rm -f /var/log/cron-apt.log*
rm -f /var/run/cron-apt.lock
rm -f /etc/logrotate.d/cron-apt

# Clean up any reboot indicators
rm -f /tmp/cron-apt-reboot

# Remove this uninstaller
rm -f /usr/local/bin/uninstall-cron-apt

echo ""
log "INFO" "✓ cron-apt has been completely removed from your system."
echo ""
log "WARN" "Note: The packages 'needrestart' and 'mailutils' were not removed"
echo "as they may be used by other applications."
echo ""
log "INFO" "Your system will no longer receive automatic updates."
echo "Remember to manually update your system regularly with:"
echo "  sudo apt update && sudo apt upgrade"
echo ""
log "INFO" "If you want to reinstall cron-apt later, visit:"
echo "  https://github.com/bidhata/cron-apt"
echo ""
EOF

    chmod +x /usr/local/bin/uninstall-cron-apt
    log "INFO" "Uninstaller created successfully"
}

# Function to install required packages with better error handling
install_required_packages() {
    log "INFO" "Installing required packages..."
    log "INFO" "This may take a few minutes depending on your internet connection..."

    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "Dry run: Would install needrestart, mailutils, logrotate"
        return 0
    fi

    # Update package lists first
    log "INFO" "Updating package lists..."
    if ! apt-get update -qq; then
        log "ERROR" "Failed to update package lists. Please check your internet connection."
        exit 1
    fi

    # Install packages with better error checking
    local packages=("needrestart" "mailutils" "logrotate")
    local failed_packages=()

    for package in "${packages[@]}"; do
        log "INFO" "Installing $package..."
        if apt-get install -y "$package" >/dev/null 2>&1; then
            log "INFO" "✓ $package installed successfully"
        else
            log "WARN" "Failed to install $package"
            failed_packages+=("$package")
        fi
    done

    if [[ ${#failed_packages[@]} -gt 0 ]]; then
        log "WARN" "Some packages failed to install: ${failed_packages[*]}"
        log "WARN" "cron-apt will still work, but some features may be limited"
    else
        log "INFO" "All required packages installed successfully"
    fi
}

# Function to initialize system with comprehensive setup
initialize_system() {
    log "INFO" "Initializing system..."

    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "Dry run: Would initialize system directories and files"
        return 0
    fi

    # Create required directories
    mkdir -p /var/lib/cron-apt
    mkdir -p /etc/cron-apt/hooks

    # Initialize log file with proper permissions
    touch /var/log/cron-apt.log
    chown root:root /var/log/cron-apt.log
    chmod 644 /var/log/cron-apt.log

    # Create initial log entry with more information
    {
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] ===== cron-apt Installation ====="
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Version: $SCRIPT_VERSION"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Installed by: $(whoami)"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] System: $(uname -a)"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Distribution: $(detect_distribution 2>/dev/null || echo 'unknown')"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] AUTO_REBOOT setting: $AUTO_REBOOT_SETTING"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] UPDATE_FREQUENCY: $UPDATE_FREQUENCY"
        if [[ -n "$EMAIL_RECIPIENT" ]]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] EMAIL_RECIPIENT: $EMAIL_RECIPIENT"
        fi
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] Installation completed successfully"
    } >> /var/log/cron-apt.log

    # Initialize status file
    {
        echo "INSTALLED"
        echo "$(date): cron-apt v$SCRIPT_VERSION installed successfully"
        echo "$(date): AUTO_REBOOT=$AUTO_REBOOT_SETTING"
        echo "$(date): UPDATE_FREQUENCY=$UPDATE_FREQUENCY"
        if [[ -n "$EMAIL_RECIPIENT" ]]; then
            echo "$(date): EMAIL_RECIPIENT=$EMAIL_RECIPIENT"
        fi
    } > /var/lib/cron-apt/status

    # Set proper permissions
    chown -R root:root /var/lib/cron-apt
    chmod -R 755 /var/lib/cron-apt
    chmod 644 /var/lib/cron-apt/status

    log "INFO" "System initialization completed"
}

# Function to enable and start services with comprehensive validation
enable_and_start_services() {
    log "INFO" "Enabling and starting cron-apt services..."

    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "Dry run: Would enable and start cron-apt services"
        return 0
    fi

    # Reload systemd daemon
    if ! systemctl daemon-reload; then
        log "ERROR" "Failed to reload systemd daemon"
        exit 1
    fi

    # Enable and start timer
    if systemctl enable cron-apt.timer; then
        log "INFO" "✓ cron-apt.timer enabled"
    else
        log "ERROR" "Failed to enable cron-apt.timer"
        exit 1
    fi

    if systemctl start cron-apt.timer; then
        log "INFO" "✓ cron-apt.timer started"
    else
        log "ERROR" "Failed to start cron-apt.timer"
        exit 1
    fi

    # Verify timer status
    sleep 2
    if systemctl is-active cron-apt.timer >/dev/null 2>&1; then
        log "INFO" "✓ Timer is running properly"
    else
        log "ERROR" "Timer failed to start properly"
        systemctl status cron-apt.timer --no-pager || true
        exit 1
    fi

    log "INFO" "Services enabled and started successfully"
}

# Enhanced verification function
verify_installation() {
    log "INFO" "Verifying installation..."
    local installation_success=true
    local warnings=0

    if [[ "$DRY_RUN" == true ]]; then
        log "INFO" "Dry run: Would verify installation"
        return 0
    fi

    # Check if files exist
    local required_files=(
        "/usr/local/bin/cron-apt"
        "/etc/systemd/system/cron-apt.service"
        "/etc/systemd/system/cron-apt.timer"
        "/var/log/cron-apt.log"
        "/etc/logrotate.d/cron-apt"
        "/etc/cron-apt/config"
        "/usr/local/bin/uninstall-cron-apt"
        "/var/lib/cron-apt/status"
    )

    for file in "${required_files[@]}"; do
        if [[ -f "$file" ]]; then
            log "INFO" "✓ $file"
        else
            log "ERROR" "✗ $file (missing)"
            installation_success=false
        fi
    done

    # Check directories
    local required_dirs=(
        "/etc/cron-apt"
        "/etc/cron-apt/hooks"
        "/var/lib/cron-apt"
    )

    for dir in "${required_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log "INFO" "✓ $dir/"
        else
            log "ERROR" "✗ $dir/ (missing)"
            installation_success=false
        fi
    done

    # Check systemd services
    if systemctl is-enabled cron-apt.timer >/dev/null 2>&1; then
        log "INFO" "✓ cron-apt.timer is enabled"
    else
        log "ERROR" "✗ cron-apt.timer is not enabled"
        installation_success=false
    fi

    if systemctl is-active cron-apt.timer >/dev/null 2>&1; then
        log "INFO" "✓ cron-apt.timer is active"
    else
        log "ERROR" "✗ cron-apt.timer is not active"
        installation_success=false
    fi

    # Check file permissions
    local file_perms
    file_perms=$(stat -c %a /usr/local/bin/cron-apt)
    if [[ "$file_perms" == "755" ]]; then
        log "INFO" "✓ Main script permissions correct"
    else
        log "WARN" "Main script permissions: $file_perms (expected: 755)"
        ((warnings++))
    fi

    # Test script syntax
    if bash -n /usr/local/bin/cron-apt; then
        log "INFO" "✓ Main script syntax valid"
    else
        log "ERROR" "✗ Main script has syntax errors"
        installation_success=false
    fi

    # Check for required commands
    local commands=("systemctl" "apt-get" "needrestart")
    for cmd in "${commands[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            log "INFO" "✓ $cmd available"
        else
            if [[ "$cmd" == "needrestart" ]]; then
                log "WARN" "needrestart not available (service restart may be limited)"
                ((warnings++))
            else
                log "ERROR" "✗ $cmd not available"
                installation_success=false
            fi
        fi
    done

    if [[ "$installation_success" == false ]]; then
        echo ""
        log "ERROR" "Installation verification failed!"
        echo "Some components may not have been installed correctly."
        echo "Please check the error messages above and try reinstalling."
        exit 1
    fi

    if [[ $warnings -gt 0 ]]; then
        echo ""
        log "WARN" "Installation completed with $warnings warning(s)"
        echo "cron-apt should work correctly, but some features may be limited."
    else
        echo ""
        log "INFO" "✓ Installation verification completed successfully!"
    fi
}

# Function to display final status and instructions
display_final_status() {
    echo ""
    echo "=== cron-apt Enhanced Installation Complete ==="
    echo ""
    echo -e "${CYAN}Created by: Krishnendu Paul (@bidhata)${NC}"
    echo -e "${CYAN}Repository: https://github.com/$GITHUB_REPO${NC}"
    echo -e "${CYAN}Version: $SCRIPT_VERSION${NC}"
    echo ""
    echo -e "${GREEN}✓ cron-apt has been installed and configured successfully!${NC}"
    echo ""
    
    echo "Configuration Summary:"
    echo "  • Auto-reboot: $AUTO_REBOOT_SETTING"
    echo "  • Update frequency: $UPDATE_FREQUENCY"
    if [[ -n "$EMAIL_RECIPIENT" ]]; then
        echo "  • Email notifications: $EMAIL_RECIPIENT"
    else
        echo "  • Email notifications: Disabled"
    fi
    echo "  • Log file: /var/log/cron-apt.log"
    echo "  • Configuration: /etc/cron-apt/config"
    echo "  • Status tracking: /var/lib/cron-apt/status"
    echo "  • Hook scripts: /etc/cron-apt/hooks/"
    echo ""
    
    echo "Next timer execution:"
    systemctl list-timers cron-apt.timer --no-pager 2>/dev/null | tail -n +2 || true
    echo ""
    
    echo "Common Management Commands:"
    echo "  • View configuration: sudo nano /etc/cron-apt/config"
    echo "  • View update log: tail -f /var/log/cron-apt.log"
    echo "  • Check status: systemctl status cron-apt.timer"
    echo "  • Run manual update: sudo /usr/local/bin/cron-apt"
    echo "  • View next scheduled run: systemctl list-timers cron-apt.timer"
    echo "  • Disable auto-updates: sudo systemctl disable cron-apt.timer"
    echo "  • Uninstall completely: sudo /usr/local/bin/uninstall-cron-apt"
    echo ""
    
    if [[ "$AUTO_REBOOT_SETTING" == "true" ]]; then
        echo -e "${YELLOW}⚠️  AUTO-REBOOT is ENABLED${NC}"
        echo "   Your system may reboot automatically after updates that require it."
        echo "   To disable: edit /etc/cron-apt/config and set AUTO_REBOOT=\"false\""
        echo ""
    fi
    
    echo "Advanced Features:"
    echo "  • Custom services restart: Set CUSTOM_SERVICES in config"  
    echo "  • Pre/post-update hooks: See examples in /etc/cron-apt/hooks/"
    echo "  • Package exclusions: Set EXCLUDE_PACKAGES in config"
    echo "  • Verbose logging: Set VERBOSE_LOGGING=\"true\" in config"
    echo ""
    
    echo -e "${GREEN}The first automatic update will run according to your schedule ($UPDATE_FREQUENCY at 2:00 AM).${NC}"
    echo ""
    
    echo "For help and documentation, visit:"
    echo "  https://github.com/$GITHUB_REPO"
    echo ""
}

# Utility function to detect distribution (used in logging)
detect_distribution() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "$ID"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/kali-version ]]; then
        echo "kali"
    else
        echo "unknown"
    fi
}

# Function to handle script termination
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo ""
        log "ERROR" "Installation failed with exit code $exit_code"
        echo ""
        echo "Please check the error messages above and try again."
        echo "If you need help, visit: https://github.com/$GITHUB_REPO/issues"
    fi
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Install or uninstall cron-apt automatic update system"
    echo ""
    echo "OPTIONS:"
    echo "  --dry-run      Show what would be done without making changes"
    echo "  --uninstall    Remove cron-apt from the system"
    echo "  --log-level    Set log level (DEBUG, INFO, WARN, ERROR)"
    echo "  -h, --help     Show this help message"
}

# Function to parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --uninstall)
                UNINSTALL=true
                shift
                ;;
            --log-level)
                if [[ -n "$2" ]]; then
                    set_log_level "$2"
                    shift
                else
                    log "ERROR" "Please specify a log level: DEBUG, INFO, WARN, ERROR"
                    exit 1
                fi
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Function to perform dry run
dry_run() {
    log "INFO" "Dry-run mode: Would perform the following actions:"
    log "INFO" "1. Install packages: needrestart, mailutils, logrotate"
    log "INFO" "2. Create systemd service and timer"
    log "INFO" "3. Set up log rotation"
    log "INFO" "4. Configure automatic updates with frequency: $UPDATE_FREQUENCY"
    log "INFO" "5. Set auto-reboot: $AUTO_REBOOT_SETTING"
    log "INFO" "6. Create uninstaller script"
    log "INFO" "7. Enable and start systemd timer"
    log "INFO" ""
    log "INFO" "No changes will be made to the system."
}

# Function to perform uninstallation
uninstall_cron_apt() {
    log "INFO" "Starting uninstallation of cron-apt..."
    
    # Stop and disable services
    systemctl stop cron-apt.timer 2>/dev/null || true
    systemctl stop cron-apt.service 2>/dev/null || true
    systemctl disable cron-apt.timer 2>/dev/null || true
    systemctl daemon-reload
    
    # Remove files
    rm -f /usr/local/bin/cron-apt
    rm -f /etc/systemd/system/cron-apt.service
    rm -f /etc/systemd/system/cron-apt.timer
    rm -f /etc/logrotate.d/cron-apt
    rm -rf /etc/cron-apt
    
    # Remove logs and data
    rm -f /var/log/cron-apt.log
    rm -rf /var/lib/cron-apt
    
    # Clean up any reboot indicators
    rm -f /tmp/cron-apt-reboot
    
    # Remove uninstaller
    rm -f /usr/local/bin/uninstall-cron-apt
    
    log "INFO" "cron-apt has been uninstalled."
}

# Main execution flow
main() {
    log "INFO" "Starting cron-apt enhanced installation v$SCRIPT_VERSION"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    if [[ "$UNINSTALL" == true ]]; then
        uninstall_cron_apt
        exit 0
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        dry_run
        exit 0
    fi
    
    # Pre-installation checks
    check_disk_space
    check_system_compatibility
    check_root_privileges
    check_internet_connectivity
    check_existing_installation
    
    # User configuration
    ask_auto_reboot_preference
    ask_email_preference
    ask_update_frequency
    
    # Installation process
    create_main_script
    create_systemd_service
    create_systemd_timer
    create_configuration_files
    create_log_rotation
    create_uninstaller
    install_required_packages
    initialize_system
    enable_and_start_services
    
    # Post-installation verification
    verify_installation
    display_final_status
    
    log "INFO" "Installation completed successfully"
}

# Handle script termination
trap cleanup EXIT

# Start main execution
main "$@"
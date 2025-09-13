#!/bin/bash

# cron-apt - Automatic Update System for Ubuntu/Debian/Kali Linux Servers
# This script automatically updates the system weekly and restarts services as needed
# Created and Maintained by Krishnendu Paul (@bidhata)
# Repository: https://github.com/bidhata/cron-apt

set -euo pipefail

# Security: Set secure PATH to prevent hijacking
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Security: Set secure umask
umask 077

# Configuration - Use absolute paths for security
readonly LOG_FILE="/var/log/cron-apt.log"
readonly LOCK_FILE="/var/run/cron-apt.lock"
readonly REBOOT_REQUIRED_FILE="/var/run/reboot-required"
readonly CONFIG_FILE="/etc/cron-apt/config"
EMAIL_RECIPIENT=""  # Set email for notifications (optional)
MAX_LOG_SIZE="10M"  # Maximum log size before rotation
AUTO_REBOOT="false" # Default: don't auto-reboot (safety first)

# Load configuration file if it exists
if [[ -f "$CONFIG_FILE" ]]; then
    # Security: Source config file safely
    if [[ -r "$CONFIG_FILE" ]] && [[ "$(stat -c %a "$CONFIG_FILE")" -le 644 ]]; then
        source "$CONFIG_FILE"
    else
        log_message "WARNING: Config file $CONFIG_FILE has unsafe permissions, ignoring"
    fi
fi

# Function to detect Linux distribution
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

# Function to log messages with improved security
log_message() {
    local message="$1"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    # Security: Sanitize message to prevent log injection
    message="${message//[$'\r\n']/ }"
    message="${message:0:1024}"  # Limit message length
    
    # Create log directory if it doesn't exist
    local log_dir
    log_dir="$(dirname "$LOG_FILE")"
    if [[ ! -d "$log_dir" ]]; then
        mkdir -p "$log_dir"
        chmod 755 "$log_dir"
    fi
    
    # Write to log with proper permissions
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
    
    # Ensure log file has proper permissions
    chmod 644 "$LOG_FILE" 2>/dev/null || true
    
    # Check log size and rotate if necessary
    if [[ -f "$LOG_FILE" ]]; then
        local log_size
        log_size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo "0")
        local max_size_bytes=10485760  # 10MB
        
        if [[ "$log_size" -gt "$max_size_bytes" ]]; then
            mv "$LOG_FILE" "${LOG_FILE}.old" 2>/dev/null || true
            echo "[$timestamp] Log rotated due to size limit" > "$LOG_FILE"
            chmod 644 "$LOG_FILE" 2>/dev/null || true
        fi
    fi
}

# Function to send notification with enhanced security
send_notification() {
    local subject="$1"
    local message="$2"
    
    # Security: Validate email recipient format
    if [[ -n "$EMAIL_RECIPIENT" ]]; then
        if [[ ! "$EMAIL_RECIPIENT" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
            log_message "WARNING: Invalid email format: $EMAIL_RECIPIENT"
            return 1
        fi
        
        # Security: Sanitize subject and message
        subject="${subject//[$'\r\n']/ }"
        subject="${subject:0:200}"  # Limit subject length
        message="${message//[$'\r\n\t']/ }"
        message="${message:0:2000}"  # Limit message length
        
        if command -v mail >/dev/null 2>&1; then
            echo "$message" | timeout 30 mail -s "$subject" "$EMAIL_RECIPIENT" 2>/dev/null || {
                log_message "WARNING: Failed to send email notification"
                return 1
            }
            log_message "Email notification sent to $EMAIL_RECIPIENT"
        else
            log_message "WARNING: mail command not available for notifications"
        fi
    fi
}

# Function to check if running as root or with sudo
check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: cron-apt must be run as root or with sudo privileges!"
        echo ""
        echo "This script requires root access to:"
        echo "  • Update system packages"
        echo "  • Restart system services"
        echo "  • Write to system log files"
        echo "  • Manage package repositories"
        echo ""
        echo "Please run with:"
        echo "  sudo $0"
        echo "  or"
        echo "  sudo /usr/local/bin/cron-apt.sh"
        echo ""
        exit 1
    fi
    
    # Log the execution context
    if [[ -n "${SUDO_USER:-}" ]]; then
        log_message "Running as root via sudo (original user: $SUDO_USER)"
    else
        log_message "Running as root user"
    fi
}

# Function to check if another update is running with improved locking
check_lock() {
    # Security: Ensure lock directory exists with proper permissions
    local lock_dir
    lock_dir="$(dirname "$LOCK_FILE")"
    if [[ ! -d "$lock_dir" ]]; then
        mkdir -p "$lock_dir"
        chmod 755 "$lock_dir"
    fi
    
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        if ! pid=$(cat "$LOCK_FILE" 2>/dev/null) || [[ ! "$pid" =~ ^[0-9]+$ ]]; then
            log_message "WARNING: Invalid lock file format, removing it"
            rm -f "$LOCK_FILE"
        elif ps -p "$pid" > /dev/null 2>&1; then
            log_message "ERROR: Another cron-apt process is already running (PID: $pid)"
            exit 1
        else
            log_message "WARNING: Stale lock file found (PID: $pid no longer exists), removing it"
            rm -f "$LOCK_FILE"
        fi
    fi
    
    # Create lock file with proper permissions
    echo $$ > "$LOCK_FILE"
    chmod 644 "$LOCK_FILE" 2>/dev/null || true
}

# Function to cleanup on exit
cleanup() {
    rm -f "$LOCK_FILE"
}

# Function to get distribution-specific services
get_distribution_services() {
    local distro
    distro=$(detect_distribution)
    
    case "$distro" in
        kali)
            echo "apache2 nginx mysql mariadb postgresql ssh ssh-server openssh-server docker containerd systemd-resolved networking network-manager dbus cron rsyslog fail2ban ufw firewalld tor privoxy"
            ;;
        ubuntu|debian)
            echo "apache2 httpd nginx mysql mariadb postgresql ssh sshd openssh-server docker containerd systemd-resolved networking network-manager dbus cron rsyslog fail2ban ufw firewalld snapd"
            ;;
        *)
            echo "apache2 httpd nginx mysql mariadb postgresql ssh sshd openssh-server docker containerd systemd-resolved networking network-manager dbus cron rsyslog fail2ban ufw firewalld"
            ;;
    esac
}

# Function to restart services with enhanced error handling
restart_services() {
    log_message "Checking for services that need restarting..."
    
    # Check if needrestart is available and install if needed
    if command -v needrestart >/dev/null 2>&1; then
        log_message "Using needrestart to identify services..."
        # Run needrestart with timeout to prevent hanging
        if timeout 300 needrestart -r a -m a 2>&1 | tee -a "$LOG_FILE"; then
            log_message "needrestart completed successfully"
        else
            log_message "WARNING: needrestart failed or timed out"
        fi
    else
        log_message "needrestart not available, installing it..."
        if apt-get update -qq && apt-get install -y needrestart; then
            log_message "needrestart installed successfully"
            timeout 300 needrestart -r a -m a 2>&1 | tee -a "$LOG_FILE" || {
                log_message "WARNING: needrestart failed after installation"
            }
        else
            log_message "ERROR: Failed to install needrestart, continuing with manual service checks"
        fi
    fi
    
    # Get distribution-specific services to check
    local services_to_check
    read -ra services_to_check <<< "$(get_distribution_services)"
    
    # Add custom services from config
    if [[ -n "${CUSTOM_SERVICES:-}" ]]; then
        read -ra custom_services <<< "$CUSTOM_SERVICES"
        services_to_check+=("${custom_services[@]}")
    fi
    
    local restarted_count=0
    local failed_count=0
    local skipped_count=0
    
    for service in "${services_to_check[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            if systemctl is-enabled --quiet "$service" 2>/dev/null; then
                log_message "Attempting to restart service: $service"
                if timeout 60 systemctl restart "$service" 2>/dev/null; then
                    log_message "Successfully restarted $service"
                    ((restarted_count++))
                else
                    log_message "ERROR: Failed to restart $service"
                    ((failed_count++))
                fi
            else
                log_message "Service $service is active but not enabled, skipping restart"
                ((skipped_count++))
            fi
        fi
    done
    
    log_message "Service restart summary: $restarted_count restarted, $failed_count failed, $skipped_count skipped"
}

# Function to check if reboot is required
check_reboot_required() {
    if [[ -f "$REBOOT_REQUIRED_FILE" ]]; then
        log_message "NOTICE: System reboot is required after updates"
        
        # Get list of packages requiring reboot
        if [[ -f "/var/run/reboot-required.pkgs" ]]; then
            log_message "Packages requiring reboot:"
            cat "/var/run/reboot-required.pkgs" | tee -a "$LOG_FILE"
        fi
        
        send_notification "cron-apt: Server Reboot Required" "The server $(hostname) requires a reboot after automatic updates. Please schedule a maintenance window."
        
        # Check if auto-reboot is enabled
        if [[ "${AUTO_REBOOT:-false}" == "true" ]]; then
            log_message "WARNING: AUTO_REBOOT is enabled - initiating automatic reboot in 2 minutes..."
            send_notification "cron-apt: Auto-Reboot Initiated" "AUTO_REBOOT is enabled. The server $(hostname) will reboot in 2 minutes due to automatic updates."
            shutdown -r +2 "System will reboot in 2 minutes due to cron-apt automatic updates"
        fi
        
        return 0
    else
        log_message "No reboot required"
        return 1
    fi
}

# Function to validate system state before updates
validate_system_state() {
    log_message "Validating system state before updates..."
    
    local validation_failed=false
    
    # Check if system is in emergency mode
    if systemctl is-system-running | grep -q "degraded\|maintenance"; then
        log_message "WARNING: System is in degraded or maintenance mode"
        validation_failed=true
    fi
    
    # Check available disk space
    local root_space
    root_space=$(df / | awk 'NR==2 {print $4}')
    if [[ "$root_space" -lt 2097152 ]]; then  # Less than 2GB
        log_message "ERROR: Insufficient disk space on root filesystem ($root_space KB available)"
        validation_failed=true
    fi
    
    # Check if dpkg is locked
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
        log_message "ERROR: Package manager is currently locked by another process"
        validation_failed=true
    fi
    
    # Check system load
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{ print $2 }' | awk '{ print $1 }' | sed 's/,//')
    if (( $(echo "$load_avg > 10" | bc -l 2>/dev/null || echo "0") )); then
        log_message "WARNING: High system load detected ($load_avg)"
    fi
    
    # Check memory usage
    local mem_available
    mem_available=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
    if [[ "$mem_available" -lt 524288 ]]; then  # Less than 512MB
        log_message "WARNING: Low memory available ($mem_available KB)"
    fi
    
    if [[ "$validation_failed" == true ]]; then
        log_message "ERROR: System validation failed. Aborting update process."
        return 1
    fi
    
    log_message "System validation passed"
    return 0
}

# Function to perform system updates with enhanced security and error handling
perform_updates() {
    log_message "Starting cron-apt automatic system update process..."
    
    # Detect distribution for logging
    local distro
    distro=$(detect_distribution)
    log_message "Detected distribution: $distro"
    
    # Security: Check available disk space before proceeding
    local available_space
    available_space=$(df /var/cache/apt/archives | awk 'NR==2 {print $4}')
    if [[ "$available_space" -lt 1048576 ]]; then  # Less than 1GB
        log_message "WARNING: Low disk space ($available_space KB available). Proceeding with caution."
    fi
    
    # Update package lists with retry mechanism
    log_message "Updating package lists..."
    local retry_count=0
    local max_retries=3
    
    while [[ $retry_count -lt $max_retries ]]; do
        if timeout 300 apt-get update -qq 2>&1 | tee -a "$LOG_FILE"; then
            log_message "Package lists updated successfully"
            break
        else
            ((retry_count++))
            log_message "WARNING: Package list update failed (attempt $retry_count/$max_retries)"
            if [[ $retry_count -lt $max_retries ]]; then
                log_message "Retrying in 30 seconds..."
                sleep 30
            else
                log_message "ERROR: Failed to update package lists after $max_retries attempts"
                return 1
            fi
        fi
    done
    
    # Check for available updates with error handling
    local updates_available
    if ! updates_available=$(apt list --upgradable 2>/dev/null | wc -l); then
        log_message "ERROR: Failed to check for available updates"
        return 1
    fi
    
    log_message "Available updates: $((updates_available - 1))"
    
    if [[ $updates_available -le 1 ]]; then
        log_message "No updates available"
        return 0
    fi
    
    # Security: Log which packages will be updated
    log_message "Packages to be updated:"
    apt list --upgradable 2>/dev/null | head -20 | tee -a "$LOG_FILE"
    
    # Check for excluded packages
    local exclude_args=""
    if [[ -n "${EXCLUDE_PACKAGES:-}" ]]; then
        log_message "Excluding packages from upgrade: $EXCLUDE_PACKAGES"
        for pkg in $EXCLUDE_PACKAGES; do
            exclude_args+=" --exclude=$pkg"
        done
    fi
    
    # Perform upgrade with timeout and error handling
    log_message "Performing package upgrades..."
    if ! timeout 1800 env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq $exclude_args 2>&1 | tee -a "$LOG_FILE"; then
        log_message "ERROR: Package upgrade failed"
        return 1
    fi
    
    # Perform dist-upgrade for dependency changes
    log_message "Performing distribution upgrade..."
    if ! timeout 1800 env DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -qq $exclude_args 2>&1 | tee -a "$LOG_FILE"; then
        log_message "WARNING: Distribution upgrade failed, but continuing"
    fi
    
    # Remove unnecessary packages with --purge for complete removal
    log_message "Removing unnecessary packages (with --purge)..."
    if ! timeout 300 apt-get autoremove --purge -y -qq 2>&1 | tee -a "$LOG_FILE"; then
        log_message "WARNING: autoremove --purge failed, but continuing"
    fi
    
    # Clean package cache
    log_message "Cleaning package cache..."
    if ! timeout 300 apt-get autoclean -qq 2>&1 | tee -a "$LOG_FILE"; then
        log_message "WARNING: autoclean failed, but continuing"
    fi
    
    # Additional cleanup for Kali Linux
    if [[ "$distro" == "kali" ]]; then
        log_message "Performing Kali-specific cleanup..."
        if ! timeout 300 apt-get clean -qq 2>&1 | tee -a "$LOG_FILE"; then
            log_message "WARNING: apt-get clean failed, but continuing"
        fi
    fi
    
    log_message "Update process completed successfully"
    return 0
}

# Main function
main() {
    # Set trap for cleanup
    trap cleanup EXIT
    
    # Check if running as root
    check_root_privileges
    
    # Check lock
    check_lock
    
    # Validate system state
    if ! validate_system_state; then
        send_notification "cron-apt: System Validation Failed" "System validation failed on $(hostname). Update process aborted."
        exit 1
    fi
    
    # Start update process
    log_message "=== Starting cron-apt automatic update process ==="
    log_message "Hostname: $(hostname)"
    log_message "System: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown Linux Distribution")"
    log_message "Distribution: $(detect_distribution)"
    log_message "cron-apt version: https://github.com/bidhata/cron-apt"
    
    # Perform updates
    if ! perform_updates; then
        send_notification "cron-apt: Update Failed" "Automatic updates failed on $(hostname). Please check the logs."
        exit 1
    fi
    
    # Restart services
    restart_services
    
    # Check if reboot is required
    if check_reboot_required; then
        if [[ "${AUTO_REBOOT:-false}" == "true" ]]; then
            send_notification "cron-apt: Auto-Update Completed - Auto-Reboot Initiated" "Automatic updates completed on $(hostname). System is rebooting automatically."
        else
            send_notification "cron-apt: Auto-Update Completed - Reboot Required" "Automatic updates completed on $(hostname). System reboot is required."
        fi
    else
        send_notification "cron-apt: Auto-Update Completed Successfully" "Automatic updates completed successfully on $(hostname). No reboot required."
    fi
    
    log_message "=== cron-apt automatic update process completed ==="
}

# Run main function
main "$@"
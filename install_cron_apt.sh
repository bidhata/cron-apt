#!/bin/bash

# cron-apt - Installation script for Automatic Update System
# Created by Krishnendu Paul (@bidhata)
# Repository: https://github.com/bidhata/cron-apt
# Run this script as root to set up automatic weekly updates

set -euo pipefail

# Function to check system compatibility
check_system_compatibility() {
    echo "Checking system compatibility..."
    
    # Check if systemd is available
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "ERROR: systemd is required but not found on this system."
        echo "cron-apt requires systemd for service management."
        exit 1
    fi
    
    # Check if apt is available
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "ERROR: apt package manager is required but not found."
        echo "cron-apt is designed for Ubuntu/Debian systems with apt."
        exit 1
    fi
    
    # Check distribution
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "Detected system: $PRETTY_NAME"
        
        case "$ID" in
            ubuntu|debian|kali)
                echo "✓ Compatible distribution detected"
                ;;
            *)
                echo "WARNING: Untested distribution ($ID). cron-apt is designed for Ubuntu/Debian."
                echo "Continue at your own risk."
                read -p "Do you want to continue? [y/N]: " -n 1 -r
                echo ""
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    exit 0
                fi
                ;;
        esac
    else
        echo "WARNING: Cannot detect distribution. Proceeding with installation..."
    fi
    
    echo ""
}

echo "Installing cron-apt - Automatic Update System for Ubuntu/Debian..."
echo "Created by Krishnendu Paul (@bidhata)"
echo "Repository: https://github.com/bidhata/cron-apt"
echo ""

# Function to check if running as root or with sudo
check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: This installation script must be run as root or with sudo privileges!"
        echo ""
        echo "The installer needs root access to:"
        echo "  • Create system files in /usr/local/bin and /etc"
        echo "  • Install required packages (needrestart, mailutils)"
        echo "  • Configure systemd services and timers"
        echo "  • Set up log rotation and permissions"
        echo ""
        echo "Please run with:"
        echo "  sudo bash $0"
        echo "  or"
        echo "  curl -fsSL https://raw.githubusercontent.com/bidhata/cron-apt/main/install_cron_apt.sh | sudo bash"
        echo ""
        exit 1
    fi
    
    # Show execution context
    if [[ -n "${SUDO_USER:-}" ]]; then
        echo "Running installation as root via sudo (original user: $SUDO_USER)"
    else
        echo "Running installation as root user"
    fi
    echo ""
}

# Function to check if cron-apt is already installed
check_existing_installation() {
    local already_installed=false
    local installed_files=()
    
    # Check for main script
    if [[ -f "/usr/local/bin/cron-apt.sh" ]]; then
        already_installed=true
        installed_files+=("/usr/local/bin/cron-apt.sh")
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
    
    # Check if timer is enabled
    local timer_enabled=false
    if systemctl is-enabled cron-apt.timer >/dev/null 2>&1; then
        timer_enabled=true
    fi
    
    if [[ "$already_installed" == true ]]; then
        echo "WARNING: cron-apt appears to be already installed!"
        echo ""
        echo "Found existing files:"
        for file in "${installed_files[@]}"; do
            echo "  • $file"
        done
        echo ""
        
        if [[ "$timer_enabled" == true ]]; then
            echo "Status: cron-apt timer is currently ENABLED and scheduled"
            systemctl list-timers cron-apt.timer --no-pager 2>/dev/null || true
        else
            echo "Status: cron-apt timer is currently DISABLED"
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
        echo ""
        read -p "Do you want to continue and reinstall cron-apt? [y/N]: " -n 1 -r
        echo ""
        
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Installation cancelled. Your existing cron-apt installation remains unchanged."
            echo ""
            echo "To manage your current installation:"
            echo "  • View status: systemctl status cron-apt.timer"
            echo "  • View logs: tail -f /var/log/cron-apt.log"
            echo "  • Run manually: sudo /usr/local/bin/cron-apt.sh"
            echo ""
            exit 0
        fi
        
        echo "Proceeding with reinstallation..."
        echo "Stopping existing services..."
        
        # Stop existing services gracefully
        if systemctl is-active --quiet cron-apt.timer 2>/dev/null; then
            systemctl stop cron-apt.timer
            echo "  • Stopped cron-apt.timer"
        fi
        
        if systemctl is-active --quiet cron-apt.service 2>/dev/null; then
            systemctl stop cron-apt.service
            echo "  • Stopped cron-apt.service"
        fi
        
        echo ""
    fi
}

# Check system compatibility
check_system_compatibility

# Check if running as root
check_root_privileges

# Check for existing installation
check_existing_installation

# Create the main script
echo "Creating cron-apt script..."
cat > /usr/local/bin/cron-apt.sh << 'EOF'
#!/bin/bash

# cron-apt - Automatic Update System for Ubuntu/Debian Servers
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

# Load configuration file if it exists
if [[ -f "$CONFIG_FILE" ]]; then
    # Security: Source config file safely
    if [[ -r "$CONFIG_FILE" ]] && [[ "$(stat -c %a "$CONFIG_FILE")" -le 644 ]]; then
        source "$CONFIG_FILE"
    else
        log_message "WARNING: Config file $CONFIG_FILE has unsafe permissions, ignoring"
    fi
fi

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
    echo $ > "$LOCK_FILE"
    chmod 644 "$LOCK_FILE" 2>/dev/null || true
}

# Function to cleanup on exit
cleanup() {
    rm -f "$LOCK_FILE"
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
    
    # Enhanced service list with more comprehensive coverage
    local -r services_to_check=(
        "apache2"
        "httpd" 
        "nginx"
        "mysql"
        "mariadb"
        "postgresql"
        "ssh"
        "sshd"
        "docker"
        "containerd"
        "systemd-resolved"
        "networking"
        "network-manager"
        "dbus"
        "cron"
        "rsyslog"
        "fail2ban"
        "ufw"
        "firewalld"
    )
    
    local restarted_count=0
    local failed_count=0
    
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
            fi
        fi
    done
    
    log_message "Service restart summary: $restarted_count restarted, $failed_count failed"
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
        
        # Check if auto-reboot is enabled (DANGEROUS!)
        if [[ "${AUTO_REBOOT:-false}" == "true" ]]; then
            log_message "WARNING: AUTO_REBOOT is enabled - initiating automatic reboot in 2 minutes..."
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
    
    # Perform upgrade with timeout and error handling
    log_message "Performing package upgrades..."
    if ! timeout 1800 env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq 2>&1 | tee -a "$LOG_FILE"; then
        log_message "ERROR: Package upgrade failed"
        return 1
    fi
    
    # Perform dist-upgrade for dependency changes
    log_message "Performing distribution upgrade..."
    if ! timeout 1800 env DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -qq 2>&1 | tee -a "$LOG_FILE"; then
        log_message "WARNING: Distribution upgrade failed, but continuing"
    fi
    
    # Remove unnecessary packages
    log_message "Removing unnecessary packages..."
    if ! timeout 300 apt-get autoremove -y -qq 2>&1 | tee -a "$LOG_FILE"; then
        log_message "WARNING: autoremove failed, but continuing"
    fi
    
    # Clean package cache
    log_message "Cleaning package cache..."
    if ! timeout 300 apt-get autoclean -qq 2>&1 | tee -a "$LOG_FILE"; then
        log_message "WARNING: autoclean failed, but continuing"
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
    log_message "System: $(lsb_release -d | cut -f2)"
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
        send_notification "cron-apt: Auto-Update Completed - Reboot Required" "Automatic updates completed on $(hostname). System reboot is required."
    else
        send_notification "cron-apt: Auto-Update Completed Successfully" "Automatic updates completed successfully on $(hostname). No reboot required."
    fi
    
    log_message "=== cron-apt automatic update process completed ==="
}

# Run main function
main "$@"
EOF

# Make the script executable
chmod +x /usr/local/bin/cron-apt.sh

# Create systemd service file with enhanced security
echo "Creating systemd service with enhanced security settings..."
cat > /etc/systemd/system/cron-apt.service << 'EOF'
[Unit]
Description=cron-apt - Automatic System Update Service
Documentation=https://github.com/bidhata/cron-apt
After=network-online.target time-sync.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cron-apt.sh
User=root
Group=root
StandardOutput=journal
StandardError=journal

# Security settings - Enhanced hardening
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=false
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
SystemCallFilter=~@debug @mount @cpu-emulation @obsolete @privileged @reboot @swap
SystemCallErrorNumber=EPERM

# Capabilities
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETUID CAP_SETGID CAP_SYS_ADMIN CAP_KILL
AmbientCapabilities=

# Resource limits
TasksMax=100
MemoryMax=1G
CPUQuota=50%

# Timeout settings
TimeoutStartSec=1800
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer file for weekly execution
echo "Creating systemd timer..."
cat > /etc/systemd/system/cron-apt.timer << 'EOF'
[Unit]
Description=cron-apt - Run automatic updates weekly
Documentation=https://github.com/bidhata/cron-apt
Requires=cron-apt.service

[Timer]
# Run every Sunday at 2:00 AM
OnCalendar=Sun *-*-* 02:00:00
# Run 10 minutes after boot if the system was off during scheduled time
Persistent=true
# Add some randomization to avoid all servers updating at exactly the same time
RandomizedDelaySec=1800

[Install]
WantedBy=timers.target
EOF

# Create log rotation configuration
echo "Creating log rotation configuration..."
cat > /etc/logrotate.d/cron-apt << 'EOF'
/var/log/cron-apt.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        /bin/systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

# Create configuration directory and example config
echo "Creating configuration directory..."
mkdir -p /etc/cron-apt
chmod 755 /etc/cron-apt

# Create example configuration file
cat > /etc/cron-apt/config.example << 'EOF'
# cron-apt Configuration File
# Copy this to /etc/cron-apt/config and modify as needed

# Email notifications (optional)
# EMAIL_RECIPIENT="admin@example.com"

# Maximum log file size before rotation
# MAX_LOG_SIZE="10M"

# Additional services to restart (space-separated)
# CUSTOM_SERVICES="your-service1 your-service2"

# Skip certain package upgrades (space-separated package names)
# EXCLUDE_PACKAGES="package1 package2"

# Enable verbose logging (true/false)
# VERBOSE_LOGGING="false"

# Reboot automatically if required (DANGEROUS - use with caution)
# AUTO_REBOOT="false"
EOF

chmod 644 /etc/cron-apt/config.example

# Create uninstall script
echo "Creating uninstall script..."
cat > /usr/local/bin/uninstall-cron-apt.sh << 'EOF'
#!/bin/bash
# cron-apt Uninstaller
# Created by Krishnendu Paul (@bidhata)

set -euo pipefail

echo "cron-apt Uninstaller"
echo "===================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root"
    echo "Usage: sudo /usr/local/bin/uninstall-cron-apt.sh"
    exit 1
fi

echo "This will completely remove cron-apt from your system."
echo ""
read -p "Are you sure you want to continue? [y/N]: " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstallation cancelled."
    exit 0
fi

echo "Uninstalling cron-apt..."

# Stop and disable services
echo "  • Stopping services..."
systemctl stop cron-apt.timer 2>/dev/null || true
systemctl stop cron-apt.service 2>/dev/null || true
systemctl disable cron-apt.timer 2>/dev/null || true

# Remove systemd files
echo "  • Removing systemd files..."
rm -f /etc/systemd/system/cron-apt.service
rm -f /etc/systemd/system/cron-apt.timer
systemctl daemon-reload

# Remove scripts and configuration
echo "  • Removing scripts and configuration..."
rm -f /usr/local/bin/cron-apt.sh
rm -rf /etc/cron-apt

# Remove logs and temporary files
echo "  • Removing logs..."
rm -f /var/log/cron-apt.log*
rm -f /var/run/cron-apt.lock
rm -f /etc/logrotate.d/cron-apt

# Remove this uninstaller
rm -f /usr/local/bin/uninstall-cron-apt.sh

echo ""
echo "✓ cron-apt has been completely removed from your system."
echo ""
echo "Note: The packages 'needrestart' and 'mailutils' were not removed"
echo "as they may be used by other applications."
echo ""
EOF

chmod +x /usr/local/bin/uninstall-cron-apt.sh

# Initialize log file
touch /var/log/cron-apt.log
chown root:root /var/log/cron-apt.log
chmod 644 /var/log/cron-apt.log

# Create initial log entry
echo "[$(date '+%Y-%m-%d %H:%M:%S')] cron-apt installed successfully" >> /var/log/cron-apt.log

# Install required packages
echo "Installing required packages..."
echo "This may take a few minutes depending on your internet connection..."

# Update package lists first
if ! apt-get update -qq; then
    echo "ERROR: Failed to update package lists. Please check your internet connection."
    exit 1
fi

# Install packages with error checking
if ! apt-get install -y needrestart mailutils; then
    echo "ERROR: Failed to install required packages. Please check your package manager configuration."
    exit 1
fi

echo "Required packages installed successfully."

# Reload systemd and enable services
echo "Enabling and starting cron-apt services..."
if ! systemctl daemon-reload; then
    echo "ERROR: Failed to reload systemd daemon"
    exit 1
fi

if ! systemctl enable cron-apt.timer; then
    echo "ERROR: Failed to enable cron-apt.timer"
    exit 1
fi

if ! systemctl start cron-apt.timer; then
    echo "ERROR: Failed to start cron-apt.timer"
    exit 1
fi

echo "Services enabled and started successfully."

# Verify installation
echo ""
echo "Verifying installation..."
installation_success=true

# Check if files exist
required_files=(
    "/usr/local/bin/cron-apt.sh"
    "/etc/systemd/system/cron-apt.service"
    "/etc/systemd/system/cron-apt.timer"
    "/var/log/cron-apt.log"
    "/etc/logrotate.d/cron-apt"
)

for file in "${required_files[@]}"; do
    if [[ -f "$file" ]]; then
        echo "✓ $file"
    else
        echo "✗ $file (missing)"
        installation_success=false
    fi
done

# Check if timer is enabled and active
if systemctl is-enabled cron-apt.timer >/dev/null 2>&1; then
    echo "✓ cron-apt.timer is enabled"
else
    echo "✗ cron-apt.timer is not enabled"
    installation_success=false
fi

if systemctl is-active cron-apt.timer >/dev/null 2>&1; then
    echo "✓ cron-apt.timer is active"
else
    echo "✗ cron-apt.timer is not active"
    installation_success=false
fi

if [[ "$installation_success" == false ]]; then
    echo ""
    echo "ERROR: Installation verification failed!"
    echo "Some components may not have been installed correctly."
    echo "Please check the error messages above and try reinstalling."
    exit 1
fi

echo ""
echo "✓ Installation verification completed successfully!"

# Show status
echo ""
echo "=== cron-apt Installation Complete ==="
echo ""
echo "Created by: Krishnendu Paul (@bidhata)"
echo "Repository: https://github.com/bidhata/cron-apt"
echo ""
echo "cron-apt has been installed and configured successfully!"
echo ""
echo "Service status:"
systemctl status cron-apt.timer --no-pager -l
echo ""
echo "Next scheduled run:"
systemctl list-timers cron-apt.timer --no-pager
echo ""
echo "Useful commands:"
echo "  - Check timer status: systemctl status cron-apt.timer"
echo "  - View logs: tail -f /var/log/cron-apt.log"
echo "  - Run update manually: sudo /usr/local/bin/cron-apt.sh"
echo "  - Disable auto-updates: sudo systemctl disable cron-apt.timer"
echo "  - Stop timer: sudo systemctl stop cron-apt.timer"
echo "  - Uninstall cron-apt: sudo /usr/local/bin/uninstall-cron-apt.sh"
echo ""
echo "Configuration:"
echo "  - Script location: /usr/local/bin/cron-apt.sh"
echo "  - Config directory: /etc/cron-apt/"
echo "  - Example config: /etc/cron-apt/config.example"
echo "  - Log file: /var/log/cron-apt.log"
echo "  - Uninstaller: /usr/local/bin/uninstall-cron-apt.sh"
echo "  - Runs every Sunday at 2:00 AM (with random delay up to 30 minutes)"
echo ""
echo "Security Features:"
echo "  - Enhanced systemd hardening with restricted capabilities"
echo "  - Secure PATH and umask settings"
echo "  - Input validation and sanitization"
echo "  - Resource limits and timeouts"
echo "  - System state validation before updates"
echo ""
echo "To configure cron-apt:"
echo "  1. Copy example config: sudo cp /etc/cron-apt/config.example /etc/cron-apt/config"
echo "  2. Edit configuration: sudo nano /etc/cron-apt/config"
echo "  3. Set EMAIL_RECIPIENT for notifications"
echo ""
echo "WARNING: The system may automatically restart services after updates."
echo "For automatic reboots when required, set AUTO_REBOOT=true in config (use with caution)."
echo ""
echo "=== Single Command Installation (for sharing) ==="
echo ""
echo "To install cron-apt on other servers, use this command:"
echo ""
echo "curl -fsSL https://raw.githubusercontent.com/bidhata/cron-apt/main/install_cron_apt.sh | sudo bash"
echo ""
echo "Or download and run locally:"
echo "wget https://raw.githubusercontent.com/bidhata/cron-apt/main/install_cron_apt.sh"
echo "sudo bash install_cron_apt.sh"
echo ""
echo "The system will then automatically:"
echo "1. Update packages every Sunday at 2:00 AM"
echo "2. Restart services that need restarting"
echo "3. Log all activities to /var/log/cron-apt.log"
echo "4. Notify about required reboots (but won't reboot automatically for safety)"
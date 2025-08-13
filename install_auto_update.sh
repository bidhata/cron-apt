#!/bin/bash

# Installation script for Auto Update System
# Run this script as root to set up automatic weekly updates

set -euo pipefail

echo "Installing Auto Update System for Ubuntu/Debian..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root"
    echo "Usage: sudo bash install-auto-update.sh"
    exit 1
fi

# Create the main script
echo "Creating auto-update script..."
cat > /usr/local/bin/auto-update.sh << 'EOF'
#!/bin/bash

# Auto Update System for Ubuntu/Debian Servers
# This script automatically updates the system weekly and restarts services as needed

set -euo pipefail

# Configuration
LOG_FILE="/var/log/auto-update.log"
LOCK_FILE="/var/run/auto-update.lock"
REBOOT_REQUIRED_FILE="/var/run/reboot-required"
EMAIL_RECIPIENT=""  # Set email for notifications (optional)

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to send notification (if email is configured)
send_notification() {
    local subject="$1"
    local message="$2"
    
    if [[ -n "$EMAIL_RECIPIENT" ]] && command -v mail >/dev/null 2>&1; then
        echo "$message" | mail -s "$subject" "$EMAIL_RECIPIENT"
    fi
}

# Function to check if another update is running
check_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid=$(cat "$LOCK_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            log_message "ERROR: Another update process is already running (PID: $pid)"
            exit 1
        else
            log_message "WARNING: Stale lock file found, removing it"
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
}

# Function to cleanup on exit
cleanup() {
    rm -f "$LOCK_FILE"
}

# Function to restart services that need restarting
restart_services() {
    log_message "Checking for services that need restarting..."
    
    # Check if needrestart is available
    if command -v needrestart >/dev/null 2>&1; then
        log_message "Using needrestart to identify services..."
        needrestart -r a -m a 2>&1 | tee -a "$LOG_FILE"
    else
        log_message "needrestart not available, installing it..."
        apt-get update -qq
        apt-get install -y needrestart
        needrestart -r a -m a 2>&1 | tee -a "$LOG_FILE"
    fi
    
    # Common services that often need restarting after updates
    local services_to_check=(
        "apache2"
        "nginx"
        "mysql"
        "mariadb"
        "postgresql"
        "ssh"
        "sshd"
        "docker"
        "systemd-resolved"
        "networking"
    )
    
    for service in "${services_to_check[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            if systemctl is-enabled --quiet "$service" 2>/dev/null; then
                log_message "Restarting service: $service"
                systemctl restart "$service" && log_message "Successfully restarted $service" || log_message "Failed to restart $service"
            fi
        fi
    done
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
        
        send_notification "Server Reboot Required" "The server $(hostname) requires a reboot after automatic updates. Please schedule a maintenance window."
        
        # Uncomment the following line if you want automatic reboot (DANGEROUS!)
        # log_message "Initiating automatic reboot in 2 minutes..."
        # shutdown -r +2 "System will reboot in 2 minutes due to automatic updates"
        
        return 0
    else
        log_message "No reboot required"
        return 1
    fi
}

# Function to perform system updates
perform_updates() {
    log_message "Starting automatic system update process..."
    
    # Update package lists
    log_message "Updating package lists..."
    apt-get update -qq 2>&1 | tee -a "$LOG_FILE"
    
    # Check for available updates
    local updates_available=$(apt list --upgradable 2>/dev/null | wc -l)
    log_message "Available updates: $((updates_available - 1))"
    
    if [[ $updates_available -le 1 ]]; then
        log_message "No updates available"
        return 0
    fi
    
    # Perform upgrade
    log_message "Performing package upgrades..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq 2>&1 | tee -a "$LOG_FILE"
    
    # Perform dist-upgrade for dependency changes
    log_message "Performing distribution upgrade..."
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -qq 2>&1 | tee -a "$LOG_FILE"
    
    # Remove unnecessary packages
    log_message "Removing unnecessary packages..."
    apt-get autoremove -y -qq 2>&1 | tee -a "$LOG_FILE"
    
    # Clean package cache
    log_message "Cleaning package cache..."
    apt-get autoclean -qq 2>&1 | tee -a "$LOG_FILE"
    
    log_message "Update process completed successfully"
}

# Main function
main() {
    # Set trap for cleanup
    trap cleanup EXIT
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR: This script must be run as root"
        exit 1
    fi
    
    # Check lock
    check_lock
    
    # Start update process
    log_message "=== Starting automatic update process ==="
    log_message "Hostname: $(hostname)"
    log_message "System: $(lsb_release -d | cut -f2)"
    
    # Perform updates
    perform_updates
    
    # Restart services
    restart_services
    
    # Check if reboot is required
    if check_reboot_required; then
        send_notification "Auto-Update Completed - Reboot Required" "Automatic updates completed on $(hostname). System reboot is required."
    else
        send_notification "Auto-Update Completed Successfully" "Automatic updates completed successfully on $(hostname). No reboot required."
    fi
    
    log_message "=== Automatic update process completed ==="
}

# Run main function
main "$@"
EOF

# Make the script executable
chmod +x /usr/local/bin/auto-update.sh

# Create systemd service file
echo "Creating systemd service..."
cat > /etc/systemd/system/auto-update.service << 'EOF'
[Unit]
Description=Automatic System Update Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/auto-update.sh
User=root
Group=root
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=false
ProtectHome=true
RestrictRealtime=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer file for weekly execution
echo "Creating systemd timer..."
cat > /etc/systemd/system/auto-update.timer << 'EOF'
[Unit]
Description=Run auto-update weekly
Requires=auto-update.service

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
cat > /etc/logrotate.d/auto-update << 'EOF'
/var/log/auto-update.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF

# Install required packages
echo "Installing required packages..."
apt-get update -qq
apt-get install -y needrestart mailutils

# Initialize log file
touch /var/log/auto-update.log
chown root:root /var/log/auto-update.log
chmod 644 /var/log/auto-update.log

# Reload systemd and enable services
echo "Enabling and starting services..."
systemctl daemon-reload
systemctl enable auto-update.timer
systemctl start auto-update.timer

# Show status
echo ""
echo "=== Installation Complete ==="
echo ""
echo "Auto-update system has been installed and configured!"
echo ""
echo "Service status:"
systemctl status auto-update.timer --no-pager -l
echo ""
echo "Next scheduled run:"
systemctl list-timers auto-update.timer --no-pager
echo ""
echo "Useful commands:"
echo "  - Check timer status: systemctl status auto-update.timer"
echo "  - View logs: tail -f /var/log/auto-update.log"
echo "  - Run update manually: sudo /usr/local/bin/auto-update.sh"
echo "  - Disable auto-updates: sudo systemctl disable auto-update.timer"
echo "  - Stop timer: sudo systemctl stop auto-update.timer"
echo ""
echo "Configuration:"
echo "  - Script location: /usr/local/bin/auto-update.sh"
echo "  - Log file: /var/log/auto-update.log"
echo "  - Runs every Sunday at 2:00 AM (with random delay up to 30 minutes)"
echo ""
echo "To configure email notifications, edit /usr/local/bin/auto-update.sh"
echo "and set the EMAIL_RECIPIENT variable."
echo ""
echo "WARNING: The system may automatically restart services after updates."
echo "For automatic reboots when required, uncomment the reboot line in the script."
EOF

# Make the installation script executable
chmod +x install-auto-update.sh

echo ""
echo "=== Single Command Installation ==="
echo ""
echo "To install and set up the auto-update system, run this single command as root:"
echo ""
echo "curl -fsSL https://raw.githubusercontent.com/bidhata/cron-apt/main/install_auto_update.sh | sudo bash"
echo ""
echo "Or download and run locally:"
echo "sudo bash install-auto-update.sh"
echo ""
echo "The system will then automatically:"
echo "1. Update packages every Sunday at 2:00 AM"
echo "2. Restart services that need restarting"
echo "3. Log all activities to /var/log/auto-update.log"
echo "4. Notify about required reboots (but won't reboot automatically for safety)"

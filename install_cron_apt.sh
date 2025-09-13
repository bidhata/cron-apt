# Create systemd service file with enhanced security
echo "Creating systemd service with enhanced security settings..."
cat > /etc/systemd/system/cron-apt.service << 'EOF'
[Unit]
Description=cron-apt - Automatic System Update Service for Ubuntu/Debian/Kali
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
Description=cron-apt - Run automatic updates weekly (Ubuntu/Debian/Kali)
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

# Create example configuration file
cat > /etc/cron-apt/config.example << 'EOF'
# cron-apt Configuration File - Example
# Copy settings from this file to /etc/cron-apt/config as needed

# Email notifications (optional)
# EMAIL_RECIPIENT="admin@example.com"

# Maximum log file size before rotation
# MAX_LOG_SIZE="10M"

# Enable automatic reboot when required (use with caution)
# AUTO_REBOOT="false"

# Additional services to restart (space-separated)
# CUSTOM_SERVICES="your-service1 your-service2"

# Skip certain package upgrades (space-separated package names)
# EXCLUDE_PACKAGES="package1 package2"

# Enable verbose logging (true/false)
# VERBOSE_LOGGING="false"

# Distribution-specific settings for Kali Linux
# For Kali, you might want to exclude certain packages:
# EXCLUDE_PACKAGES="kali-linux-everything kali-tools-top10"
EOF

chmod 644 /etc/cron-apt/config.example

# Create enhanced uninstall script
echo "Creating uninstall script..."
cat > /usr/local/bin/uninstall-cron-apt.sh << 'EOF'
#!/bin/bash
# cron-apt Uninstaller - Enhanced Version
# Created by Krishnendu Paul (@bidhata)
# Supports Ubuntu/Debian/Kali Linux

set -euo pipefail

echo "cron-apt Uninstaller for Ubuntu/Debian/Kali Linux"
echo "=================================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root"
    echo "Usage: sudo /usr/local/bin/uninstall-cron-apt.sh"
    exit 1
fi

echo "This will completely remove cron-apt from your system."
echo "All configuration files, logs, and scheduled updates will be removed."
echo ""

# Show current status
if systemctl is-enabled cron-apt.timer >/dev/null 2>&1; then
    echo "Current status: cron-apt is ACTIVE and scheduled"
    systemctl list-timers cron-apt.timer --no-pager 2>/dev/null || true
else
    echo "Current status: cron-apt is not active"
fi

echo ""
read -p "Are you sure you want to continue? [y/N]: " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstallation cancelled."
    exit 0
fi

echo "Uninstalling cron-apt..."

# Stop and disable services
echo "  • Stopping and disabling services..."
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
echo "  • Removing logs and temporary files..."
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
echo "Your system will no longer receive automatic updates."
echo "Remember to manually update your system regularly with:"
echo "  sudo apt update && sudo apt upgrade"
echo ""
EOF

chmod +x /usr/local/bin/uninstall-cron-apt.sh

# Initialize log file
touch /var/log/cron-apt.log
chown root:root /var/log/cron-apt.log
chmod 644 /var/log/cron-apt.log

# Create initial log entry
echo "[$(date '+%Y-%m-%d %H:%M:%S')] cron-apt installed successfully with AUTO_REBOOT=$AUTO_REBOOT_SETTING" >> /var/log/cron-apt.log

# Install required packages
echo "Installing required packages..."
echo "This may take a few minutes depending on your internet connection..."

# Update package lists first
if ! apt-get update -qq; then
    echo "ERROR: Failed to update package lists. Please check your internet connection."
    exit 1
fi

# Install packages with error checking
echo "Installing needrestart and mailutils..."
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
    "/etc/cron-apt/config"
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
echo "Configuration Summary:"
echo "  • Auto-reboot: $AUTO_REBOOT_SETTING"#!/bin/bash

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
        echo "cron-apt is designed for Ubuntu/Debian/Kali systems with apt."
        exit 1
    fi
    
    # Check distribution
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "Detected system: $PRETTY_NAME"
        
        case "$ID" in
            ubuntu|debian|kali)
                echo "✓ Compatible distribution detected"
                if [[ "$ID" == "kali" ]]; then
                    echo "  Kali Linux specific optimizations will be applied"
                fi
                ;;
            *)
                echo "WARNING: Untested distribution ($ID). cron-apt is designed for Ubuntu/Debian/Kali."
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

echo "Installing cron-apt - Automatic Update System for Ubuntu/Debian/Kali Linux..."
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

# Function to ask about auto-reboot preference
ask_auto_reboot_preference() {
    echo "AUTO-REBOOT CONFIGURATION"
    echo "========================="
    echo ""
    echo "Some system updates require a reboot to take effect (kernel updates, etc.)."
    echo "You can configure cron-apt to automatically reboot the system when needed."
    echo ""
    echo "WARNING: Auto-reboot will restart your server automatically without manual intervention!"
    echo ""
    echo "Options:"
    echo "  1. Enable auto-reboot (recommended for development/testing servers)"
    echo "  2. Disable auto-reboot (recommended for production servers)"
    echo ""
    echo "You can always change this later by editing /etc/cron-apt/config"
    echo ""
    
    while true; do
        read -p "Enable automatic reboot when required? [Y/n]: " -n 1 -r
        echo ""
        
        case $REPLY in
            [Yy]|"")
                AUTO_REBOOT_SETTING="true"
                echo "✓ Auto-reboot ENABLED"
                echo "  The system will automatically reboot when updates require it."
                break
                ;;
            [Nn])
                AUTO_REBOOT_SETTING="false"
                echo "✓ Auto-reboot DISABLED"
                echo "  The system will send notifications but won't reboot automatically."
                break
                ;;
            *)
                echo "Please answer Y (yes) or N (no)."
                ;;
        esac
    done
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

# Ask about auto-reboot preference
ask_auto_reboot_preference

# Create the main script
echo "Creating enhanced cron-apt script..."
cat > /usr/local/bin/cron-apt.sh << 'EOF'
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
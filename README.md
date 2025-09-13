# cron-apt - Automatic Update System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![SystemD](https://img.shields.io/badge/SystemD-Enabled-blue.svg)](https://systemd.io/)

**cron-apt** is a robust, secure, and comprehensive automatic update system designed specifically for Ubuntu, Debian, and Kali Linux servers. It provides automated weekly system updates with intelligent service management, comprehensive logging, and optional email notifications.

## Table of Contents

- [Features](#features)
- [Supported Distributions](#supported-distributions)
- [Quick Installation](#quick-installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security Features](#security-features)
- [Logging and Monitoring](#logging-and-monitoring)
- [Service Management](#service-management)
- [Uninstallation](#uninstallation)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

### ✨ Core Features

- **Automated Updates**: Weekly automatic system updates via systemd timer
- **Service Management**: Intelligent restart of affected services using `needrestart`
- **Reboot Detection**: Automatic detection when system reboot is required
- **Email Notifications**: Optional email alerts for update status and reboot requirements
- **Enhanced Security**: Comprehensive security hardening throughout the entire system
- **Comprehensive Logging**: Detailed logging with automatic rotation
- **Distribution Detection**: Optimized for Ubuntu, Debian, and Kali Linux
- **Resource Management**: Built-in resource limits and timeout protection

### 🔒 Security Features

- **Secure PATH**: Prevents path hijacking attacks
- **Process Isolation**: SystemD security sandboxing
- **Lock File Management**: Prevents concurrent execution
- **Input Validation**: All inputs are sanitized and validated
- **Permission Checks**: Strict file permission validation
- **Resource Limits**: CPU, memory, and task limitations
- **System Call Filtering**: Restricted system call access

### 🛠 Advanced Features

- **System State Validation**: Pre-update system health checks
- **Retry Mechanisms**: Automatic retry for failed operations
- **Disk Space Monitoring**: Prevents updates when disk space is low
- **Load Average Monitoring**: System load awareness
- **Memory Usage Tracking**: Low memory detection and warnings
- **Package Exclusion**: Ability to exclude specific packages from updates
- **Custom Service Support**: Configure additional services to restart

## Supported Distributions

| Distribution | Version | Status |
|-------------|---------|---------|
| Ubuntu | 18.04+ | ✅ Fully Supported |
| Ubuntu | 20.04+ | ✅ Fully Supported |
| Ubuntu | 22.04+ | ✅ Fully Supported |
| Debian | 10+ | ✅ Fully Supported |
| Debian | 11+ | ✅ Fully Supported |
| Debian | 12+ | ✅ Fully Supported |
| Kali Linux | 2020+ | ✅ Fully Supported |
| Other Debian-based | Various | ⚠️ May work but untested |

## Quick Installation

### One-Line Installation

```bash
curl -fsSL https://raw.githubusercontent.com/bidhata/cron-apt/main/install_cron_apt.sh | sudo bash
```

### Manual Installation

```bash
# Download the installer
wget https://raw.githubusercontent.com/bidhata/cron-apt/main/install_cron_apt.sh

# Make it executable
chmod +x install_cron_apt.sh

# Run the installer
sudo ./install_cron_apt.sh
```

### Installation Process

The installer will:

1. **Check system compatibility** and detect your Linux distribution
2. **Verify root privileges** (required for system-level operations)
3. **Detect existing installations** and offer to upgrade
4. **Configure auto-reboot preference** (interactive prompt)
5. **Install required packages** (`needrestart`, `mailutils`)
6. **Create system files** and configure permissions
7. **Enable systemd services** and start the timer
8. **Verify installation** and show status

## Configuration

### Main Configuration File

After installation, customize your settings by creating `/etc/cron-apt/config`:

```bash
# Copy the example configuration
sudo cp /etc/cron-apt/config.example /etc/cron-apt/config

# Edit the configuration
sudo nano /etc/cron-apt/config
```

### Configuration Options

```bash
# Email notifications (optional)
EMAIL_RECIPIENT="admin@example.com"

# Maximum log file size before rotation
MAX_LOG_SIZE="10M"

# Enable automatic reboot when required (use with caution)
AUTO_REBOOT="false"

# Additional services to restart (space-separated)
CUSTOM_SERVICES="nginx apache2 mysql"

# Skip certain package upgrades (space-separated package names)
EXCLUDE_PACKAGES="kernel-image linux-image"

# Enable verbose logging (true/false)
VERBOSE_LOGGING="false"
```

### Kali Linux Specific Configuration

For Kali Linux systems, you might want to exclude certain packages:

```bash
# Prevent upgrading large metapackages that might change tools
EXCLUDE_PACKAGES="kali-linux-everything kali-tools-top10"

# Custom services common in Kali
CUSTOM_SERVICES="tor privoxy apache2 mysql postgresql"
```

## Usage

### View Current Status

```bash
# Check if cron-apt is running and scheduled
sudo systemctl status cron-apt.timer
sudo systemctl list-timers cron-apt.timer

# View recent logs
sudo tail -f /var/log/cron-apt.log

# Check last execution
sudo journalctl -u cron-apt.service --no-pager -l
```

### Manual Execution

```bash
# Run updates manually
sudo /usr/local/bin/cron-apt.sh

# Run with verbose output
sudo bash -x /usr/local/bin/cron-apt.sh
```

### Schedule Modification

The default schedule runs every Sunday at 2:00 AM. To modify:

```bash
# Edit the timer
sudo systemctl edit cron-apt.timer

# Add custom schedule (example: daily at 3 AM)
[Timer]
OnCalendar=
OnCalendar=*-*-* 03:00:00
```

### Service Management

```bash
# Enable/disable automatic updates
sudo systemctl enable cron-apt.timer   # Enable
sudo systemctl disable cron-apt.timer  # Disable

# Start/stop the timer
sudo systemctl start cron-apt.timer    # Start
sudo systemctl stop cron-apt.timer     # Stop

# Restart the timer (apply configuration changes)
sudo systemctl restart cron-apt.timer
```

## Security Features

### SystemD Security Hardening

The service runs with comprehensive security restrictions:

- **NoNewPrivileges**: Prevents privilege escalation
- **PrivateTmp**: Isolated temporary directory
- **ProtectSystem**: System directory protection
- **ProtectHome**: User home directory protection
- **RestrictRealtime**: Blocks realtime scheduling
- **SystemCallFilter**: Restricted system call access
- **CapabilityBoundingSet**: Limited capabilities

### File Security

- **Secure PATH**: Prevents binary hijacking
- **Permission Validation**: All files checked for safe permissions
- **Input Sanitization**: All user inputs are sanitized
- **Log Injection Prevention**: Protects against log manipulation

### Network Security

- **Timeout Protection**: All network operations have timeouts
- **Package Verification**: Uses APT's built-in signature verification
- **Secure DNS**: Respects system DNS configuration

## Logging and Monitoring

### Log Location

Primary log file: `/var/log/cron-apt.log`

### Log Format

```
[2024-01-15 02:00:01] Starting cron-apt automatic system update process...
[2024-01-15 02:00:02] Detected distribution: ubuntu
[2024-01-15 02:00:03] Updating package lists...
[2024-01-15 02:00:15] Package lists updated successfully
[2024-01-15 02:00:16] Available updates: 23
[2024-01-15 02:00:45] Update process completed successfully
[2024-01-15 02:01:00] Service restart summary: 5 restarted, 0 failed, 2 skipped
[2024-01-15 02:01:01] No reboot required
```

### Log Rotation

Logs are automatically rotated:
- **Frequency**: Weekly
- **Retention**: 12 weeks
- **Compression**: Enabled
- **Configuration**: `/etc/logrotate.d/cron-apt`

### Monitoring Integration

#### Nagios/Icinga Check

```bash
#!/bin/bash
# Check cron-apt status
if systemctl is-active --quiet cron-apt.timer; then
    echo "OK - cron-apt timer is active"
    exit 0
else
    echo "CRITICAL - cron-apt timer is not active"
    exit 2
fi
```

#### Prometheus Metrics

Create a custom exporter to monitor cron-apt logs:

```bash
# Example: Count recent update failures
grep -c "ERROR" /var/log/cron-apt.log | tail -1
```

## Service Management

### Automatic Service Restart

cron-apt automatically restarts services affected by updates:

#### Default Services Monitored

**Ubuntu/Debian:**
- apache2, httpd, nginx
- mysql, mariadb, postgresql
- ssh, sshd, openssh-server
- docker, containerd
- systemd-resolved, networking, network-manager
- dbus, cron, rsyslog
- fail2ban, ufw, firewalld
- snapd

**Kali Linux (additional):**
- tor, privoxy

#### Adding Custom Services

```bash
# Edit configuration
echo 'CUSTOM_SERVICES="your-service1 your-service2"' | sudo tee -a /etc/cron-apt/config
```

### Reboot Management

#### Detection

The system automatically detects when a reboot is required by checking:
- `/var/run/reboot-required`
- `/var/run/reboot-required.pkgs`

#### Notification

When reboot is required:
- **Log Entry**: Recorded in cron-apt log
- **Email Alert**: Sent if configured
- **Package List**: Shows which packages require reboot

#### Auto-Reboot

**⚠️ Use with extreme caution!**

```bash
# Enable auto-reboot (not recommended for production)
echo 'AUTO_REBOOT="true"' | sudo tee -a /etc/cron-apt/config
```

## Uninstallation

### Quick Uninstall

```bash
# Run the uninstaller (created during installation)
sudo /usr/local/bin/uninstall-cron-apt.sh
```

### Manual Uninstall

```bash
# Stop and disable services
sudo systemctl stop cron-apt.timer
sudo systemctl disable cron-apt.timer

# Remove files
sudo rm -f /usr/local/bin/cron-apt.sh
sudo rm -f /etc/systemd/system/cron-apt.{service,timer}
sudo rm -rf /etc/cron-apt
sudo rm -f /var/log/cron-apt.log*
sudo rm -f /etc/logrotate.d/cron-apt

# Reload systemd
sudo systemctl daemon-reload
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied

```bash
# Check file permissions
ls -la /usr/local/bin/cron-apt.sh
# Should be: -rwxr-xr-x root root

# Fix if needed
sudo chmod 755 /usr/local/bin/cron-apt.sh
sudo chown root:root /usr/local/bin/cron-apt.sh
```

#### 2. Timer Not Running

```bash
# Check timer status
sudo systemctl status cron-apt.timer

# Check if enabled
sudo systemctl is-enabled cron-apt.timer

# Restart if needed
sudo systemctl restart cron-apt.timer
```

#### 3. Email Notifications Not Working

```bash
# Test mail configuration
echo "Test email" | mail -s "Test" your-email@example.com

# Install mail utilities if missing
sudo apt update && sudo apt install -y mailutils
```

#### 4. Updates Failing

```bash
# Check available disk space
df -h /var/cache/apt/archives

# Clean package cache
sudo apt clean

# Check for held packages
apt-mark showhold

# Run manual update to see errors
sudo /usr/local/bin/cron-apt.sh
```

#### 5. Lock File Issues

```bash
# Check for stale lock file
ls -la /var/run/cron-apt.lock

# Remove if stale (no process running)
sudo rm -f /var/run/cron-apt.lock
```

### Debug Mode

```bash
# Run with debug output
sudo bash -x /usr/local/bin/cron-apt.sh 2>&1 | tee debug.log
```

### Logs Analysis

```bash
# Check for errors
sudo grep -i error /var/log/cron-apt.log

# Check for warnings
sudo grep -i warning /var/log/cron-apt.log

# View update history
sudo grep "Update process completed" /var/log/cron-apt.log

# Check reboot requirements
sudo grep "reboot" /var/log/cron-apt.log
```

### System Requirements Check

```bash
# Check systemd version
systemctl --version

# Check available memory
free -h

# Check disk space
df -h

# Check load average
uptime
```

## Best Practices

### Production Servers

1. **Disable auto-reboot**: `AUTO_REBOOT="false"`
2. **Configure email notifications**: Set `EMAIL_RECIPIENT`
3. **Test in staging first**: Verify updates in non-production environment
4. **Monitor logs regularly**: Set up log monitoring
5. **Exclude critical packages**: Use `EXCLUDE_PACKAGES` for sensitive software

### Development/Testing Servers

1. **Enable auto-reboot**: `AUTO_REBOOT="true"` for convenience
2. **Shorter retention**: Adjust log rotation if needed
3. **More frequent updates**: Consider daily updates if needed

### Security Servers (Kali Linux)

1. **Careful package exclusion**: Exclude large metapackages
2. **Monitor tool availability**: Ensure security tools remain functional
3. **Custom service management**: Include specialized services

## Contributing

We welcome contributions to improve cron-apt! Here's how you can help:

### Reporting Issues

1. Check existing issues first
2. Provide detailed system information:
   - Distribution and version
   - cron-apt version
   - Relevant log entries
   - Steps to reproduce

### Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly on supported distributions
5. Submit a pull request with detailed description

### Development Setup

```bash
# Clone the repository
git clone https://github.com/bidhata/cron-apt.git
cd cron-apt

# Test the installer in a VM
vagrant up  # If using Vagrant
# or use Docker
docker run -it ubuntu:22.04 /bin/bash
```

### Code Style

- Use bash strict mode: `set -euo pipefail`
- Follow existing indentation (2 spaces)
- Add comments for complex logic
- Use meaningful variable names
- Validate all inputs

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### v2.0.0 (Latest)
- Enhanced security with SystemD hardening
- Improved service detection and restart logic
- Added distribution-specific optimizations
- Better error handling and logging
- Resource usage monitoring
- Comprehensive installation verification

### v1.5.0
- Added Kali Linux support
- Improved email notifications
- Enhanced logging system
- Better lock file management

### v1.0.0
- Initial release
- Basic update automation
- SystemD integration
- Email notifications

## Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/bidhata/cron-apt/issues)
- **Documentation**: This README and inline code comments
- **Community**: Share experiences and solutions in GitHub Discussions

## Acknowledgments

- **needrestart**: For intelligent service restart detection
- **SystemD**: For robust service management
- **APT**: For reliable package management
- **Community**: For feedback and contributions

---

**Created and maintained by Krishnendu Paul (@bidhata)**

*Keep your systems secure and up-to-date automatically!* 🚀
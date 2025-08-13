# Auto Update System for Ubuntu/Debian Servers

A comprehensive, production-ready automatic update system that keeps your Ubuntu and Debian servers up-to-date with zero user interaction. The system automatically updates packages, restarts services, and provides detailed logging and notifications.

## 🚀 Features

- **Fully Automated**: Zero user interaction required
- **Weekly Schedule**: Runs every Sunday at 2:00 AM with randomized delay
- **Intelligent Service Restart**: Uses `needrestart` to identify and restart services automatically
- **Comprehensive Logging**: Detailed logs with timestamps for audit trails
- **Email Notifications**: Optional email alerts for update completion and reboot requirements
- **Safety First**: Detects reboot requirements but doesn't auto-reboot for safety
- **Lock Prevention**: Prevents multiple update processes from running simultaneously
- **Log Rotation**: Automatic log rotation to manage disk space
- **Systemd Integration**: Proper systemd service with security hardening

## 📋 Requirements

- Ubuntu 16.04+ or Debian 9+
- Root access for installation
- Internet connection for package updates
- Optional: Mail server configuration for notifications

## ⚡ Quick Installation

### One-Line Installation

```bash
curl -fsSL https://raw.githubusercontent.com/bidhata/cron-apt/main/install_auto_update.sh | sudo bash
```

### Manual Installation

1. Download the installation script:
```bash
wget https://raw.githubusercontent.com/bidhata/cron-apt/main/install-auto-update.sh
```

2. Make it executable and run:
```bash
chmod +x install-auto-update.sh
sudo ./install-auto-update.sh
```

## 🔧 What Gets Installed

### Files Created
- `/usr/local/bin/auto-update.sh` - Main update script
- `/etc/systemd/system/auto-update.service` - Systemd service file
- `/etc/systemd/system/auto-update.timer` - Systemd timer for weekly execution
- `/etc/logrotate.d/auto-update` - Log rotation configuration
- `/var/log/auto-update.log` - Log file for all activities

### Packages Installed
- `needrestart` - For intelligent service restart detection
- `mailutils` - For email notifications (optional)

## 📅 Default Schedule

- **When**: Every Sunday at 2:00 AM
- **Randomization**: Up to 30 minutes random delay to distribute load
- **Persistence**: Catches up if system was offline during scheduled time

## 🔄 Update Process

The system performs these steps automatically:

1. **Update Package Lists**: `apt update`
2. **Upgrade Packages**: `apt upgrade -y`
3. **Distribution Upgrade**: `apt dist-upgrade -y` (handles dependency changes)
4. **Remove Orphaned Packages**: `apt autoremove -y`
5. **Clean Package Cache**: `apt autoclean`
6. **Restart Services**: Intelligent service restart using `needrestart`
7. **Check Reboot Requirements**: Detect if system reboot is needed
8. **Send Notifications**: Email alerts (if configured)

## 🛠️ Management Commands

### Check Status
```bash
# View timer status
sudo systemctl status auto-update.timer

# Check next scheduled run
sudo systemctl list-timers auto-update.timer

# View recent logs
sudo tail -f /var/log/auto-update.log
```

### Manual Operations
```bash
# Run update manually
sudo /usr/local/bin/auto-update.sh

# Enable auto-updates
sudo systemctl enable auto-update.timer
sudo systemctl start auto-update.timer

# Disable auto-updates
sudo systemctl disable auto-update.timer
sudo systemctl stop auto-update.timer
```

### Log Management
```bash
# View recent activity
sudo tail -20 /var/log/auto-update.log

# View logs in real-time
sudo tail -f /var/log/auto-update.log

# View full log
sudo less /var/log/auto-update.log
```

## 📧 Email Notifications

To enable email notifications:

1. Edit the main script:
```bash
sudo nano /usr/local/bin/auto-update.sh
```

2. Set the email recipient:
```bash
EMAIL_RECIPIENT="admin@example.com"
```

3. Ensure your system can send emails (configure postfix, sendmail, etc.)

## ⚙️ Configuration Options

### Change Schedule
Edit the timer file to modify the schedule:
```bash
sudo nano /etc/systemd/system/auto-update.timer
```

Example schedules:
```ini
# Daily at 3:00 AM
OnCalendar=*-*-* 03:00:00

# Every Tuesday at 1:30 AM
OnCalendar=Tue *-*-* 01:30:00

# Monthly on the 1st at 2:00 AM
OnCalendar=*-*-01 02:00:00
```

After changes, reload systemd:
```bash
sudo systemctl daemon-reload
sudo systemctl restart auto-update.timer
```

### Enable Automatic Reboot (Use with Caution)
To enable automatic reboots when required, edit the main script:
```bash
sudo nano /usr/local/bin/auto-update.sh
```

Uncomment these lines:
```bash
log_message "Initiating automatic reboot in 2 minutes..."
shutdown -r +2 "System will reboot in 2 minutes due to automatic updates"
```

⚠️ **Warning**: Automatic reboots can cause service disruption. Only enable in environments where this is acceptable.

## 📊 Monitoring and Logs

### Log Format
```
[2024-12-15 02:15:30] Starting automatic system update process...
[2024-12-15 02:15:35] Updating package lists...
[2024-12-15 02:15:45] Available updates: 23
[2024-12-15 02:15:50] Performing package upgrades...
[2024-12-15 02:18:20] Restarting service: nginx
[2024-12-15 02:18:25] Successfully restarted nginx
[2024-12-15 02:18:30] No reboot required
[2024-12-15 02:18:35] === Automatic update process completed ===
```

### Monitoring Integration
The logs can be integrated with monitoring systems:
- **ELK Stack**: Parse logs with Logstash
- **Prometheus**: Use node_exporter textfile collector
- **Nagios/Icinga**: Monitor log file for error patterns
- **Zabbix**: Create log monitoring items

## 🔐 Security Features

The systemd service includes security hardening:
- `NoNewPrivileges=true` - Prevents privilege escalation
- `PrivateTmp=true` - Isolated temporary directory
- `ProtectHome=true` - Restricts access to user home directories
- `RestrictRealtime=true` - Prevents real-time scheduling
- `RestrictSUIDSGID=true` - Prevents SUID/SGID execution

## 🚨 Troubleshooting

### Common Issues

**Timer not running:**
```bash
sudo systemctl status auto-update.timer
sudo systemctl start auto-update.timer
```

**Service fails to start:**
```bash
sudo systemctl status auto-update.service
sudo journalctl -u auto-update.service
```

**Lock file issues:**
```bash
sudo rm -f /var/run/auto-update.lock
```

**Permission issues:**
```bash
sudo chown root:root /usr/local/bin/auto-update.sh
sudo chmod +x /usr/local/bin/auto-update.sh
```

### Debug Mode
Run the script manually with verbose output:
```bash
sudo bash -x /usr/local/bin/auto-update.sh
```

## 📝 Customization

### Adding Custom Services
To add custom services to the restart list, edit the script and modify the `services_to_check` array:

```bash
local services_to_check=(
    "apache2"
    "nginx"
    "mysql"
    "your-custom-service"
    # Add more services here
)
```

### Custom Pre/Post Update Scripts
You can add custom hooks by creating scripts in `/etc/auto-update/`:
- `/etc/auto-update/pre-update.sh` - Runs before updates
- `/etc/auto-update/post-update.sh` - Runs after updates

## 🔄 Uninstallation

To completely remove the auto-update system:

```bash
# Stop and disable the timer
sudo systemctl stop auto-update.timer
sudo systemctl disable auto-update.timer

# Remove systemd files
sudo rm -f /etc/systemd/system/auto-update.service
sudo rm -f /etc/systemd/system/auto-update.timer
sudo systemctl daemon-reload

# Remove script and logs
sudo rm -f /usr/local/bin/auto-update.sh
sudo rm -f /var/log/auto-update.log
sudo rm -f /etc/logrotate.d/auto-update

# Remove lock file if exists
sudo rm -f /var/run/auto-update.lock
```

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review the logs at `/var/log/auto-update.log`
3. Open an issue on GitHub

## 🙏 Acknowledgments

- Ubuntu and Debian communities for excellent package management
- `needrestart` developers for intelligent service restart detection
- systemd team for robust service management

---

**⚠️ Important Notes:**
- Always test in a development environment before production deployment
- Consider your specific infrastructure requirements before enabling automatic reboots
- Monitor the first few runs to ensure everything works as expected
- Keep backups of your system before implementing automatic updates

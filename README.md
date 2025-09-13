# cron-apt - Automatic Update System for Ubuntu/Debian Servers

A comprehensive, production-ready automatic update system that keeps your Ubuntu and Debian servers up-to-date with zero user interaction. The system automatically updates packages, restarts services, and provides detailed logging and notifications.

**Created by:** Krishnendu Paul ([@bidhata](https://github.com/bidhata))  
**Repository:** [https://github.com/bidhata/cron-apt](https://github.com/bidhata/cron-apt)

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
curl -fsSL https://raw.githubusercontent.com/bidhata/cron-apt/main/install_cron_apt.sh | sudo bash
```

### Manual Installation

1. Download the installation script:
```bash
wget https://raw.githubusercontent.com/bidhata/cron-apt/main/install_cron_apt.sh
```

2. Make it executable and run:
```bash
chmod +x install_cron_apt.sh
sudo ./install_cron_apt.sh
```

## 🔧 What Gets Installed

### Files Created
- `/usr/local/bin/cron-apt.sh` - Main update script
- `/etc/systemd/system/cron-apt.service` - Systemd service file
- `/etc/systemd/system/cron-apt.timer` - Systemd timer for weekly execution
- `/etc/logrotate.d/cron-apt` - Log rotation configuration
- `/var/log/cron-apt.log` - Log file for all activities

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
sudo systemctl status cron-apt.timer

# Check next scheduled run
sudo systemctl list-timers cron-apt.timer

# View recent logs
sudo tail -f /var/log/cron-apt.log
```

### Manual Operations
```bash
# Run update manually
sudo /usr/local/bin/cron-apt.sh

# Enable auto-updates
sudo systemctl enable cron-apt.timer
sudo systemctl start cron-apt.timer

# Disable auto-updates
sudo systemctl disable cron-apt.timer
sudo systemctl stop cron-apt.timer
```

### Log Management
```bash
# View recent activity
sudo tail -20 /var/log/cron-apt.log

# View logs in real-time
sudo tail -f /var/log/cron-apt.log

# View full log
sudo less /var/log/cron-apt.log
```

## 📧 Email Notifications

To enable email notifications:

1. Edit the main script:
```bash
sudo nano /usr/local/bin/cron-apt.sh
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
sudo nano /etc/systemd/system/cron-apt.timer
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
sudo systemctl restart cron-apt.timer
```

### Enable Automatic Reboot (Use with Caution)
To enable automatic reboots when required, edit the main script:
```bash
sudo nano /usr/local/bin/cron-apt.sh
```

Uncomment these lines:
```bash
log_message "Initiating automatic reboot in 2 minutes..."
shutdown -r +2 "System will reboot in 2 minutes due to cron-apt automatic updates"
```

⚠️ **Warning**: Automatic reboots can cause service disruption. Only enable in environments where this is acceptable.

## 📊 Monitoring and Logs

### Log Format
```
[2024-12-15 02:15:30] Starting cron-apt automatic system update process...
[2024-12-15 02:15:35] Updating package lists...
[2024-12-15 02:15:45] Available updates: 23
[2024-12-15 02:15:50] Performing package upgrades...
[2024-12-15 02:18:20] Restarting service: nginx
[2024-12-15 02:18:25] Successfully restarted nginx
[2024-12-15 02:18:30] No reboot required
[2024-12-15 02:18:35] === cron-apt automatic update process completed ===
```

### Monitoring Integration
The logs can be integrated with monitoring systems:
- **ELK Stack**: Parse logs with Logstash
- **Prometheus**: Use node_exporter textfile collector
- **Nagios/Icinga**: Monitor log file for error patterns
- **Zabbix**: Create log monitoring items

## 🔒 Security Features

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
sudo systemctl status cron-apt.timer
sudo systemctl start cron-apt.timer
```

**Service fails to start:**
```bash
sudo systemctl status cron-apt.service
sudo journalctl -u cron-apt.service
```

**Lock file issues:**
```bash
sudo rm -f /var/run/cron-apt.lock
```

**Permission issues:**
```bash
sudo chown root:root /usr/local/bin/cron-apt.sh
sudo chmod +x /usr/local/bin/cron-apt.sh
```

### Debug Mode
Run the script manually with verbose output:
```bash
sudo bash -x /usr/local/bin/cron-apt.sh
```

## 🎨 Customization

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
You can add custom hooks by creating scripts in `/etc/cron-apt/`:
- `/etc/cron-apt/pre-update.sh` - Runs before updates
- `/etc/cron-apt/post-update.sh` - Runs after updates

Create the hooks directory and add your custom scripts:
```bash
sudo mkdir -p /etc/cron-apt
sudo chmod 755 /etc/cron-apt
```

## 🗑️ Uninstallation

To completely remove cron-apt:

```bash
# Stop and disable the timer
sudo systemctl stop cron-apt.timer
sudo systemctl disable cron-apt.timer

# Remove systemd files
sudo rm -f /etc/systemd/system/cron-apt.service
sudo rm -f /etc/systemd/system/cron-apt.timer
sudo systemctl daemon-reload

# Remove script and logs
sudo rm -f /usr/local/bin/cron-apt.sh
sudo rm -f /var/log/cron-apt.log
sudo rm -f /etc/logrotate.d/cron-apt

# Remove lock file if exists
sudo rm -f /var/run/cron-apt.lock

# Remove hooks directory (if created)
sudo rm -rf /etc/cron-apt
```

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request to the [cron-apt repository](https://github.com/bidhata/cron-apt).

### Development Guidelines
- Follow bash best practices
- Ensure compatibility with Ubuntu 16.04+ and Debian 9+
- Add appropriate error handling
- Update documentation for new features
- Test on multiple distributions before submitting

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review the logs at `/var/log/cron-apt.log`
3. Open an issue on the [GitHub repository](https://github.com/bidhata/cron-apt/issues)
4. Check existing issues and discussions

## 🙏 Acknowledgments

- **Krishnendu Paul ([@bidhata](https://github.com/bidhata))** - Creator and maintainer
- Ubuntu and Debian communities for excellent package management
- `needrestart` developers for intelligent service restart detection
- systemd team for robust service management
- All contributors and users who provide feedback and improvements

## 🏷️ Version History

- **v1.0.0** - Initial release with basic functionality
- **v1.1.0** - Added intelligent service restart with needrestart
- **v1.2.0** - Enhanced logging and email notifications
- **v1.3.0** - Added systemd integration and security hardening
- **v1.4.0** - Improved error handling and lock mechanisms
- **Current** - Rebranded as cron-apt with enhanced features

## 🌟 Similar Projects

If cron-apt doesn't meet your needs, consider these alternatives:
- `unattended-upgrades` - Ubuntu's built-in automatic update system
- `dnf-automatic` - For Red Hat/CentOS/Fedora systems
- `zypper-automatic` - For openSUSE systems
- `apticron` - Email-based update notifications

## 🔗 Useful Links

- **Repository**: [https://github.com/bidhata/cron-apt](https://github.com/bidhata/cron-apt)
- **Issues**: [https://github.com/bidhata/cron-apt/issues](https://github.com/bidhata/cron-apt/issues)
- **Releases**: [https://github.com/bidhata/cron-apt/releases](https://github.com/bidhata/cron-apt/releases)
- **Author**: [Krishnendu Paul (@bidhata)](https://github.com/bidhata)

---

**⚠️ Important Notes:**
- Always test in a development environment before production deployment
- Consider your specific infrastructure requirements before enabling automatic reboots
- Monitor the first few runs to ensure everything works as expected
- Keep backups of your system before implementing automatic updates
- Review and customize the service restart list based on your server configuration

**📈 Performance Impact:**
- Minimal system resource usage during execution
- Network bandwidth depends on available updates
- Typical execution time: 2-15 minutes depending on update size
- CPU usage is generally low during package installation

**🔄 Update Frequency Recommendations:**
- **Production servers**: Weekly (default)
- **Development servers**: Daily or weekly
- **Critical infrastructure**: Manual updates with testing
- **Desktop systems**: Daily updates acceptable

**📱 Mobile and Remote Management:**
- Monitor via SSH and log files
- Set up email notifications for remote awareness
- Consider VPN access for emergency management
- Use monitoring tools for automated alerting

**🎯 Best Practices:**
1. **Test First**: Always test updates in a staging environment
2. **Backup Strategy**: Ensure regular backups before automatic updates
3. **Monitoring**: Implement log monitoring and alerting
4. **Documentation**: Keep track of your server configurations
5. **Recovery Plan**: Have a rollback strategy for critical issues
6. **Security**: Regularly review and update the service list
7. **Maintenance Window**: Consider your organization's maintenance windows

---

*cron-apt - Keeping your servers secure and up-to-date automatically!*
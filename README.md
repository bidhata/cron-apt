```
       ____ _            _            
      / ___| |__   ___  | |__   _ __  
     | |   | '_ \ / __| | '_ \ | '_ \ 
     | |___| | | | (__  | |_) || | | |
      \____|_| |_| \___| |_.__/ |_| |_|

   Enhanced Automatic Update System
```

# cron-apt - Enhanced Automatic Update System

**cron-apt** is a robust and feature-rich solution for automating system updates on Debian-based Linux distributions, including Ubuntu, Debian, Kali Linux, Linux Mint, and Pop!_OS. It provides scheduled package updates, service management, email notifications, and comprehensive logging, with a focus on security and reliability.

## Features

```
🌟 Key Highlights
```
- **Automated Updates**: Schedule daily, weekly, or monthly package updates using `apt-get`.
- **Systemd Integration**: Leverages systemd timers for reliable scheduling.
- **Service Management**: Automatically restarts services affected by updates using `needrestart`.
- **Email Notifications**: Sends detailed update reports and alerts to specified email addresses.
- **Customizable Hooks**: Supports pre- and post-update scripts for custom actions.
- **Logging and Metrics**: Comprehensive logging with rotation and performance metrics.
- **Auto-Reboot Option**: Configurable automatic reboots for updates requiring system restarts.
- **Package Exclusions**: Allows skipping specific packages during upgrades.
- **Uninstaller**: Includes a dedicated script for complete removal.
- **Security Hardening**: Implements systemd security features and secure file permissions.
- **Dry-Run Mode**: Simulates installation without making changes.

## Supported Distributions

```
✅ Compatible Systems
```
- Ubuntu
- Debian
- Kali Linux
- Linux Mint
- Pop!_OS

## Prerequisites

```
📋 Requirements
```
- Root or sudo privileges
- Internet connectivity
- `systemd` and `apt-get` installed
- Minimum disk space:
  - 100 MB on root (`/`)
  - 50 MB on `/boot` (if separate partition)
  - 200 MB on `/var` (if separate partition)

## Installation

```
🚀 Get Started
```

### Quick Install

Run the following command as root to install `cron-apt`:

```bash
curl -fsSL https://raw.githubusercontent.com/bidhata/cron-apt/main/install_cron_apt.sh | sudo bash
```

### Manual Installation

1. Download the installation script:
   ```bash
   wget https://raw.githubusercontent.com/bidhata/cron-apt/main/install_cron_apt.sh
   ```
2. Make it executable:
   ```bash
   chmod +x install_cron_apt.sh
   ```
3. Run as root:
   ```bash
   sudo ./install_cron_apt.sh
   ```

### Installation Options

- `--dry-run`: Simulate installation without making changes.
- `--uninstall`: Remove `cron-apt` from the system.
- `--log-level [DEBUG|INFO|WARN|ERROR]`: Set verbosity of installation logs.
- `-h, --help`: Display help message.

Example:
```bash
sudo ./install_cron_apt.sh --log-level DEBUG
```

### Configuration Prompts

During installation, you will be prompted to configure:
- **Auto-reboot**: Enable/disable automatic reboots for updates requiring restarts.
- **Email Notifications**: Specify an email address for update reports (optional).
- **Update Frequency**: Choose daily, weekly, or monthly updates.

## Configuration

```
⚙️ Customize Your Setup
```

The main configuration file is located at `/etc/cron-apt/config`. Key settings include:

- `EMAIL_RECIPIENT`: Email address for notifications.
- `AUTO_REBOOT`: Set to `true` for automatic reboots, `false` to disable.
- `UPDATE_FREQUENCY`: Set to `daily`, `weekly`, or `monthly`.
- `CUSTOM_SERVICES`: Space-separated list of services to restart after updates.
- `EXCLUDE_PACKAGES`: Space-separated list of packages to skip during upgrades.
- `VERBOSE_LOGGING`: Enable detailed logs with `true`.
- `PRE_UPDATE_HOOK` and `POST_UPDATE_HOOK`: Paths to custom scripts to run before/after updates.

Example configuration:
```bash
EMAIL_RECIPIENT="admin@example.com"
AUTO_REBOOT="false"
CUSTOM_SERVICES="nginx apache2"
EXCLUDE_PACKAGES="kernel-image-* mysql-server"
VERBOSE_LOGGING="true"
```

### Custom Hooks

Place executable scripts in `/etc/cron-apt/hooks/` for pre- or post-update actions. Example scripts are provided:
- `/etc/cron-apt/hooks/pre-update.sh.example`
- `/etc/cron-apt/hooks/post-update.sh.example`

To use, copy and modify:
```bash
sudo cp /etc/cron-apt/hooks/pre-update.sh.example /etc/cron-apt/hooks/pre-update.sh
sudo chmod +x /etc/cron-apt/hooks/pre-update.sh
sudo nano /etc/cron-apt/hooks/pre-update.sh
```

## Usage

```
🛠️ Manage Your System
```

### Manual Update
Run updates manually:
```bash
sudo /usr/local/bin/cron-apt
```

### Check Status
View the status of the update timer:
```bash
systemctl status cron-apt.timer
```

### View Logs
Check update logs:
```bash
tail -f /var/log/cron-apt.log
```

### View Next Scheduled Run
See when the next update is scheduled:
```bash
systemctl list-timers cron-apt.timer
```

### Disable Auto-Updates
Stop automatic updates:
```bash
sudo systemctl disable cron-apt.timer
```

### Uninstall
Remove `cron-apt` completely:
```bash
sudo /usr/local/bin/uninstall-cron-apt
```

## Files and Directories

```
📂 System Layout
```
- **Main Script**: `/usr/local/bin/cron-apt`
- **Uninstaller**: `/usr/local/bin/uninstall-cron-apt`
- **Configuration**: `/etc/cron-apt/config`
- **Hooks Directory**: `/etc/cron-apt/hooks/`
- **Log File**: `/var/log/cron-apt.log`
- **Status File**: `/var/lib/cron-apt/status`
- **Metrics File**: `/var/lib/cron-apt/metrics`
- **Systemd Service**: `/etc/systemd/system/cron-apt.service`
- **Systemd Timer**: `/etc/systemd/system/cron-apt.timer`
- **Log Rotation**: `/etc/logrotate.d/cron-apt`

## Security Features

```
🔒 Built-in Protections
```
- **Systemd Hardening**: Uses `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem`, and other security directives.
- **Secure Permissions**: Files and directories are owned by `root` with appropriate permissions.
- **Lock Management**: Prevents concurrent runs using a lock file.
- **Error Handling**: Comprehensive error trapping and logging.
- **Safe Configuration Loading**: Validates configuration file permissions and syntax.

## Troubleshooting

```
🛠️ Fix Common Issues
```
- **No Email Notifications**: Ensure `mailutils` is installed and a mail server is configured. Verify `EMAIL_RECIPIENT` in `/etc/cron-apt/config`.
- **Timer Not Running**: Check status with `systemctl status cron-apt.timer` and logs in `/var/log/cron-apt.log`.
- **Insufficient Disk Space**: Free up space on `/`, `/boot`, or `/var` partitions.
- **Syntax Errors**: Validate scripts with `bash -n /usr/local/bin/cron-apt`.
- **Failed Updates**: Check internet connectivity and review logs.

For further assistance, open an issue at [github.com/bidhata/cron-apt/issues](https://github.com/bidhata/cron-apt/issues).

## Contributing

```
🤝 Join the Project
```
Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/YourFeature`).
3. Commit changes (`git commit -m "Add YourFeature"`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request.

## License

```
📜 Legal
```
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

```
👤 Creator
```
Krishnendu Paul ([@bidhata](https://github.com/bidhata))

## Acknowledgments

```
🙏 Thanks
```
- Inspired by the need for reliable, secure, and configurable automatic updates.
- Thanks to the open-source community for tools like `needrestart` and `logrotate`.
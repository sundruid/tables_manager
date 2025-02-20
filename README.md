```markdown:README.md
# Tables Manager

A Python service for managing IP blacklists using nftables or iptables on Linux systems. This service automatically downloads and maintains a list of blocked IP addresses, providing efficient packet filtering and threat protection.

## Features

- **Dual Firewall Support**: Works with both nftables (modern) and iptables (legacy)
- **Efficient IP Management**: 
  - Uses native nftables sets or ipset for optimal performance
  - Batch processing of IP updates
  - Incremental updates to minimize system impact
- **Robust Error Handling**:
  - Graceful recovery from network issues
  - Automatic ruleset repair
  - State consistency checks
- **Comprehensive Logging**:
  - System logging via journald/syslog
  - Detailed debug logging
  - Statistics tracking
- **Maintenance Tools**:
  - `-refresh` flag for system reset
  - State file management
  - Statistics reporting

## Requirements

### System Requirements
- Linux system with nftables or iptables+ipset
- Python 3.6 or higher
- Root/sudo access for firewall management

### Python Dependencies
```bash
pip install requests
```

### System Packages
For nftables:
```bash
sudo apt install nftables    # Debian/Ubuntu
sudo yum install nftables    # RHEL/CentOS
```

For iptables:
```bash
sudo apt install iptables ipset    # Debian/Ubuntu
sudo yum install iptables ipset    # RHEL/CentOS
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/tables_manager.git
cd tables_manager
```

2. Make the script executable:
```bash
chmod +x tables_manager.py
```

3. Configure the script:
Edit the configuration section at the top of `tables_manager.py`:
```python
FIREWALL_TYPE = "nftables"  # or "iptables"
UPDATE_INTERVAL = 5         # minutes
IP_LIST_URL = "your_ip_list_url"
```

## Usage

### Running the Service

```bash
sudo ./tables_manager.py
```

### Refreshing the System

To clear all rules and state files, then reinitialize:
```bash
sudo ./tables_manager.py -refresh
```

### Checking Status

View current statistics:
```bash
# For nftables
sudo nft list chain inet filter blacklist_chain
sudo nft list set inet filter blacklist

# For iptables
sudo iptables -L INPUT -v
sudo ipset list blacklist
```

View logs:
```bash
# System logs
sudo journalctl -t tables_manager

# Debug logs
sudo tail -f /var/log/tables_manager_debug.log
```

## File Locations

- **Script**: `/usr/local/sbin/tables_manager.py`
- **State Files**: `/var/lib/tables_manager/`
  - `current_ips`: Currently blocked IPs
  - `last_update`: Last update timestamp
- **Logs**:
  - System logs: journald/syslog
  - Debug log: `/var/log/tables_manager_debug.log`

## Firewall Implementation

### nftables
- Creates `inet filter` table
- Sets up `blacklist_chain` with input hook
- Uses efficient set for IP storage
- Implements packet counting

### iptables
- Uses ipset for efficient IP storage
- Single iptables rule referencing ipset
- Automatic ipset creation and management

## Statistics

The service tracks and reports:
- Number of IPs added/removed
- Currently blocked IPs
- Dropped packet count
- Total bytes dropped
- Invalid IP counts
- Comment counts in source file

## Error Handling

Handles various failure scenarios:
- Download failures
- Network issues
- File access problems
- Firewall command failures
- Invalid IP formats
- URL validation failures

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

[Your License Here]

## Author

[Your Name]

## Acknowledgments

- [Any acknowledgments or credits]
```

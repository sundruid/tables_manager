#!/usr/bin/env python3

import requests
import subprocess
import time
import logging
import logging.handlers
import sys
from datetime import datetime
from typing import Set, Tuple
import argparse
import os

# Configuration
FIREWALL_TYPE = "nftables"  # Options: "nftables" or "iptables"
UPDATE_INTERVAL = 5  # Minutes between updates
IP_LIST_URL = "https://cdn.ellio.tech/YOURLINKHERE"
LAST_UPDATE_FILE = "/var/lib/tables_manager/last_update"
CURRENT_IPS_FILE = "/var/lib/tables_manager/current_ips"

# Initialize logger without handlers
logger = logging.getLogger('tables_manager')

def setup_directories() -> None:
    """Create necessary directories for storing state files."""
    try:
        subprocess.run(['mkdir', '-p', '/var/lib/tables_manager'], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create directory structure: {e}")
        sys.exit(1)

def download_ip_list() -> Set[str]:
    """Download and parse the IP list, returning a set of IPs."""
    try:
        logger.info("Downloading IP list...")
        response = requests.get(IP_LIST_URL, timeout=30)
        response.raise_for_status()
        
        # Parse IPs, excluding comments
        ips = set()
        comment_count = 0
        invalid_count = 0
        
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                comment_count += 1
                continue
                
            try:
                # Basic IP validation
                parts = line.split('.')
                if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                    ips.add(line)
                else:
                    invalid_count += 1
                    logger.warning(f"Invalid IP format: {line}")
            except (ValueError, IndexError):
                invalid_count += 1
                logger.warning(f"Invalid IP format: {line}")
        
        logger.info(f"Processed IP list: {len(ips)} valid IPs, {comment_count} comments, {invalid_count} invalid entries")
        
        if not ips:
            logger.error("No valid IPs found in downloaded list")
            return set()
        
        # Debug: Log a sample of IPs
        sample_size = min(5, len(ips))
        sample_ips = list(ips)[:sample_size]
        logger.debug(f"Sample of downloaded IPs: {', '.join(sample_ips)}")
        
        return ips
    
    except requests.RequestException as e:
        logger.error(f"Failed to download IP list: {e}")
        return set()

def read_current_ips() -> Set[str]:
    """Read the current list of blocked IPs from file."""
    try:
        with open(CURRENT_IPS_FILE, 'r') as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()

def write_current_ips(ips: Set[str]) -> None:
    """Write the current list of blocked IPs to file."""
    with open(CURRENT_IPS_FILE, 'w') as f:
        for ip in sorted(ips):
            f.write(f"{ip}\n")

def setup_iptables() -> bool:
    """Initialize iptables structure if it doesn't exist."""
    try:
        # Create ipset for storing blocked IPs if it doesn't exist
        commands = [
            ['ipset', 'create', 'blacklist', 'hash:ip', '-exist'],
            ['iptables', '-C', 'INPUT', '-m', 'set', '--match-set', 'blacklist', 'src', '-j', 'DROP'],
        ]
        
        # Try to check if the rule exists
        rule_check = commands[1]
        rule_result = subprocess.run(rule_check, capture_output=True, text=True)
        
        if rule_result.returncode != 0:
            # Rule doesn't exist, create ipset and add rule
            for cmd in commands:
                subprocess.run(cmd, check=True)
                logger.info(f"Executed command: {' '.join(cmd)}")
            
            logger.info("Successfully initialized iptables structure")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to initialize iptables: {e}")
        return False

def update_firewall_rules(ips_to_add: Set[str], ips_to_remove: Set[str]) -> bool:
    """Update firewall rules using either nftables or iptables."""
    success = True
    BATCH_SIZE = 50  # Reduce batch size to 50 for testing

    if FIREWALL_TYPE == "nftables":
        try:
            # Handle removals in batches
            remove_list = list(ips_to_remove)
            for i in range(0, len(remove_list), BATCH_SIZE):
                batch = remove_list[i:i + BATCH_SIZE]
                if batch:  # Only proceed if we have IPs to remove
                    remove_elements = ', '.join(batch)
                    try:
                        subprocess.run([
                            'nft', 'delete', 'element', 'inet', 'filter', 'blacklist',
                            '{', remove_elements, '}'
                        ], check=True, capture_output=True)
                        logger.info(f"Removed {len(batch)} IPs from blacklist")
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"Some IPs couldn't be removed: {e}")
                        # Log the specific IPs that failed
                        logger.debug(f"Failed to remove IPs: {batch}")

            # Handle additions in batches
            add_list = list(ips_to_add)
            for i in range(0, len(add_list), BATCH_SIZE):
                batch = add_list[i:i + BATCH_SIZE]
                if batch:  # Only proceed if we have IPs to add
                    add_elements = ', '.join(batch)
                    try:
                        subprocess.run([
                            'nft', 'add', 'element', 'inet', 'filter', 'blacklist',
                            '{', add_elements, '}'
                        ], check=True, capture_output=True)
                        logger.info(f"Added {len(batch)} IPs to blacklist")
                    except subprocess.CalledProcessError as e:
                        logger.error(f"Failed to add IPs to blacklist: {e}")
                        success = False

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to update nftables rules: {e}")
            success = False

    else:  # iptables
        try:
            # Ensure ipset exists before making changes
            if not setup_iptables():
                return False

            # Handle removals in batches
            remove_list = list(ips_to_remove)
            for i in range(0, len(remove_list), BATCH_SIZE):
                batch = remove_list[i:i + BATCH_SIZE]
                for ip in batch:
                    try:
                        subprocess.run([
                            'ipset', 'del', 'blacklist', ip
                        ], check=True)
                    except subprocess.CalledProcessError:
                        # Ignore errors when trying to remove non-existent elements
                        pass

            # Handle additions in batches
            add_list = list(ips_to_add)
            for i in range(0, len(add_list), BATCH_SIZE):
                batch = add_list[i:i + BATCH_SIZE]
                for ip in batch:
                    subprocess.run([
                        'ipset', 'add', 'blacklist', ip
                    ], check=True)

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to update iptables rules: {e}")
            success = False

    return success

def update_last_update_time() -> None:
    """Update the last update timestamp file."""
    with open(LAST_UPDATE_FILE, 'w') as f:
        f.write(datetime.now().isoformat())

def process_ip_updates() -> Tuple[bool, int, int]:
    """
    Process IP updates and return success status and counts.
    Returns: (success, added_count, removed_count)
    """
    new_ips = download_ip_list()
    if not new_ips:
        return False, 0, 0

    try:
        # Check if blacklist set exists and has elements
        set_result = subprocess.run(
            ['nft', 'list', 'set', 'inet', 'filter', 'blacklist'],
            capture_output=True, text=True, check=True
        )
        
        current_ips = read_current_ips()
        needs_repopulation = False
        
        # Check if set is empty but we have IPs in our current_ips file
        if 'elements = { }' in set_result.stdout and current_ips:
            logger.warning("Blacklist set is empty but we have IPs stored. Repopulating...")
            needs_repopulation = True
        
        # Check if set doesn't exist
        if 'No such set' in set_result.stderr:
            logger.warning("Blacklist set not found. Reinitializing...")
            if not setup_nftables():
                return False, 0, 0
            needs_repopulation = True
        
        if needs_repopulation:
            # Repopulate the entire set
            if update_firewall_rules(new_ips, set()):
                write_current_ips(new_ips)
                update_last_update_time()
                return True, len(new_ips), 0
            return False, 0, 0
        
        # Normal update process
        ips_to_add = new_ips - current_ips
        ips_to_remove = current_ips - new_ips
        
        if update_firewall_rules(ips_to_add, ips_to_remove):
            write_current_ips(new_ips)
            update_last_update_time()
            return True, len(ips_to_add), len(ips_to_remove)
        
        return False, 0, 0
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to check blacklist set status: {e}")
        return False, 0, 0

def setup_nftables() -> bool:
    """Initialize nftables structure if it doesn't exist."""
    try:
        # Check if table exists
        result = subprocess.run(['nft', 'list', 'table', 'inet', 'filter'], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            # Create base table and chain structure
            commands = [
                ['nft', 'add', 'table', 'inet', 'filter'],
                ['nft', 'add', 'chain', 'inet', 'filter', 'blacklist_chain', 
                 '{ type filter hook input priority 0 ; policy accept ; }'],
                ['nft', 'add', 'set', 'inet', 'filter', 'blacklist', 
                 '{ type ipv4_addr ; flags interval ; }'],
                ['nft', 'add', 'rule', 'inet', 'filter', 'blacklist_chain', 
                 'ip', 'saddr', '@blacklist', 'counter', 'drop']
            ]
            
            for cmd in commands:
                subprocess.run(cmd, check=True)
                logger.info(f"Executed command: {' '.join(cmd)}")
            
            logger.info("Successfully initialized nftables structure")
        else:
            # Check if set exists, create if it doesn't
            set_result = subprocess.run(['nft', 'list', 'set', 'inet', 'filter', 'blacklist'],
                                      capture_output=True, text=True)
            if set_result.returncode != 0:
                subprocess.run([
                    'nft', 'add', 'set', 'inet', 'filter', 'blacklist',
                    '{ type ipv4_addr ; flags interval ; }'
                ], check=True)
                logger.info("Created blacklist set")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to initialize nftables: {e}")
        return False

def get_drop_statistics() -> dict:
    """Get statistics for dropped packets from the blacklist rule."""
    try:
        # Get all rules with their counters
        result = subprocess.run(
            ['nft', 'list', 'chain', 'inet', 'filter', 'blacklist_chain'],
            capture_output=True, text=True, check=True
        )
        
        # Get current blacklist set size
        set_result = subprocess.run(
            ['nft', 'list', 'set', 'inet', 'filter', 'blacklist'],
            capture_output=True, text=True, check=True
        )
        
        stats = {
            'packets': 0,
            'bytes': 0,
            'active_ips': 0
        }
        
        # Parse set size
        elements = []
        in_elements_section = False
        for line in set_result.stdout.splitlines():
            if 'elements = {' in line:
                in_elements_section = True
                # Start collecting elements
                elements_part = line.split('{', 1)[1].strip()
                elements.append(elements_part)
            elif in_elements_section:
                # Continue collecting elements until the closing brace
                if '}' in line:
                    elements_part = line.rsplit('}', 1)[0].strip()
                    elements.append(elements_part)
                    break
                else:
                    elements.append(line.strip())
        
        # Join all parts and split by comma to count IPs
        all_elements = ','.join(elements)
        stats['active_ips'] = len([x.strip() for x in all_elements.split(',') if x.strip()])
        
        # Parse counter values
        for line in result.stdout.splitlines():
            if '@blacklist' in line and 'counter' in line:
                # Example line: "ip saddr @blacklist counter packets 42 bytes 1337 drop"
                parts = line.split()
                counter_idx = parts.index('counter')
                if len(parts) > counter_idx + 4:  # Ensure we have enough parts
                    stats['packets'] = int(parts[counter_idx + 2])
                    stats['bytes'] = int(parts[counter_idx + 4])
                break
        
        return stats
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get drop statistics: {e}")
        return {'packets': 0, 'bytes': 0, 'active_ips': 0}

def validate_ip_list_url() -> bool:
    """Validate that the IP list URL is accessible and returns expected data."""
    try:
        logger.info(f"Validating IP list URL: {IP_LIST_URL}")
        
        # Try HEAD request first
        logger.debug("Attempting HEAD request...")
        response = requests.head(IP_LIST_URL, timeout=5)
        response.raise_for_status()
        
        # Get a small sample to verify format
        logger.debug("Attempting GET request...")
        response = requests.get(IP_LIST_URL, timeout=30, stream=True)
        response.raise_for_status()
        
        # Read lines until we find IPs
        logger.debug("Reading lines until we find IPs...")
        sample_lines = []
        ip_lines = []
        line_count = 0
        
        for line in response.iter_lines(decode_unicode=True):
            if line:
                line = line.strip()
                sample_lines.append(line)
                
                # Skip comments but log them for debug
                if line.startswith('#'):
                    logger.debug(f"Comment line: {line}")
                    continue
                
                # Check if line looks like an IP
                if '.' in line and all(part.isdigit() for part in line.split('.')):
                    ip_lines.append(line)
                    logger.debug(f"Found IP: {line}")
                    if len(ip_lines) >= 5:  # Found enough IPs
                        break
            
            line_count += 1
            if line_count >= 100:  # Safety limit
                break
        
        if not ip_lines:
            logger.error(f"No valid IP addresses found in first {line_count} lines")
            logger.debug(f"Sample of content: {sample_lines[:10]}")
            return False
            
        logger.info(f"Found {len(ip_lines)} valid IP lines in sample")
        logger.debug(f"Sample valid IPs: {ip_lines}")
        return True
        
    except requests.RequestException as e:
        logger.error(f"Failed to validate IP list URL: {e}")
        logger.debug(f"Full error: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error validating URL: {type(e).__name__}: {e}")
        logger.debug(f"Full error: {str(e)}")
        return False

def setup_logging():
    """Setup logging with both syslog and debug file output."""
    # Clear any existing handlers
    logger.handlers = []
    
    logger.setLevel(logging.DEBUG)
    
    # Syslog handler
    syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
    syslog_handler.setFormatter(logging.Formatter(
        'tables_manager[%(process)d]: %(levelname)s %(message)s'
    ))
    syslog_handler.setLevel(logging.INFO)
    logger.addHandler(syslog_handler)
    
    # Debug file handler
    debug_handler = logging.FileHandler('/var/log/tables_manager_debug.log')
    debug_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    debug_handler.setLevel(logging.DEBUG)
    logger.addHandler(debug_handler)

def refresh_system() -> None:
    """Refresh the system by clearing firewall rules and state files, then reinitialize."""
    logger.info("Refreshing system...")
    
    # Clear firewall rules
    if FIREWALL_TYPE == "nftables":
        try:
            logger.info("Flushing nftables ruleset...")
            subprocess.run(['nft', 'flush', 'ruleset'], check=True)
            logger.info("Successfully flushed nftables ruleset")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to flush nftables ruleset: {e}")
            sys.exit(1)
    else:  # iptables
        try:
            logger.info("Cleaning up ipset and iptables...")
            # Remove iptables rule that references the blacklist
            subprocess.run([
                'iptables', '-D', 'INPUT', '-m', 'set', 
                '--match-set', 'blacklist', 'src', '-j', 'DROP'
            ], check=False)  # Don't check as it might not exist
            
            # Destroy the ipset
            subprocess.run(['ipset', 'destroy', 'blacklist'], check=False)
            logger.info("Successfully cleaned up iptables and ipset")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to clean up iptables/ipset: {e}")
            sys.exit(1)
    
    # Remove state files
    try:
        logger.info("Removing state files...")
        files_to_remove = [CURRENT_IPS_FILE, LAST_UPDATE_FILE]
        for file in files_to_remove:
            if os.path.exists(file):
                os.remove(file)
                logger.info(f"Removed {file}")
    except OSError as e:
        logger.error(f"Failed to remove state files: {e}")
        sys.exit(1)
    
    logger.info("Cleanup completed, reinitializing system...")
    
    # Reinitialize everything
    try:
        # Create directories
        setup_directories()
        
        # Validate IP list URL
        logger.info("Validating IP list URL...")
        if not validate_ip_list_url():
            logger.error("Failed to validate IP list URL during refresh. Exiting.")
            sys.exit(1)
        
        # Initialize firewall
        logger.info("Reinitializing firewall...")
        if FIREWALL_TYPE == "nftables":
            if not setup_nftables():
                logger.error("Failed to reinitialize nftables. Exiting.")
                sys.exit(1)
        else:  # iptables
            if not setup_iptables():
                logger.error("Failed to reinitialize iptables. Exiting.")
                sys.exit(1)
        
        # Download and apply initial IP list
        logger.info("Downloading and applying initial IP list...")
        success, added_count, _ = process_ip_updates()
        if not success:
            logger.error("Failed to apply initial IP list. Exiting.")
            sys.exit(1)
        
        logger.info(f"Successfully initialized with {added_count} IPs")
        logger.info("System refresh and reinitialization completed successfully")
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"Failed during reinitialization: {e}")
        sys.exit(1)

def main() -> None:
    """Main function to run the IP blocking service."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='IP blocking service')
    parser.add_argument('-refresh', action='store_true', 
                       help='Refresh system by clearing rules and state files')
    args = parser.parse_args()
    
    setup_logging()
    logger.info("Starting tables_manager service")
    
    # Handle refresh flag
    if args.refresh:
        refresh_system()
        return  # Not needed due to sys.exit(0) but good practice
    
    setup_directories()
    
    # Validate IP list URL before starting
    logger.info("Validating IP list URL...")
    if not validate_ip_list_url():
        logger.error("Failed to validate IP list URL. Exiting.")
        sys.exit(1)
    
    logger.info("URL validation successful, initializing firewall...")
    
    if FIREWALL_TYPE == "nftables":
        if not setup_nftables():
            logger.error("Failed to initialize nftables. Exiting.")
            sys.exit(1)
    else:  # iptables
        if not setup_iptables():
            logger.error("Failed to initialize iptables. Exiting.")
            sys.exit(1)
    
    while True:
        success, added_count, removed_count = process_ip_updates()
        
        if success:
            stats = get_drop_statistics()
            logger.info(
                f"Successfully updated IP list: "
                f"Added {added_count} IPs, Removed {removed_count} IPs. "
                f"Currently blocking {stats['active_ips']} IPs. "
                f"Total drops: {stats['packets']} packets ({stats['bytes']} bytes)"
            )
        else:
            logger.error("Failed to update IP list")
        
        time.sleep(UPDATE_INTERVAL * 60)

if __name__ == "__main__":
    main() 


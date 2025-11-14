"""
IP Address Validation Module
Handles IP address validation and subnet operations
"""
import re
import ipaddress
from typing import List, Tuple


class IPValidator:
    """Validates IP addresses and manages IP lists"""

    @staticmethod
    def is_valid_ip(ip: str) -> Tuple[bool, str]:
        """
        Validate a single IP address

        Args:
            ip: IP address string to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            ip_obj = ipaddress.ip_address(ip.strip())

            # Check for reserved/invalid ranges
            if ip_obj.is_loopback:
                return False, f"{ip} is a loopback address"
            if ip_obj.is_link_local:
                return False, f"{ip} is a link-local address"
            if ip_obj.is_multicast:
                return False, f"{ip} is a multicast address"
            if ip_obj.is_reserved:
                return False, f"{ip} is a reserved address"

            return True, ""

        except ValueError as e:
            return False, f"Invalid IP format: {str(e)}"

    @staticmethod
    def validate_ip_list(ips: List[str]) -> Tuple[List[str], List[str]]:
        """
        Validate a list of IP addresses

        Args:
            ips: List of IP address strings

        Returns:
            Tuple of (valid_ips, invalid_ips_with_reasons)
        """
        valid_ips = []
        invalid_ips = []

        for ip in ips:
            ip = ip.strip()
            if not ip or ip.startswith('#'):  # Skip empty lines and comments
                continue

            is_valid, error_msg = IPValidator.is_valid_ip(ip)
            if is_valid:
                valid_ips.append(ip)
            else:
                invalid_ips.append(f"{ip}: {error_msg}")

        return valid_ips, invalid_ips

    @staticmethod
    def expand_subnet(subnet: str) -> List[str]:
        """
        Expand a subnet into individual IP addresses

        Args:
            subnet: Subnet in CIDR notation (e.g., '192.168.1.0/24')

        Returns:
            List of IP addresses in the subnet
        """
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []

    @staticmethod
    def load_from_file(file_path: str) -> Tuple[List[str], List[str]]:
        """
        Load and validate IP addresses from a file

        Args:
            file_path: Path to file containing IP addresses

        Returns:
            Tuple of (valid_ips, errors)
        """
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()

            all_ips = []
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Check if it's a subnet
                if '/' in line:
                    all_ips.extend(IPValidator.expand_subnet(line))
                else:
                    all_ips.append(line)

            return IPValidator.validate_ip_list(all_ips)

        except FileNotFoundError:
            return [], [f"File not found: {file_path}"]
        except Exception as e:
            return [], [f"Error reading file: {str(e)}"]

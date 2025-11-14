"""
Configuration Management Module
Handles saving and loading of configuration profiles
"""
import json
import os
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
import base64
import hashlib


@dataclass
class Profile:
    """Configuration profile"""
    name: str
    description: str = ""
    ip_list: List[str] = None
    commands: List[str] = None
    username: str = ""
    port: int = 22
    concurrent_connections: int = 5
    ping_timeout: int = 2
    ssh_timeout: int = 30

    def __post_init__(self):
        if self.ip_list is None:
            self.ip_list = []
        if self.commands is None:
            self.commands = []


class ConfigManager:
    """Manages configuration profiles and secure credential storage"""

    def __init__(self, config_dir: str = None):
        """
        Initialize configuration manager

        Args:
            config_dir: Directory to store configuration files
        """
        if config_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            config_dir = os.path.join(base_dir, 'data', 'profiles')

        self.config_dir = config_dir
        os.makedirs(config_dir, exist_ok=True)

        self.key_file = os.path.join(config_dir, '.key')
        self._init_encryption()

    def _init_encryption(self):
        """Initialize encryption key"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
            # Make key file readable only by owner
            os.chmod(self.key_file, 0o600)

        self.cipher = Fernet(self.key)

    def encrypt_password(self, password: str) -> str:
        """Encrypt a password"""
        return self.cipher.encrypt(password.encode()).decode()

    def decrypt_password(self, encrypted: str) -> str:
        """Decrypt a password"""
        try:
            return self.cipher.decrypt(encrypted.encode()).decode()
        except Exception:
            return ""

    def save_profile(self, profile: Profile, password: str = "") -> bool:
        """
        Save a configuration profile

        Args:
            profile: Profile to save
            password: Password to encrypt (optional)

        Returns:
            True if saved successfully
        """
        try:
            profile_data = asdict(profile)

            # Encrypt password if provided
            if password:
                profile_data['encrypted_password'] = self.encrypt_password(password)

            file_path = os.path.join(self.config_dir, f"{profile.name}.json")
            with open(file_path, 'w') as f:
                json.dump(profile_data, f, indent=2)

            return True

        except Exception as e:
            print(f"Error saving profile: {e}")
            return False

    def load_profile(self, name: str) -> Optional[tuple[Profile, str]]:
        """
        Load a configuration profile

        Args:
            name: Profile name

        Returns:
            Tuple of (Profile, decrypted_password) or None if not found
        """
        try:
            file_path = os.path.join(self.config_dir, f"{name}.json")

            if not os.path.exists(file_path):
                return None

            with open(file_path, 'r') as f:
                data = json.load(f)

            # Extract and decrypt password
            password = ""
            if 'encrypted_password' in data:
                password = self.decrypt_password(data.pop('encrypted_password'))

            profile = Profile(**data)
            return profile, password

        except Exception as e:
            print(f"Error loading profile: {e}")
            return None

    def list_profiles(self) -> List[str]:
        """
        List all available profiles

        Returns:
            List of profile names
        """
        try:
            profiles = []
            for file in os.listdir(self.config_dir):
                if file.endswith('.json'):
                    profiles.append(file[:-5])  # Remove .json extension
            return sorted(profiles)
        except Exception:
            return []

    def delete_profile(self, name: str) -> bool:
        """
        Delete a profile

        Args:
            name: Profile name

        Returns:
            True if deleted successfully
        """
        try:
            file_path = os.path.join(self.config_dir, f"{name}.json")
            if os.path.exists(file_path):
                os.remove(file_path)
                return True
            return False
        except Exception:
            return False

    def export_profile(self, name: str, export_path: str, include_password: bool = False) -> bool:
        """
        Export a profile to a file

        Args:
            name: Profile name
            export_path: Path to export to
            include_password: Whether to include encrypted password

        Returns:
            True if exported successfully
        """
        try:
            result = self.load_profile(name)
            if not result:
                return False

            profile, password = result
            profile_data = asdict(profile)

            if include_password and password:
                profile_data['encrypted_password'] = self.encrypt_password(password)

            with open(export_path, 'w') as f:
                json.dump(profile_data, f, indent=2)

            return True

        except Exception:
            return False

"""
Command Template Manager
Handles command templates and history
"""
import os
import json
from datetime import datetime
from typing import List, Dict, Optional


class TemplateManager:
    """Manages command templates"""

    def __init__(self, template_dir: str = None):
        """
        Initialize template manager

        Args:
            template_dir: Directory to store templates
        """
        if template_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            template_dir = os.path.join(base_dir, 'src', 'templates')

        self.template_dir = template_dir
        os.makedirs(template_dir, exist_ok=True)

        # Load default templates
        self._create_default_templates()

    def _create_default_templates(self):
        """Create default command templates if they don't exist"""
        default_templates = {
            'vlan_setup': {
                'name': 'VLAN Setup',
                'description': 'Configure multiple VLANs',
                'commands': [
                    'enable',
                    'conf t',
                    'vlan 10',
                    'name MANAGEMENT',
                    'vlan 20',
                    'name USERS',
                    'vlan 30',
                    'name SERVERS',
                    'exit'
                ]
            },
            'ntp_config': {
                'name': 'NTP Configuration',
                'description': 'Configure NTP server',
                'commands': [
                    'enable',
                    'conf t',
                    'ntp server 192.168.1.1',
                    'exit'
                ]
            },
            'backup_config': {
                'name': 'Backup Configuration',
                'description': 'Save running config',
                'commands': [
                    'enable',
                    'copy running-config startup-config'
                ]
            },
            'show_info': {
                'name': 'Show Device Info',
                'description': 'Display device information',
                'commands': [
                    'show version',
                    'show ip interface brief',
                    'show vlan brief',
                    'show running-config'
                ]
            }
        }

        for template_id, template_data in default_templates.items():
            template_file = os.path.join(self.template_dir, f'{template_id}.json')
            if not os.path.exists(template_file):
                with open(template_file, 'w') as f:
                    json.dump(template_data, f, indent=2)

    def save_template(self, template_id: str, name: str, description: str, commands: List[str]) -> bool:
        """
        Save a command template

        Args:
            template_id: Unique template identifier
            name: Template name
            description: Template description
            commands: List of commands

        Returns:
            True if saved successfully
        """
        try:
            template_data = {
                'name': name,
                'description': description,
                'commands': commands
            }

            template_file = os.path.join(self.template_dir, f'{template_id}.json')
            with open(template_file, 'w') as f:
                json.dump(template_data, f, indent=2)

            return True

        except Exception as e:
            print(f"Error saving template: {e}")
            return False

    def load_template(self, template_id: str) -> Optional[Dict]:
        """
        Load a command template

        Args:
            template_id: Template identifier

        Returns:
            Template data dictionary or None
        """
        try:
            template_file = os.path.join(self.template_dir, f'{template_id}.json')

            if not os.path.exists(template_file):
                return None

            with open(template_file, 'r') as f:
                return json.load(f)

        except Exception as e:
            print(f"Error loading template: {e}")
            return None

    def list_templates(self) -> List[Dict[str, str]]:
        """
        List all available templates

        Returns:
            List of template info dictionaries
        """
        templates = []

        try:
            for file in os.listdir(self.template_dir):
                if file.endswith('.json'):
                    template_id = file[:-5]
                    template_data = self.load_template(template_id)

                    if template_data:
                        templates.append({
                            'id': template_id,
                            'name': template_data.get('name', template_id),
                            'description': template_data.get('description', '')
                        })

        except Exception:
            pass

        return sorted(templates, key=lambda x: x['name'])

    def delete_template(self, template_id: str) -> bool:
        """
        Delete a template

        Args:
            template_id: Template identifier

        Returns:
            True if deleted successfully
        """
        try:
            template_file = os.path.join(self.template_dir, f'{template_id}.json')
            if os.path.exists(template_file):
                os.remove(template_file)
                return True
            return False
        except Exception:
            return False


class HistoryManager:
    """Manages execution history"""

    def __init__(self, history_dir: str = None):
        """
        Initialize history manager

        Args:
            history_dir: Directory to store history
        """
        if history_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            history_dir = os.path.join(base_dir, 'data', 'history')

        self.history_dir = history_dir
        os.makedirs(history_dir, exist_ok=True)

        self.history_file = os.path.join(history_dir, 'execution_history.json')
        self.history = self._load_history()

    def _load_history(self) -> List[Dict]:
        """Load execution history from file"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass

        return []

    def _save_history(self):
        """Save execution history to file"""
        try:
            # Keep only last 100 entries
            if len(self.history) > 100:
                self.history = self.history[-100:]

            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2)

        except Exception as e:
            print(f"Error saving history: {e}")

    def add_entry(self, ips: List[str], commands: List[str], profile_name: str = ""):
        """
        Add an execution entry to history

        Args:
            ips: List of IP addresses
            commands: List of commands executed
            profile_name: Name of profile used (if any)
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'profile': profile_name,
            'ip_count': len(ips),
            'command_count': len(commands),
            'ips': ips[:5],  # Store first 5 IPs
            'commands': commands[:10]  # Store first 10 commands
        }

        self.history.append(entry)
        self._save_history()

    def get_recent(self, count: int = 10) -> List[Dict]:
        """
        Get recent execution history

        Args:
            count: Number of recent entries to retrieve

        Returns:
            List of history entries
        """
        return self.history[-count:]

    def clear_history(self):
        """Clear all history"""
        self.history = []
        self._save_history()

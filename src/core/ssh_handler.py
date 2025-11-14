"""
SSH Connection Handler Module
Manages SSH connections and command execution
"""
import paramiko
import time
import re
from typing import List, Optional, Callable, Dict
from dataclasses import dataclass
from datetime import datetime
import threading
from queue import Queue


@dataclass
class SSHCredentials:
    """SSH authentication credentials"""
    username: str
    password: str
    enable_password: Optional[str] = None
    port: int = 22


@dataclass
class SSHResult:
    """Result of SSH command execution"""
    ip: str
    success: bool
    output: str
    error: Optional[str] = None
    timestamp: datetime = None
    execution_time: float = 0.0

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class SSHHandler:
    """Handles SSH connections and command execution"""

    def __init__(self, credentials: SSHCredentials, timeout: int = 30):
        """
        Initialize SSH handler

        Args:
            credentials: SSH authentication credentials
            timeout: Connection timeout in seconds
        """
        self.credentials = credentials
        self.timeout = timeout
        self.shell_delay = 2  # Delay between commands in seconds

    def connect_and_execute(
        self,
        ip: str,
        commands: List[str],
        enable_mode: bool = True
    ) -> SSHResult:
        """
        Connect to device and execute commands

        Args:
            ip: IP address of device
            commands: List of commands to execute
            enable_mode: Whether to enter enable mode

        Returns:
            SSHResult object with execution results
        """
        start_time = time.time()
        client = None

        try:
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect
            client.connect(
                ip,
                port=self.credentials.port,
                username=self.credentials.username,
                password=self.credentials.password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )

            # Invoke shell
            shell = client.invoke_shell()
            time.sleep(self.shell_delay)

            # Clear initial output
            if shell.recv_ready():
                shell.recv(65535)

            # Enter enable mode if needed
            if enable_mode and self.credentials.enable_password:
                shell.send("enable\n")
                time.sleep(1)
                shell.send(f"{self.credentials.enable_password}\n")
                time.sleep(1)

            # Execute commands
            output_buffer = []
            for cmd in commands:
                cmd = cmd.strip()
                if not cmd or cmd.startswith('#'):
                    continue

                shell.send(f"{cmd}\n")
                time.sleep(self.shell_delay)

                # Collect output
                if shell.recv_ready():
                    output = shell.recv(65535).decode('utf-8', errors='ignore')
                    output_buffer.append(f"Command: {cmd}\n{output}\n")

            # Get final output
            time.sleep(1)
            if shell.recv_ready():
                final_output = shell.recv(65535).decode('utf-8', errors='ignore')
                output_buffer.append(final_output)

            full_output = '\n'.join(output_buffer)

            # Check for errors
            error = None
            if re.search(r'% Invalid|% Incomplete|% Ambiguous', full_output):
                error = "Command syntax error detected"

            execution_time = time.time() - start_time

            return SSHResult(
                ip=ip,
                success=error is None,
                output=full_output,
                error=error,
                execution_time=execution_time
            )

        except paramiko.AuthenticationException:
            return SSHResult(
                ip=ip,
                success=False,
                output="",
                error="Authentication failed - invalid credentials",
                execution_time=time.time() - start_time
            )

        except paramiko.SSHException as e:
            return SSHResult(
                ip=ip,
                success=False,
                output="",
                error=f"SSH error: {str(e)}",
                execution_time=time.time() - start_time
            )

        except Exception as e:
            return SSHResult(
                ip=ip,
                success=False,
                output="",
                error=f"Unexpected error: {str(e)}",
                execution_time=time.time() - start_time
            )

        finally:
            if client:
                client.close()

    def execute_multiple(
        self,
        ips: List[str],
        commands: List[str],
        callback: Optional[Callable[[SSHResult], None]] = None,
        max_workers: int = 5
    ) -> List[SSHResult]:
        """
        Execute commands on multiple devices concurrently

        Args:
            ips: List of IP addresses
            commands: List of commands to execute
            callback: Optional callback function for each result
            max_workers: Maximum number of concurrent connections

        Returns:
            List of SSHResult objects
        """
        results = []
        queue = Queue()
        lock = threading.Lock()

        for ip in ips:
            queue.put(ip)

        def worker():
            while not queue.empty():
                try:
                    ip = queue.get_nowait()
                    result = self.connect_and_execute(ip, commands)

                    with lock:
                        results.append(result)

                    if callback:
                        callback(result)

                    queue.task_done()
                except:
                    break

        threads = []
        for _ in range(min(max_workers, len(ips))):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return results

"""
Network Connectivity Module
Handles ping operations and reachability checks
"""
import subprocess
import platform
import threading
from typing import Dict, Callable, Optional
from queue import Queue
import time


class ConnectivityChecker:
    """Handles network connectivity checks"""

    def __init__(self, timeout: int = 2, count: int = 2):
        """
        Initialize connectivity checker

        Args:
            timeout: Ping timeout in seconds
            count: Number of ping packets
        """
        self.timeout = timeout
        self.count = count
        self.use_fast_ping = False
        self._check_fast_ping_available()

    def _check_fast_ping_available(self):
        """Check if C++ fast ping module is available"""
        try:
            import sys
            import os
            bin_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'bin')
            if os.path.exists(os.path.join(bin_path, 'fast_ping.so')):
                sys.path.insert(0, bin_path)
                import fast_ping
                self.fast_ping = fast_ping
                self.use_fast_ping = True
        except ImportError:
            self.use_fast_ping = False

    def ping(self, ip: str) -> tuple[bool, float]:
        """
        Ping a single IP address

        Args:
            ip: IP address to ping

        Returns:
            Tuple of (is_reachable, response_time_ms)
        """
        if self.use_fast_ping:
            return self._fast_ping(ip)
        else:
            return self._system_ping(ip)

    def _fast_ping(self, ip: str) -> tuple[bool, float]:
        """Use C++ fast ping module"""
        try:
            result = self.fast_ping.ping(ip, self.timeout)
            return result['reachable'], result['time_ms']
        except Exception:
            return self._system_ping(ip)

    def _system_ping(self, ip: str) -> tuple[bool, float]:
        """Use system ping command"""
        system = platform.system().lower()

        if system == 'windows':
            cmd = f'ping -n {self.count} -w {self.timeout * 1000} {ip}'
        else:
            cmd = f'ping -c {self.count} -W {self.timeout} {ip}'

        start_time = time.time()
        try:
            result = subprocess.call(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=True,
                timeout=self.timeout * self.count + 2
            )
            elapsed = (time.time() - start_time) * 1000
            return result == 0, elapsed

        except subprocess.TimeoutExpired:
            return False, 0.0
        except Exception:
            return False, 0.0

    def ping_multiple(
        self,
        ips: list[str],
        callback: Optional[Callable[[str, bool, float], None]] = None,
        max_workers: int = 10
    ) -> Dict[str, tuple[bool, float]]:
        """
        Ping multiple IP addresses concurrently

        Args:
            ips: List of IP addresses to ping
            callback: Optional callback function(ip, is_reachable, time_ms)
            max_workers: Maximum number of concurrent ping operations

        Returns:
            Dictionary mapping IP to (is_reachable, response_time_ms)
        """
        results = {}
        queue = Queue()

        for ip in ips:
            queue.put(ip)

        def worker():
            while not queue.empty():
                try:
                    ip = queue.get_nowait()
                    is_reachable, time_ms = self.ping(ip)
                    results[ip] = (is_reachable, time_ms)

                    if callback:
                        callback(ip, is_reachable, time_ms)

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

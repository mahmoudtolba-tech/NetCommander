"""
Logging and Reporting Module
Handles logging operations and report generation
"""
import logging
import os
from datetime import datetime
from typing import List
import csv
import json
from ..core.ssh_handler import SSHResult


class AutomationLogger:
    """Handles logging for automation operations"""

    def __init__(self, log_dir: str = None):
        """
        Initialize logger

        Args:
            log_dir: Directory to store log files
        """
        if log_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            log_dir = os.path.join(base_dir, 'data', 'logs')

        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        # Setup logging
        self.setup_logging()

    def setup_logging(self):
        """Setup logging configuration"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(self.log_dir, f'automation_{timestamp}.log')

        # Create logger
        self.logger = logging.getLogger('AutomationNet')
        self.logger.setLevel(logging.DEBUG)

        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)

    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)

    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)

    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)


class ReportGenerator:
    """Generates reports from SSH execution results"""

    @staticmethod
    def generate_text_report(results: List[SSHResult], output_file: str):
        """
        Generate a text report

        Args:
            results: List of SSH results
            output_file: Output file path
        """
        with open(output_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("AutomationNet Execution Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")

            # Summary
            total = len(results)
            successful = sum(1 for r in results if r.success)
            failed = total - successful

            f.write(f"Summary:\n")
            f.write(f"  Total Devices: {total}\n")
            f.write(f"  Successful: {successful}\n")
            f.write(f"  Failed: {failed}\n")
            f.write(f"  Success Rate: {(successful/total*100):.2f}%\n\n")

            # Individual results
            f.write("\n" + "=" * 80 + "\n")
            f.write("Device Results:\n")
            f.write("=" * 80 + "\n\n")

            for result in results:
                f.write(f"Device: {result.ip}\n")
                f.write(f"Status: {'SUCCESS' if result.success else 'FAILED'}\n")
                f.write(f"Execution Time: {result.execution_time:.2f}s\n")
                f.write(f"Timestamp: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")

                if result.error:
                    f.write(f"Error: {result.error}\n")

                if result.output:
                    f.write("\nOutput:\n")
                    f.write("-" * 40 + "\n")
                    f.write(result.output)
                    f.write("\n" + "-" * 40 + "\n")

                f.write("\n" + "=" * 80 + "\n\n")

    @staticmethod
    def generate_csv_report(results: List[SSHResult], output_file: str):
        """
        Generate a CSV report

        Args:
            results: List of SSH results
            output_file: Output file path
        """
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                'IP Address',
                'Status',
                'Execution Time (s)',
                'Timestamp',
                'Error',
                'Output Length'
            ])

            # Data
            for result in results:
                writer.writerow([
                    result.ip,
                    'SUCCESS' if result.success else 'FAILED',
                    f'{result.execution_time:.2f}',
                    result.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    result.error or '',
                    len(result.output)
                ])

    @staticmethod
    def generate_json_report(results: List[SSHResult], output_file: str):
        """
        Generate a JSON report

        Args:
            results: List of SSH results
            output_file: Output file path
        """
        report_data = {
            'generated': datetime.now().isoformat(),
            'summary': {
                'total': len(results),
                'successful': sum(1 for r in results if r.success),
                'failed': sum(1 for r in results if not r.success)
            },
            'results': [
                {
                    'ip': r.ip,
                    'success': r.success,
                    'execution_time': r.execution_time,
                    'timestamp': r.timestamp.isoformat(),
                    'error': r.error,
                    'output': r.output
                }
                for r in results
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)

    @staticmethod
    def generate_html_report(results: List[SSHResult], output_file: str):
        """
        Generate an HTML report

        Args:
            results: List of SSH results
            output_file: Output file path
        """
        total = len(results)
        successful = sum(1 for r in results if r.success)
        failed = total - successful

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AutomationNet Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        .summary {{
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary-item {{
            display: inline-block;
            margin: 10px 20px;
        }}
        .success {{
            color: #4CAF50;
            font-weight: bold;
        }}
        .failed {{
            color: #f44336;
            font-weight: bold;
        }}
        .device {{
            border: 1px solid #ddd;
            margin: 15px 0;
            padding: 15px;
            border-radius: 5px;
        }}
        .device-header {{
            font-weight: bold;
            font-size: 18px;
            margin-bottom: 10px;
        }}
        .output {{
            background-color: #f5f5f5;
            padding: 10px;
            border-left: 3px solid #4CAF50;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
        }}
        .error {{
            color: #f44336;
            background-color: #ffebee;
            padding: 10px;
            border-left: 3px solid #f44336;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AutomationNet Execution Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="summary">
            <h2>Summary</h2>
            <div class="summary-item">Total Devices: <strong>{total}</strong></div>
            <div class="summary-item">Successful: <span class="success">{successful}</span></div>
            <div class="summary-item">Failed: <span class="failed">{failed}</span></div>
            <div class="summary-item">Success Rate: <strong>{(successful/total*100):.2f}%</strong></div>
        </div>

        <h2>Device Results</h2>
"""

        for result in results:
            status_class = 'success' if result.success else 'failed'
            status_text = 'SUCCESS' if result.success else 'FAILED'

            html += f"""
        <div class="device">
            <div class="device-header">
                {result.ip} - <span class="{status_class}">{status_text}</span>
            </div>
            <p><strong>Execution Time:</strong> {result.execution_time:.2f}s</p>
            <p><strong>Timestamp:</strong> {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
"""

            if result.error:
                html += f'            <div class="error"><strong>Error:</strong> {result.error}</div>\n'

            if result.output:
                html += f'            <div class="output">{result.output}</div>\n'

            html += '        </div>\n'

        html += """
    </div>
</body>
</html>
"""

        with open(output_file, 'w') as f:
            f.write(html)

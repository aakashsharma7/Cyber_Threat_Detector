import re
from typing import List, Dict, Any
import logging
from datetime import datetime, timedelta
import pytz
from app.core.config import settings

logger = logging.getLogger(__name__)

class LogScanner:
    def __init__(self):
        self.log_patterns = {
            'apache': r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>.*?)\] "(?P<method>\w+) (?P<url>.*?) HTTP/\d\.\d" (?P<status>\d+) (?P<size>\d+)',
            'nginx': r'(?P<ip>[\d\.]+) - (?P<user>[\w-]+) \[(?P<timestamp>.*?)\] "(?P<method>\w+) (?P<url>.*?) HTTP/\d\.\d" (?P<status>\d+) (?P<size>\d+)',
            'iis': r'(?P<timestamp>.*?) (?P<ip>[\d\.]+) (?P<method>\w+) (?P<url>.*?) - (?P<status>\d+)',
        }
        
        self.suspicious_patterns = [
            r'\.php\?',
            r'\.asp\?',
            r'\.jsp\?',
            r'\.exe',
            r'\.dll',
            r'\.bat',
            r'\.cmd',
            r'\.vbs',
            r'\.js\?',
            r'\.hta',
            r'\.htaccess',
            r'\.env',
            r'\.git',
            r'\.svn',
            r'\.bak',
            r'\.old',
            r'\.tmp',
            r'\.log',
            r'\.ini',
            r'\.config',
            r'\.xml',
            r'\.json',
            r'\.sql',
            r'\.db',
            r'\.sqlite',
            r'\.mdb',
            r'\.accdb',
            r'\.xls',
            r'\.xlsx',
            r'\.doc',
            r'\.docx',
            r'\.pdf',
            r'\.zip',
            r'\.rar',
            r'\.7z',
            r'\.tar',
            r'\.gz',
            r'\.bz2',
            r'\.xz',
            r'\.iso',
            r'\.img',
            r'\.vhd',
            r'\.vmdk',
            r'\.ova',
            r'\.ovf',
            r'\.vmx',
            r'\.vbox',
            r'\.vdi',
            r'\.vhd',
            r'\.vhdx',
            r'\.vmdk',
            r'\.vmsd',
            r'\.vmsn',
            r'\.vmss',
            r'\.vmx',
            r'\.vmxf',
            r'\.nvram',
            r'\.vswp',
            r'\.vmem',
            r'\.vmem',
            r'\.vmem',
            r'\.vmem',
            r'\.vmem',
        ]

    def scan_logs(self, log_file: str = None) -> List[Dict[str, Any]]:
        """Scan log files for suspicious activity"""
        try:
            # In a real implementation, this would read from actual log files
            # For now, we'll return some sample data
            return self._generate_sample_logs()
        except Exception as e:
            logger.error(f"Error scanning logs: {str(e)}")
            return []

    def _parse_log_line(self, line: str, log_type: str = 'apache') -> Dict[str, Any]:
        """Parse a single log line"""
        try:
            pattern = self.log_patterns.get(log_type)
            if not pattern:
                return None

            match = re.match(pattern, line)
            if not match:
                return None

            data = match.groupdict()
            
            # Convert timestamp to datetime
            try:
                data['timestamp'] = datetime.strptime(
                    data['timestamp'],
                    '%d/%b/%Y:%H:%M:%S %z'
                )
            except ValueError:
                data['timestamp'] = datetime.now(pytz.UTC)

            # Check for suspicious patterns in URL
            data['has_suspicious_patterns'] = any(
                re.search(pattern, data['url'], re.IGNORECASE)
                for pattern in self.suspicious_patterns
            )

            return data
        except Exception as e:
            logger.error(f"Error parsing log line: {str(e)}")
            return None

    def _generate_sample_logs(self) -> List[Dict[str, Any]]:
        """Generate sample log entries for testing"""
        now = datetime.now(pytz.UTC)
        return [
            {
                'timestamp': now - timedelta(minutes=i),
                'ip': f'192.168.1.{i}',
                'method': 'GET',
                'url': '/api/v1/users',
                'status': 200,
                'size': 1024,
                'has_suspicious_patterns': False,
                'request_count': 1,
                'failed_login_attempts': 0,
                'unique_ips': 1,
                'request_rate': 1.0,
                'time_since_last_request': 60,
            }
            for i in range(10)
        ] 
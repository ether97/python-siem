import re
from collections import defaultdict
from datetime import datetime, timedelta

# Example log line format (Ubuntu auth.log style):
# "Apr 24 10:01:12 myhost sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"

def parse_log_line(line):
	match = re.search(r'Failed password.*from (\d+\.\d+\.\d+\.\d+)', line)
	if match:
		ip = match.group(1)
		return ip
	return None

def detect_brute_force(logs, threshold=3, window_minutes=1):
	attempts = defaultdict(list)
	now = datetime.now()

	for line in logs:
		ip = parse_log_line(line)
		if ip:
			attempts[ip].append(now)

	for ip, times in attempts.items():
		if len(times) >= threshold:
			print(f"[ALERT] Potential brute-force attack from {ip} ({len(times)} attempts)")

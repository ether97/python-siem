import os
import re
import json
from collections import defaultdict
from datetime import datetime, timedelta

def load_file(filename):
    # resolve the absolute path relative to the script location
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, '..', '..', 'frontend', filename)
    file_path = os.path.normpath(file_path) # clean up path

    try:
        # Open and load the JSON file
        with open(file_path, 'r') as f:
            return set(json.load(f))
    except json.JSONDecodeError:
        print("JSONDecodeError")
        return set()
    except FileNotFoundError:
        print("FileNotFoundError")
        return set()
    except Exception as e:
        print(f"Error loading blacklist: {e}")
        return set()

def convert_to_datetime_obj(timestamp):
    fmt = "%H:%M:%S"
    year = datetime.now().year
    datetime_obj = datetime.strptime(f"{year} {timestamp}", f"%Y {fmt}")
    return datetime_obj

# Parse log line to extract timestamp and IP address
def parse_log_line(line):
    # match = re.search(r'^(\w{3} +\d+ \d+:\d+:\d+).*from (\d+\.\d+\.\d+\.\d+)', line)
    # example log:
    # 2025-05-04T19:18:01.610446-04:00 ZEUS sshd[15682]: Failed password for invalid user admin from 192.168.1.101 port 22 ssh2

    # Update regex to match the correct timestamp format with 'T' and the IP address
    pattern = r'T(\d{2}:\d{2}:\d{2}).*from (\d+\.\d+\.\d+\.\d+)'
    
    match = re.search(pattern, line)
    if match:
        timestamp = convert_to_datetime_obj(match.group(1))  # Extract the time part
        ip = match.group(2)  # Extract the IP address
        return timestamp, ip

    return None, None

def detect_brute_force(logs, threshold_seconds=60, threshold_count=3):
    blacklist = load_file('blacklist.json')
    whitelist = load_file('whitelist.json') 

    print("current blacklist:", blacklist)
    print("current whitelist:", whitelist)
    attempts = {}
    now = datetime.now()

    for line in logs:
        timestamp, ip = parse_log_line(line)
        if ip:
            if ip in whitelist:
                print(f"[ALLOWED] {ip} is in the whitelist, ignoring.")
                continue
            if ip in blacklist:
                print(f"[ALERT] {ip} is in the blacklist, logging.")
                if ip in attempts:
                    attempts[ip]["timestamps"].append(timestamp)
                    attempts[ip]["count"] += 1
                else:
                    attempts[ip] = {"timestamps": [timestamp], "count": 1}

    # for ip, times in attempts.items():
     #   if len(times) >= threshold:
     #       print(f"[ALERT] Potential brute-force attack from {ip} ({len(times)} attempts)")

    for ip, data in attempts.items():
        # print(f"IP: {ip}, Time: {data['timestamps']}, Count: {data['count']}")
        if data['count'] >= threshold_count:
            within_threshold = (data['timestamps'][-1] - data['timestamps'][0]).total_seconds() <= threshold_seconds
            if within_threshold:
                print(f"[ALERT] Potential brute-force attack from {ip}: {data['count']} attempts")




































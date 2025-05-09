from detectors.brute_force import detect_brute_force

def read_logs(log_file):
	with open(log_file, 'r') as f:
		return f.readlines()

if __name__ == "__main__":
	logs = read_logs('logs/auth.log/failed_logins/192.168.1.101')
	detect_brute_force(logs)

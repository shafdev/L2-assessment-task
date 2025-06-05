import re
from datetime import datetime

def parse_log_line(log_line):
    pattern = r'(\d+\.\d+\.\d+\.\d+) - (\w+) \[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\] "(\w+\.\w+\.\w+)" "(\w+) (/[^\s]+) (HTTP/\d\.\d)" (\d+) (\d+) (\d+)' #
    

    match = re.match(pattern, log_line)
    if match:
        # print(match.groups())
        # return
        ip, action, timestamp_str, domain, method, path, protocol, status, bytes_sent, unknown = match.groups()
        timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        return {
            'timestamp': timestamp,
            'status':  int(status),
            'ip': ip,
            'method':method,
            'bytes_sent':int(bytes_sent),
            'path':path
        }
    else:
        return None

def is_error_status(status):
    return status >= 400 and status <= 599

def monitor_logs(log_file):
    with open(log_file, 'r') as f:
        lines = f.readlines()
    
    window_size = 5
    error_threshold = 0.10
    current_window_start = None
    window_requests = 0
    window_errors = 0

    for line in lines:
        log_data = parse_log_line(line.strip())
        if log_data is None:
            continue
        
        timestamp = log_data['timestamp']
        status = log_data['status']

        if current_window_start is None:
            current_window_start = timestamp
        
        time_diff = (timestamp - current_window_start).total_seconds() / 60
        if time_diff > window_size:
            if window_requests > 0:
                error_rate = window_errors / window_requests
                if error_rate > error_threshold:
                    print(f"Alert! Error rate {error_rate}% exceeds threshold at {current_window_start}")
            current_window_start = timestamp
            window_requests = 0
            window_errors = 0

        window_requests += 1
        if is_error_status(status):
            window_errors += 1

    if window_requests > 0:
        error_rate = window_errors / window_requests
        if error_rate > error_threshold:
            print(f"Alert! Error rate {error_rate}% exceeds threshold at {current_window_start}")

if __name__ == '__name__':
    monitor_logs('nginx_access.log')

#Bug: status is a string, but function is_error_status() compares it numerically
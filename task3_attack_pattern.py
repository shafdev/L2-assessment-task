from datetime import timedelta
from collections import defaultdict, deque
from python_monitor import is_error_status, parse_log_line



# Thresholds for suspicious activity
requests_per_min_threshold = 100
err_rate_threshold = 0.5
suspicious_endpoint = ['/admin', '/login',]



def detect_attack_patterns(log_file):
    ip_requests = defaultdict(deque)  # ip -> deque of timestamps
    ip_error_counts = defaultdict(int)
    ip_total_counts = defaultdict(int)
    ip_suspicious_endpoint_counts = defaultdict(int)

    suspicious_ips = set()

    with open(log_file) as f:
        for line in f:
            parsed = parse_log_line(line.strip())
            # print(parsed)c
            if parsed is None:
                continue
            ip = parsed['ip']
            status = parsed['status']
            path = parsed['path']
            timestamp = parsed['timestamp']

            # Track requests by IP with timestamps
            ip_requests[ip].append(timestamp)
            ip_total_counts[ip] += 1

            if is_error_status(status):
                ip_error_counts[ip] += 1


            # Track suspicious endpoint hits
            for endpoint in suspicious_endpoint:
                if path.startswith(endpoint):
                    ip_suspicious_endpoint_counts[ip] += 1

            # Clean up old timestamps outside the 1-minute window
            one_min_ago = timestamp - timedelta(minutes=1)
            while ip_requests[ip] and ip_requests[ip][0] < one_min_ago:
                ip_requests[ip].popleft()

            # Check if IP has excessive requests in last minute
            if len(ip_requests[ip]) > requests_per_min_threshold:
                suspicious_ips.add(ip)

            # Check error rate for IP if enough requests recorded
            if ip_total_counts[ip] >= 20:
                error_rate = ip_error_counts[ip] / ip_total_counts[ip]
                if error_rate > err_rate_threshold:
                    suspicious_ips.add(ip)

            # Check suspicious endpoint attempts
            if ip_suspicious_endpoint_counts[ip] > 10:
                suspicious_ips.add(ip)

    # Output suspicious IPs and why
    print("Suspicious IPs detected:")
    for ip in suspicious_ips:
        print(f"IP: {ip}")
        print(f"  Total requests: {ip_total_counts[ip]}")
        print(f"  Errors: {ip_error_counts[ip]} (error rate: {ip_error_counts[ip] / ip_total_counts[ip]:.2f})")
        print(f"  Requests in last minute: {len(ip_requests[ip])}")
        print(f"  Suspicious endpoint hits: {ip_suspicious_endpoint_counts[ip]}")
        print()

if __name__ == "__main__":
    detect_attack_patterns('nginx_access.log')

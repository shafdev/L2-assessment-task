from python_monitor import is_error_status, parse_log_line
from collections import defaultdict

def analyze_log(file_name):
    ip_count_map = defaultdict(int)
    total_req_count = 0
    total_error_code = 0 
    total_get_resp_size = 0
    total_get_resp_count = 0
    top_n_ips = 6
    with open(file_name, 'r') as file:
        for line in file:
            new_line = parse_log_line(line)
            if new_line is None:
                continue
            ip = new_line['ip']
            status = new_line['status']
            method = new_line['method']
            bytes_sent = new_line['bytes_sent']
        
            if (method == 'GET'):
                total_get_resp_count += 1
                total_get_resp_size += bytes_sent
                
            if is_error_status(status):
                total_error_code +=1

            total_req_count += 1

            ip_count_map[ip] += 1  

    sorted_by_values = dict(sorted(ip_count_map.items(), key=lambda item: item[1], reverse=True))
    top_request_ips = list(sorted_by_values.items())[:top_n_ips]
    avg_resp_size = total_get_resp_size / total_get_resp_count
    error_percent = (total_error_code / total_req_count)*100
    error_percent = round(error_percent, 2)
    print('Top IPs:')
    for indx, ip in enumerate(top_request_ips):
        print(f"  {indx+1}->",f"IP :{ip[0]}"," ",f"Count :{ip[1]}")

    print(f"average response size in bytes: {avg_resp_size}")
    print(f"percentage of requests with status codes in the 400-599 range: {error_percent} %")


if __name__ == '__main__':
    analyze_log('nginx_access.log')



import sys
import pandas as pd
import re
try:
    from log_utiliti import get_log_file_path_from_cmd_line, filter_log_by_regex
except ImportError:
    print("Error: log_utils module not found. Ensure it is in the same directory or installed.")
    sys.exit(1)

def main():
    log_file = get_log_file_path_from_cmd_line(1)
    
    # Step 5: Investigate the Gateway Firewall Log
    print(" Investigating the Gateway Firewall Log for SSHD entries...")
    filter_log_by_regex(log_file, 'sshd', ignore_case=True, print_summary=True, print_records=True)
    
    print("\n Investigating for invalid user attempts...")
    filter_log_by_regex(log_file, 'invalid user', ignore_case=True, print_summary=True, print_records=True)
    
    print("\n Checking if all invalid user attempts are from the same IP...")
    filter_log_by_regex(log_file, 'invalid user.*220.195.35.40', ignore_case=True, print_summary=True, print_records=True)
    
    print("\n Looking for any error messages in the log...")
    filter_log_by_regex(log_file, 'error', ignore_case=True, print_summary=True, print_records=True)
    
    print("\n Investigating PAM authentication failures...")
    filter_log_by_regex(log_file, 'pam', ignore_case=True, print_summary=True, print_records=True)
    
    # Step 10: Generate Destination Port Reports
    print("\n Generating destination port traffic reports for high-traffic ports...")
    port_traffic = tally_port_traffic(log_file)
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(log_file, port)
    
    # Step 11: Generate Invalid User Report
    print("\n Generating invalid user report...")
    generate_invalid_user_report(log_file)
    
    # Step 12: Generate Source IP Log
    print("\n Generating log for source IP 220.195.35.40...")
    generate_source_ip_log(log_file, '220.195.35.40')

def tally_port_traffic(log_file):
    port_traffic = {}
    
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'DPT=(\d+)', line)
            if match:
                port = int(match.group(1))
                if port in port_traffic:
                    port_traffic[port] += 1
                else:
                    port_traffic[port] = 1
    
    return port_traffic

def generate_port_traffic_report(log_file, port_number):
    report_data = []
    
    with open(log_file, 'r') as file:
        for line in file:
            if f'DPT={port_number}' in line:
                date_time = re.search(r'^\w+ \d+ \d+:\d+:\d+', line).group()
                src_ip = re.search(r'SRC=(\S+)', line).group(1)
                dst_ip = re.search(r'DST=(\S+)', line).group(1)
                src_port = re.search(r'SPT=(\d+)', line).group(1)
                dst_port = re.search(r'DPT=(\d+)', line).group(1)
                
                report_data.append([date_time.split()[0], date_time.split()[1], src_ip, dst_ip, src_port, dst_port])
    
    df = pd.DataFrame(report_data, columns=['Date', 'Time', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port'])
    df.to_csv(f'destination_port_{port_number}_report.csv', index=False)

def generate_invalid_user_report(log_file):
    report_data = []
    
    with open(log_file, 'r') as file:
        for line in file:
            if 'invalid user' in line.lower():
                date_time = re.search(r'^\w+ \d+ \d+:\d+:\d+', line).group()
                username = re.search(r'invalid user (\S+)', line.lower()).group(1)
                ip_address = re.search(r'from (\S+)', line.lower()).group(1)
                
                report_data.append([date_time.split()[0], date_time.split()[1], username, ip_address])
    
    df = pd.DataFrame(report_data, columns=['Date', 'Time', 'Username', 'IP Address'])
    df.to_csv('invalid_users.csv', index=False)

def generate_source_ip_log(log_file, ip_address):
    matching_records = []
    
    with open(log_file, 'r') as file:
        for line in file:
            if f'SRC={ip_address}' in line:
                matching_records.append(line.strip())
    
    with open(f'source_ip_{ip_address.replace(".", "_")}.log', 'w') as output_file:
        for record in matching_records:
            output_file.write(record + '\n')

if __name__ == '__main__':
    main()
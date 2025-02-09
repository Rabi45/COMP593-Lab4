import re
import sys

def get_log_file_path_from_cmd_line(param_num):
    if len(sys.argv) <= param_num:
        print(f" Error: Missing command line parameter {param_num} for log file path.")
        sys.exit(1)
    
    log_file_path = sys.argv[param_num]
    
    try:
        with open(log_file_path, 'r') as file:
            pass
    except FileNotFoundError:
        print(f" Error: The file '{log_file_path}' does not exist.")
        sys.exit(1)
    
    return log_file_path

def filter_log_by_regex(log_file, regex, ignore_case=True, print_summary=False, print_records=False):
    flags = re.IGNORECASE if ignore_case else 0
    pattern = re.compile(regex, flags)
    
    matching_records = []
    captured_data = []
    
    with open(log_file, 'r') as file:
        for line in file:
            if pattern.search(line):
                matching_records.append(line.strip())
                captured_data.append(pattern.findall(line.strip()))
    
    if print_records:
        for record in matching_records:
            print(record)
    
    if print_summary:
        case_sensitivity = "case-insensitive" if ignore_case else "case-sensitive"
        print(f"The log file contains {len(matching_records)} records that {case_sensitivity} match the regex \"{regex}\".")
    
    return matching_records, captured_data
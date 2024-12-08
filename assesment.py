import re
import csv
from collections import defaultdict

# Constants
FAILED_LOGIN_THRESHOLD = 5
LOG_FILE = 'C:/Users/User/Downloads/MedicalChatbot-master/templates/sample.log'
OUTPUT_CSV = 'log_analysis_results.csv'

def parse_log_file(log_file):
    """Parse the log file and extract relevant information."""
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP addresses
            ip_match = re.match(r'^(\S+)', line)
            if ip_match:
                ip_address = ip_match.group(1)
                ip_requests[ip_address] += 1

            # Extract endpoints
            endpoint_match = re.search(r'"[A-Z]+\s(\S+)\sHTTP', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            # Detect failed login attempts
            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_login_attempts[ip_address] += 1

    return ip_requests, endpoint_requests, failed_login_attempts

def save_to_csv(ip_requests, most_accessed_endpoint, failed_login_attempts):
    """Save the analysis results to a CSV file."""
    with open(OUTPUT_CSV, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in sorted(failed_login_attempts.items(), key=lambda x: x[1], reverse=True):
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

def main():
    ip_requests, endpoint_requests, failed_login_attempts = parse_log_file(LOG_FILE)

    # Determine the most accessed endpoint
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])

    # Display Results
    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in sorted(failed_login_attempts.items(), key=lambda x: x[1], reverse=True):
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20}{count}")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, failed_login_attempts)

if __name__ == "__main__":
    main()

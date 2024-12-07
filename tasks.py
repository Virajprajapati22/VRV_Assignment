from collections import Counter
import re
import csv

class LogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.log_data = self._read_log_file()

    def _read_log_file(self):
        with open(self.log_file, 'r') as file:
            return file.read()

    def count_requests_per_ip(self):
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        ip_addresses = ip_pattern.findall(self.log_data)
        ip_counts = Counter(ip_addresses)
        return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

    def most_frequent_endpoint(self):
        endpoint_pattern = re.compile(r'"(?:GET|POST) (.*?) HTTP/1\.1"')
        endpoints = endpoint_pattern.findall(self.log_data)
        endpoint_counts = Counter(endpoints)
        return max(endpoint_counts.items(), key=lambda x: x[1])

    def detect_suspicious_activity(self, threshold=10):
        failed_login_pattern = re.compile(r'(\b(?:\d{1,3}\.){3}\d{1,3}\b).*?401.*?Invalid credentials')
        failed_logins = failed_login_pattern.findall(self.log_data)
        failed_login_counts = Counter(failed_logins)
        return {ip: count for ip, count in failed_login_counts.items() if count > threshold}

    def export_results_to_csv(self, output_file):
        # Collect data for export
        requests_per_ip = self.count_requests_per_ip()
        most_frequent_endpoint, endpoint_count = self.most_frequent_endpoint()
        suspicious_ips = self.detect_suspicious_activity()

        # Write results to a CSV file
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)

            # Write requests per IP
            writer.writerow(["Requests per IP"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in requests_per_ip:
                writer.writerow([ip, count])

            # Separate sections with an empty row
            writer.writerow([])

            # Write most frequent endpoint
            writer.writerow(["Most Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([most_frequent_endpoint, endpoint_count])

            # Separate sections with an empty row
            writer.writerow([])

            # Write suspicious activity
            writer.writerow(["Suspicious Activity"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])

# Usage example
if __name__ == "__main__":
    log_analyzer = LogAnalyzer('sample.log')

    # Task 1: Count requests per IP address
    print("IP Address           Request Count")
    for ip, count in log_analyzer.count_requests_per_ip():
        print(f"{ip:<20} {count}")

    # Task 2: Most frequently accessed endpoint
    endpoint, count = log_analyzer.most_frequent_endpoint()
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{endpoint} (Accessed {count} times)")

    # Task 3: Detect suspicious activity
    suspicious_ips = log_analyzer.detect_suspicious_activity()
    if suspicious_ips:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("\nNo suspicious activity detected.")

    # Export results to CSV
    log_analyzer.export_results_to_csv('log_analysis_results.csv')

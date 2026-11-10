import re

ip_addresses = []
failed_attempts = {}

total_logs = 0
failed_login = 0
successful_login = 0
pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"

try:
    with open ("sample.log", "r") as file:
        for line in file:
            total_logs += 1
            print (line, end="")

            if "Failed login" in line:
                failed_login += 1
                result= re.findall(pattern, line)
                ip_addresses.extend(result)

                for ip in result:
                    if ip in failed_attempts:
                        failed_attempts[ip] += 1
                    else:
                        failed_attempts[ip] = 1

            elif "Login successful" in line:
                successful_login += 1

        print("==== IP ADDRESSES ====")
        for ip in ip_addresses:
            print (ip)

        unique_ips = set(ip_addresses)
        print ("===== UNIQUE IP ADDRESSES =====")
        for ip in unique_ips:
            print (ip)
        print ("===============")
        print("Total unique IP:", len(unique_ips))

        print ("===== SUSPICIOUS ACTIVITY =====")
        for ip, attempts in failed_attempts.items():
            if attempts >= 3:
                print (f"{ip} - {attempts} failed attempts")
            
    print ("===================")
    print("Total log entries:", total_logs)
    print("Successful login:", successful_login)
    print("Failed Login:", failed_login)

    with open("report.txt", "w") as report:
        report.write("===== LOG ANALYZER REPORT =====\n")
        report.write(f"total log entries: {total_logs}\n")
        report.write(f"Successful login: {successful_login}\n")
        report.write(f"Failed login: {failed_login}\n")
        for ip, attempts in failed_attempts.items():
            if attempts >= 3:
                report.write(f"Suspicious activity: {ip} - {attempts} failed attempts\n")
        report.write(f"Total unique IP: {len(unique_ips)}\n")

except FileNotFoundError:
    print ("File not found!")





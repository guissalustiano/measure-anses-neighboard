import csv
import ipaddress
from bisect import bisect_left

def load_ip_database(database_path):
    ipv4_database = []
    ipv6_database = []
    with open(database_path, newline='', encoding='utf-8-sig') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip header
        for start_ip, end_ip, asn, name, domain in reader:
            try:
                start_ip_obj = ipaddress.ip_address(start_ip)
                end_ip_obj = ipaddress.ip_address(end_ip)
                entry = (start_ip_obj, end_ip_obj, asn, name, domain)
                if start_ip_obj.version == 4:
                    ipv4_database.append(entry)
                else:
                    ipv6_database.append(entry)
            except ValueError:
                continue

    ipv4_database.sort(key=lambda x: (x[0], x[1]))  # Sort IPv4 by start IP and then end IP
    ipv6_database.sort(key=lambda x: (x[0], x[1]))  # Sort IPv6 by start IP and then end IP
    return ipv4_database, ipv6_database

def find_asn_name_domain(ip, ipv4_database, ipv6_database):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None, None, None

    database = ipv4_database if ip_obj.version == 4 else ipv6_database
    start_ips = [entry[0] for entry in database]
    idx = bisect_left(start_ips, ip_obj)
    
    candidates = []
    if idx < len(database):
        candidates.append(database[idx])
    if idx > 0:
        candidates.append(database[idx - 1])

    for start_ip, end_ip, asn, name, domain in candidates:
        if start_ip <= ip_obj <= end_ip:
            return asn, name, domain
    
    return None, None, None

# Load the database
ipv4_database, ipv6_database = load_ip_database('asn.csv')

# Process the IPs and write the results
with open('ips.csv', newline='', encoding='utf-8-sig') as ips_csv, open('output.csv', 'w', newline='', encoding='utf-8-sig') as output_csv:
    ip_reader = csv.reader(ips_csv)
    output_writer = csv.writer(output_csv)

    output_writer.writerow(['IP Address', 'ASN', 'Name', 'Domain'])
    
    for row in ip_reader:
        ip = row[0]
        asn, name, domain = find_asn_name_domain(ip, ipv4_database, ipv6_database)
        output_writer.writerow([ip, asn, name, domain])

print("Processing complete.")

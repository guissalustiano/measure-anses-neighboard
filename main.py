import csv
import ipaddress

def load_ip_database(database_path):
    database = []
    with open(database_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)
        for start_ip, end_ip, asn, name, domain in reader:
           
            try:
                start_ip_obj = ipaddress.ip_address(start_ip)
                end_ip_obj = ipaddress.ip_address(end_ip)
                ip_range = [start_ip_obj, end_ip_obj, asn, name, domain]
                database.append(ip_range)
            except ValueError:
                
                continue
    return database


def find_asn_name_domain(ip, database):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        
        return None, None, None

    for start_ip, end_ip, asn, name, domain in database:
        
        if type(start_ip) is type(ip_obj) and start_ip <= ip_obj <= end_ip:
            return asn, name, domain
    return None, None, None

database = load_ip_database('asn.csv')

with open('ips.csv', newline='') as ips_csv, open('output.csv', 'w', newline='') as output_csv:
    ip_reader = csv.reader(ips_csv)
    output_writer = csv.writer(output_csv)

    output_writer.writerow(['IP Address', 'ASN', 'Name', 'Domain'])
    
    next(ip_reader)

    for row in ip_reader:
        ip = row[0]
        asn, name, domain = find_asn_name_domain(ip, database)
        if asn and name and domain:
            output_writer.writerow([ip, asn, name, domain])

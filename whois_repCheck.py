from ipwhois import IPWhois
import requests
import json

API_KEY = 'YOUR_API_KEY' #just paste your actual abuseipdb api key here

def whois_lookup(ip_list):
    results = []
    for ip in ip_list:
        whois_info = lookup_whois(ip)
        reputation_info = check_reputation(ip)
        combined_info = {**whois_info, **reputation_info}
        results.append(combined_info)
    return results

def lookup_whois(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        return {
            "IP": ip,
            "Network Name": res.get('network', {}).get('name', 'N/A'),
            "Registrar": res.get('asn_registry', 'N/A'),
            "ASN": res.get('asn', 'N/A'),
            "ASN Country": res.get('asn_country_code', 'N/A'),
            "ASN Date": res.get('asn_date', 'N/A'),
            "ASN Description": res.get('asn_description', 'N/A'),
            "Network CIDR": res.get('network', {}).get('cidr', 'N/A'),
            "Network Start": res.get('network', {}).get('start_address', 'N/A'),
            "Network End": res.get('network', {}).get('end_address', 'N/A'),
            "Network Country": res.get('network', {}).get('country', 'N/A')
        }
    except Exception as e:
        print(f"Error looking up {ip}: {e}")
        return {
            "IP": ip,
            "Network Name": "N/A",
            "Registrar": "N/A",
            "ASN": "N/A",
            "ASN Country": "N/A",
            "ASN Date": "N/A",
            "ASN Description": "N/A",
            "Network CIDR": "N/A",
            "Network Start": "N/A",
            "Network End": "N/A",
            "Network Country": "N/A"
        }

def check_reputation(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Accept': 'application/json',
            'Key': 'YOUR_API_KEY' #api key goes here as well
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        response = requests.get(url, headers=headers, params=params)
        data = response.json()

        return {
            "Reputation Score": data.get('data', {}).get('abuseConfidenceScore', 'N/A'),
            "Last Reported": data.get('data', {}).get('lastReportedAt', 'N/A'),
            "Number of Reports": data.get('data', {}).get('totalReports', 'N/A'),
            "Country": data.get('data', {}).get('countryCode', 'N/A')
        }
    except Exception as e:
        print(f"Error checking reputation for {ip}: {e}")
        return {
            "Reputation Score": "N/A",
            "Last Reported": "N/A",
            "Number of Reports": "N/A",
            "Country": "N/A"
        }

def write_to_json(data, filename='whoisrecord.json'):
    with open(filename, 'w', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False, indent=4)

def main():
    ip_list = input("Enter IP addresses separated by commas: ").split(',')
    ip_list = [ip.strip() for ip in ip_list]
    results = whois_lookup(ip_list)
    write_to_json(results)

if __name__ == '__main__':
    main()



# from ipwhois import IPWhois
# import csv
# import requests

# API_KEY = 'YOUR_ABUSEIPDB_API_KEY'

# def whois_lookup(ip_list):
#     results = []
#     for ip in ip_list:
#         whois_info = lookup_whois(ip)
#         reputation_info = check_reputation(ip)
#         combined_info = {**whois_info, **reputation_info}
#         results.append(combined_info)
#     return results

# def lookup_whois(ip):
#     try:
#         obj = IPWhois(ip)
#         res = obj.lookup_rdap()
#         return {
#             "IP": ip,
#             "Network Name": res.get('network', {}).get('name', 'N/A'),
#             "Registrar": res.get('asn_registry', 'N/A'),
#             "ASN": res.get('asn', 'N/A'),
#             "ASN Country": res.get('asn_country_code', 'N/A'),
#             "ASN Date": res.get('asn_date', 'N/A'),
#             "ASN Description": res.get('asn_description', 'N/A'),
#             "Network CIDR": res.get('network', {}).get('cidr', 'N/A'),
#             "Network Start": res.get('network', {}).get('start_address', 'N/A'),
#             "Network End": res.get('network', {}).get('end_address', 'N/A'),
#             "Network Country": res.get('network', {}).get('country', 'N/A')
#         }
#     except Exception as e:
#         print(f"Error looking up {ip}: {e}")
#         return {
#             "IP": ip,
#             "Network Name": "N/A",
#             "Registrar": "N/A",
#             "ASN": "N/A",
#             "ASN Country": "N/A",
#             "ASN Date": "N/A",
#             "ASN Description": "N/A",
#             "Network CIDR": "N/A",
#             "Network Start": "N/A",
#             "Network End": "N/A",
#             "Network Country": "N/A"
#         }

# def check_reputation(ip):
#     try:
#         url = f"https://api.abuseipdb.com/api/v2/check"
#         headers = {
#             'Accept': 'application/json',
#             'Key': '0913417486d7b50380e82dc21f129b39328a6fa6adbc5321b1ac4b6098844f6ab5bcf5818b2379a2'
#         }
#         params = {
#             'ipAddress': ip,
#             'maxAgeInDays': '90'
#         }
#         response = requests.get(url, headers=headers, params=params)
#         data = response.json()

#         return {
#             "Reputation Score": data.get('data', {}).get('abuseConfidenceScore', 'N/A'),
#             "Last Reported": data.get('data', {}).get('lastReportedAt', 'N/A'),
#             "Number of Reports": data.get('data', {}).get('totalReports', 'N/A'),
#             "Country": data.get('data', {}).get('countryCode', 'N/A')
#         }
#     except Exception as e:
#         print(f"Error checking reputation for {ip}: {e}")
#         return {
#             "Reputation Score": "N/A",
#             "Last Reported": "N/A",
#             "Number of Reports": "N/A",
#             "Country": "N/A"
#         }

# def write_to_csv(data, filename='whoisrecord.csv'):
#     with open(filename, mode='w', newline='', encoding='utf-8') as file:
#         writer = csv.DictWriter(file, fieldnames=data[0].keys())
#         writer.writeheader()
#         writer.writerows(data)

# def main():
#     ip_list = input("Enter IP addresses separated by commas: ").split(',')
#     ip_list = [ip.strip() for ip in ip_list]
#     results = whois_lookup(ip_list)
#     write_to_csv(results)

# if __name__ == '__main__':
#     main()

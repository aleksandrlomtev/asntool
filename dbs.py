import csv
import ipaddress
import requests
from flask import Flask, request

app = Flask(__name__)
app.debug = True

def load_database():
    database = {}

    with open('database.csv', 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            start_ip = row[0]
            end_ip = row[1]
            as_number = row[2]
            ip_range = ipaddress.summarize_address_range(ipaddress.ip_address(start_ip), ipaddress.ip_address(end_ip))
            if as_number not in database:
                database[as_number] = []
            for cidr in ip_range:
                database[as_number].append(cidr)

    return database

def get_as_number(identifier):
    # Remove the "AS" prefix if present
    identifier = identifier.lstrip("AS")

    # Check if the identifier is a valid AS number
    if identifier.isdigit():
        return identifier

    # Try to fetch AS number from domain
    url = f"http://ip-api.com/json/{identifier}"
    try:
        response = requests.get(url)
        data = response.json()
        if response.status_code == 200 and 'as' in data:
            as_number = data['as'].split()[0].strip('AS')
            return as_number
    except requests.exceptions.RequestException:
        pass

    return None

def find_cidr(identifier, database):
    as_number = get_as_number(identifier)
    if as_number and as_number in database:
        return database[as_number]
    else:
        try:
            ip = ipaddress.ip_address(identifier)
            for as_num, cidrs in database.items():
                for cidr in cidrs:
                    if cidr.version == ip.version and ip in cidr:
                        return cidrs
        except ValueError:
            pass

    return []

@app.route('/', methods=['POST'])
def handle_request():
    identifier = request.form.get('identifier')
    if not identifier:
        return "No identifier provided."

    results = find_cidr(identifier, app.config['database'])

    if results:
        return "\n".join(str(cidr) for cidr in results)
    else:
        return "No matching AS or IP found."

if __name__ == '__main__':
    app.config['database'] = load_database()
    app.run(host='0.0.0.0', port=5000)

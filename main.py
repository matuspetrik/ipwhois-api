import requests
import json
import os
import pandas as pd
from ipwhois import IPWhois

def DESCRIPTION():
    return """
    This application reads IP addresses from a file, fetches their information
    from the ipinfo.io API using a bearer token, and writes the results to an output file.
    It also retrieves CIDR information for each IP address using the IPWhois library.
    """

def read_variables():
    """
    Reads variables from a YAML file located at 'Files/input-variables.yml'.

    The function parses each line containing a colon (':') as a key-value pair,
    strips whitespace from keys and values, and stores them in a dictionary.

    Returns:
        dict: A dictionary containing the parsed variables from the file.
    """
    with open('Files/input-variables.yml', 'r') as file:
        lines = file.readlines()
        variables = {}
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                variables[key.strip()] = value.strip()
        print(variables)
    return variables

def get_ip_info(ip, bearer_token):
    """
    Fetches information about a given IP address from the ipinfo.io API.
    """
    url = f"https://ipinfo.io/{ip.strip()}"
    headers = {
        "Authorization": f"Bearer {bearer_token}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching IP info for {ip}: {response.status_code}")

def read_ips_from_file(input_file):
    """
    Reads IP addresses from the specified input file.
    """
    try:
        with open(input_file, 'r') as file:
            data = file.read()
        return data.splitlines()
    except FileNotFoundError:
        print(f"Input file {input_file} not found.")
        return []

def write_output_to_file(output_file, output_data):
    """
    Writes the output data to a file.
    """
    with open(output_file, 'a') as file:
        for entry in output_data:
            file.write(json.dumps(entry) + '\n')

def clear_output_to_file(output_file, output_data):
    """
    Clears the output file before new data writes.
    """
    if os.path.exists(output_file):
        # action
        print(f"Output file: {output_file} already exists. Do you"\
              " want to overwrite it? (y/n)")
        choice = input().strip().lower()
        if choice != 'y':
            print("==> OK, I won't overwrite the file and use it instead.")
            return True
    try:
        with open(output_file, 'w') as file:
            file.truncate()
            return False
    except FileNotFoundError:
        print(f"Output file {output_file} not found.")
        return False

def process_output_file(output_file, output_file_csv):
    """
    Processes the output file to display the content.
    """
    data_params = [
        'ip',
        # 'hostname',
        'city',
        'region',
        'country',
        # 'loc',
        'org',
        # 'postal',
        'timezone'
    ]
    try:
        with open(output_file, 'r') as file:
            # lines = file.readlines()
            lines = json.loads("[" + file.read().replace("\n", ",")[:-1] + "]")
            df = pd.DataFrame(lines)
            print(df)
            df.to_csv(output_file_csv, index=False)
    except FileNotFoundError:
        print(f"Output file {output_file} not found.")

def get_cidr_info(ips):
    """
    Fetches CIDR information for a given IP address.
    """
    for ip in ips:
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap()
            cidr = res.get('network', {}).get('cidr', 'N/A')
            cidr = cidr.split(', ')
            if len(cidr) > 1:
                for i in cidr:
                    print(f"IP: {ip}, CIDR: {i}")
            else:
                print(f"IP: {ip}, CIDR: {cidr[0]}")
        except Exception as e:
            print(f"Error fetching CIDR info for {ip}: {e}")

def main():
    """
    Main function to read variables, fetch IP info, and write to output file.
    """
    variables = read_variables()
    bearer_token = variables.get('bearer', '')
    input_file = variables.get('input_file', 'Files/one-ip-per-line.txt')
    output_file = variables.get('output_file', '/tmp/output.txt')
    output_file_csv = variables.get('output_file_csv', '/tmp/output.csv')

    ips = read_ips_from_file(input_file)
    get_cidr_info(ips)

    # Clear the output file before writing new data
    use_existing_output_file = clear_output_to_file(output_file, [])
    if use_existing_output_file:
        process_output_file(output_file, output_file_csv)
    else:
        for ip in ips:
            ip_info = get_ip_info(ip, bearer_token)
            if ip_info:
                write_output_to_file(output_file, [ip_info])
        process_output_file(output_file)

if __name__ == "__main__":
    main()

# Example curl command to fetch IP info
#curl -H "Authorization: Bearer abcdefg1234567" https://ipinfo.io/20.189.173.27 | jq -rc >> /tmp/output.txt

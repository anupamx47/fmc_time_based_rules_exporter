# Custom Build 1.0
# Anupam Pavithran (anpavith@cisco.com) | Cisco Systems India

import requests
import json
import csv
from requests.auth import HTTPBasicAuth
from getpass import getpass
import time
from datetime import datetime
import sys

# Disable warnings for unverified HTTPS requests
requests.packages.urllib3.disable_warnings()

def get_auth_token(fmc_server, username, password):
    auth_url = f"{fmc_server}/api/fmc_platform/v1/auth/generatetoken"
    response = requests.post(auth_url, auth=HTTPBasicAuth(username, password), verify=False)
    if response.status_code == 204:
        return response.headers['X-auth-access-token']
    else:
        raise Exception("Failed to obtain access token")

def get_access_control_policies(fmc_server, token):
    url = f"{fmc_server}/api/fmc_config/v1/domain/default/policy/accesspolicies"
    headers = {'X-auth-access-token': token}
    response = requests.get(url, headers=headers, verify=False)
    return response.json()

def get_all_time_ranges(fmc_server, token, domain_id):
    url = f"{fmc_server}/api/fmc_config/v1/domain/{domain_id}/object/timeranges?limit=1000&expanded=true"
    headers = {
        'X-auth-access-token': token,
        'accept': 'application/json'
    }
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json().get('items', [])
    else:
        print(f"Error fetching time ranges: {response.status_code} - {response.text}")
        return []

def match_time_ranges_with_rules(rules, time_ranges):
    for rule in rules:
        for tro in rule.get('timeRangeObjects', []):
            matched_time_range = next((tr for tr in time_ranges if tr['id'] == tro['id']), None)
            if matched_time_range:
                yield rule, matched_time_range

def get_all_time_based_rules(fmc_server, policy_id, token, domain_id):
    headers = {'X-auth-access-token': token}
    all_rules = []
    url = f"{fmc_server}/api/fmc_config/v1/domain/{domain_id}/policy/accesspolicies/{policy_id}/accessrules?limit=1000&expanded=true"
    page_count = 0

    while url:
        response = requests.get(url, headers=headers, verify=False)

        if response.status_code != 200:
            print(f"\nError fetching data: {response.status_code} - {response.text}")
            break

        try:
            data = response.json()
        except json.JSONDecodeError:
            print("\nFailed to decode JSON response. Possible empty response.")
            break

        rules = data.get('items', [])
        all_rules.extend([rule for rule in rules if 'timeRangeObjects' in rule])

        paging = data.get('paging', {})
        next_url = paging.get('next')

        if isinstance(next_url, list) and next_url:
            url = next_url[0]
        elif isinstance(next_url, str):
            url = next_url
        else:
            url = None

        # Update progress display
        page_count += 1
        sys.stdout.write(f"\rProcessing page {page_count}...")
        sys.stdout.flush()

        time.sleep(1)

    # Print a newline after progress
    print("\nAll pages processed.")
    return all_rules

def save_rules_to_csv(fmc_server, token, matched_rules, filename, domain_id):
    csv_headers = ['Policy Name', 'Rule Name', 'Time Range Objects', 'Expired Objects']

    with open(filename, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=csv_headers)
        writer.writeheader()

        current_date = datetime.now()

        for rule, time_range_details in matched_rules:
            time_range_info = []
            expired_objects = []

            start_date = time_range_details.get('effectiveStartDateTime')
            end_date = time_range_details.get('effectiveEndDateTime')

            if end_date:
                end_datetime = datetime.strptime(end_date, '%Y-%m-%dT%H:%M')
                if end_datetime < current_date:
                    expired_objects.append(time_range_details['name'])

            time_range_info.append(f"{time_range_details['name']} (Start: {start_date}, End: {end_date})")
            #print(f"{time_range_details['name']} (Start: {start_date}, End: {end_date})")

            writer.writerow({
                'Policy Name': rule.get('policyName', 'Unknown'),
                'Rule Name': rule.get('name', 'Unnamed'),
                'Time Range Objects': '; '.join(time_range_info),
                'Expired Objects': ', '.join(expired_objects)
            })

def main():
    try:
        fmc_server = input("Enter the FMC server IP (e.g., https://192.168.1.1): ")
        username = input("Enter your FMC username: ")
        password = getpass("Enter your FMC password: ")

        token = get_auth_token(fmc_server, username, password)

        policies = get_access_control_policies(fmc_server, token)

        print("Available Access Control Policies:")
        for idx, policy in enumerate(policies.get('items', []), start=1):
            print(f"{idx}. {policy['name']}")

        policy_choice = int(input("Select an Access Control Policy by entering the corresponding number: ")) - 1
        selected_policy = policies['items'][policy_choice]
        policy_name = selected_policy['name']
        policy_id = selected_policy['id']
        
        domain_id = selected_policy.get('metadata', {}).get('domain', {}).get('id', 'default')

        time_based_rules = get_all_time_based_rules(fmc_server, policy_id, token, domain_id)

        for rule in time_based_rules:
            rule['policyName'] = policy_name

        time_ranges = get_all_time_ranges(fmc_server, token, domain_id)
        matched_rules = list(match_time_ranges_with_rules(time_based_rules, time_ranges))

        save_rules_to_csv(fmc_server, token, matched_rules, 'time_based_rules.csv', domain_id)
        print("Time-based rules have been exported to 'time_based_rules.csv'.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
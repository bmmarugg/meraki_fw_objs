#!/usr/bin/python3
# v1.0 | 2023-09-07

import json
import requests
import urllib3
from pprint import pprint
import meraki

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Fill out the 'PATH/TO/' with your preferred documents directory location.
base_doc_path = "PATH/TO/DOCUMENTS"

with open(f"{base_doc_path}/creds.json") as creds:
    creds = json.load(creds)

# The necessary REST headers needed to authenticate and pass data each and every time an API call is made.
headers = {
    "X-Cisco-Meraki-API-Key": creds.get('meraki_api_token'),
    "content-type": "application/json",
    "accept": "application/json"
}

# A variable that acts as a short-hand way to call the API URL. Makes for cleaner code
base_url = f'https://api.meraki.com/api/v1/'
dashboard = meraki.DashboardAPI(creds.get('meraki_api_token'))

# Defines the location and file that will back up all of the currently existing objects in Meraki in .json format
objects_backup_file = open(f'{base_doc_path}/current_objs.json', 'w')


# Function that retrieves the organization ID that's tied to your API token. Absolute requirement.
def get_org_id():
    for entry in dashboard.organizations.getOrganizations():
        org = entry.get('id')

        return org

# Runs the above function to return the organization ID as a global variable that can be used in later functions.
org_id = get_org_id()


# Allows the user to manually give a name to be used in the object and object group for easy identification.
def get_vuln_name():
    vuln_name = input("Vulnerability name (one word only - use CamelCase if you need to): ")

    return vuln_name

# Runs the above function to return the global variable that will be used in later functions.
vuln_name = get_vuln_name()


# Does a query to get a list of and back up the current policy objects in case things blow up. Writes them to a JSON
# file for easy re-importing, if needed.
objects_backup = dashboard.organizations.getOrganizationPolicyObjects(org_id)
json.dump(objects_backup, objects_backup_file, ensure_ascii=False, indent=4)


# The function that iterates through the list of IP addresses to be blocked and adds them as policy objects.
def block_ip():
    n = 1

    for ip in open(f"{base_doc_path}/objs-to-block.txt"):
        block_ip = ip.replace('\n', "")

        data = {
            "name": f"{vuln_name}-ip{n}",
            "category": "network",
            "type": "cidr",
            "cidr": f"{block_ip}/32"
        }

        response_code = requests.post(f"{base_url}/organizations/{org_id}/policyObjects",
                                      verify=False, headers=headers, data=json.dumps(data))
        pprint(f"{block_ip} | {response_code}")
        n = n + 1


# Creates a new object policy group and dynamically adds the
def obj_group():
    get_objs = requests.get(f"{base_url}/organizations/{org_id}/policyObjects", headers=headers, verify=False)

    obj_id_list = []
    for obj in get_objs.json():
        if vuln_name.lower() in obj.get('name').lower():
            obj_id_list.append(obj.get('id'))

    data = {
        "name": f"{vuln_name}-block",
        "objectIds": obj_id_list
    }
    create_obj_group = requests.post(f"{base_url}/organizations/{org_id}/policyObjects/groups",
                                     headers=headers, verify=False, data=json.dumps(data))
    pprint(create_obj_group)


block_ip()
obj_group()

"""
Parses a CSV file that contains vulnerability data
and retrieves commonly exploited CVE data from CISA's
website in JSON format. Merges the information to 
inform if there are commonly exploited vulnerabilities 
present in the enterprise network.

Future improvements:
  - Option for specifying the input csv file by name/path
  - Option for specifying the output csv file by name/path
"""
import csv
from operator import itemgetter
import requests


def main():
    nessus_input = import_nessus_csv()
    cisa_input = get_cisa_json()
    nessus_entries = create_nessus_entries(nessus_input)
    cisa_entries = create_cisa_entries(cisa_input)
    joined_entries = join_entries(nessus_entries, cisa_entries)
    print_tables(joined_entries)


def import_nessus_csv():
    """
    Reads in a locally downloaded CSV.

    Returns a list of lists. Each top level list is a line
    from the CSV file. Each contained list is a field from
    the CSV.

    Format: [[<field1>, <field2>, ...], ...]
    """
    csv_entries = []
    with open('nessus_csv.csv', newline='') as csvfile:
        csvreader = csv.reader(csvfile)
        next(csvreader)     # throwing away the header line
        for row in csvreader:
            csv_entries.append(row)

    return csv_entries


def get_cisa_json():
    """
    CISA keeps a record of "known exploited vulnerabilities."
    CISA Site: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

    Downloads a json object from the website. The vulnerabilities is 
    stored in the JSON as a JSON array. Parses the vulnerabilities out
    and returns a list of vulnerability dictionaries with format:

    [{
        "cveID":  "CVE-2021-27102",
        "vendorProject":  "Accellion",
        "product":  "FTA",
        "vulnerabilityName":  "Accellion FTA OS Command Injection Vulnerability",
        "dateAdded":  "2021-11-03",
        "shortDescription":  "Accellion FTA 9_12_411 and earlier is affected by OS command execution via a local web service call.",
        "requiredAction":  "Apply updates per vendor instructions.",
        "dueDate":  "2021-11-17",
        "notes":  ""
    }, ... ]
    """
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    cisa_response = requests.get(URL)
    response_dict = cisa_response.json()
    vulns = response_dict.get('vulnerabilities')  # list of vulnerability dictionaries

    return vulns


def create_nessus_entries(nessus_input):
    """
    Nessus generates a csv file of vulnerabilities. Format of the file:
    Severity,Plugin,Plugin Name,IP Address,CVE,NetBIOS Name

    nessus_input: a list of lists. First list is each line, inner list is
    the fields of each line.

    Returns a dictionary of nessus results. Format:
    {
        <cve_id>: {
            severity: <highest_related_severity>
            plugins: [{
                id: <plugin_id>,
                name: <plugin_name>
            },
            ...],
            ips: [<ip>, ...],
            computer_names: [<computer_name>, ...]
        },
        ...
    }
    """
    nessus_entries = {}

    for line in nessus_input:
        cves = line[4].split(',')  # creates a list of cves
        for cve in cves:
            if cve == '':
                continue
            elif nessus_entries.get(cve):    # cve already exists in dict
                update_entry(nessus_entries, cve, line)
            else:
                entry = create_entry(line)
                nessus_entries[cve] = entry

    return nessus_entries


def update_entry(nessus_entries, cve, line):
    """
    updates an existing entry in the dictionary,
    given the information in this cve line.

    nessus_entries: dictionary of entries
    cve: cve_id that has been found to exist
         as a key in the nessus_entries
    line: the full entry line from the csv file    
    """
    # update the severity
    this_entry = nessus_entries.get(cve)
    new_severity = get_highest_severity(line[0], this_entry.get('severity'))
    this_entry['severity'] = new_severity

    # add plugin if it doesn't already exist
    new_plugin = {
        'id': line[1],
        'name': line[2]
    }
    if new_plugin not in this_entry.get('plugins'):
        this_entry.get('plugins').append(new_plugin)

    # add the ip
    this_entry.get('ips').add(line[3])

    # add the computer name
    this_entry.get('computer_names').add(line[5])


def get_highest_severity(new_severity, existing_severity):
    severities = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1,
        'Info': 0
    }

    if severities.get(new_severity) >= severities.get(existing_severity):
        return new_severity

    return existing_severity


def create_entry(line):
    """
    creates a new entry in the dictionary of nessus
    entries.

    nessus_entries: dictionary of entries
    cve: cve_id that has been found to not yet exist
         as a key in the nessus_entries
    line: the full entry line from the csv file
    """
    entry = {
        'severity': line[0],
        'plugins': [{
            'id': line[1],
            'name': line[2]
        }],
        'ips': set([line[3]]),
        'computer_names': set([line[5]])
    }

    return entry


def create_cisa_entries(cisa_input):
    """
    cisa_input: a list of vulnerability dictionaries.
    See get_cisa_json for format of input

    Returns a dictionary of nessus results. Format:
    {
        <cve_id>: {
            "cveID":  <cve_id>,
            "vendorProject":  <vendor>,
            "product":  <product>,
            "vulnerabilityName":  <vulnerability_name>,
            "dateAdded":  <date_added>,
            "shortDescription":  <short_description>,
            "requiredAction":  <required_action>,
            "dueDate":  <due_date>,
            "notes":  <notes>
        }, ...
    }
    """
    cve_output = {}

    for cve in cisa_input:
        cve_id = cve['cveID']
        cve_output[cve_id] = cve

    return cve_output


def join_entries(nessus_entries, cisa_entries):
    """
    nessus_entries: data returned from nessus in the format as
    shown in create_nessus_entries.

    cisa_entries: data returned from cisa data in the format
    as shown in create_cisa_data.

    Returns a dictionary. Format:
    {
        <criticality>: {
            <cve_id>: [{
                id: <cve_id>,
                criticality: <criticality>,
                name: <cve_name>,
                hosts: <number_of_hosts_affected>
            }, ...]
        }
    }
    """
    joined_entries = {}

    for cve_id, cisa_details in cisa_entries.items():
        if nessus_entries.get(cve_id):
            nessus_entry = nessus_entries.get(cve_id)
            if joined_entries.get(nessus_entry['severity']):
                update_joined_entry(joined_entries, nessus_entry, cisa_details)
            else:
                create_joined_entry(joined_entries, nessus_entry, cisa_details)

    return joined_entries


def update_joined_entry(joined_entries, nessus_entry, cisa_details):
    joined_entry = joined_entries.get(nessus_entry['severity'])
    joined_entry[cisa_details["cveID"]] = {
        'id': cisa_details["cveID"],
        'criticality': nessus_entry['severity'],
        'name': cisa_details["vulnerabilityName"],
        'hosts': len(nessus_entry["ips"])
    }


def create_joined_entry(joined_entries, nessus_entry, cisa_details):
    joined_entries[nessus_entry['severity']] = {
        cisa_details['cveID']: {
            'id': cisa_details["cveID"],
            'criticality': nessus_entry['severity'],
            'name': cisa_details['vulnerabilityName'],
            'hosts': len(nessus_entry['ips']),
        }
    }


def print_tables(joined_entries):
    """
    Prints a table to a text file that looks like this:
    ----------------------------------------------------
    |   Criticality  |  CVE ID  |  Vulnerability Name  |
    ----------------------------------------------------
    |  <Criticality> | <CVE ID> | <Vulnerability Name> |
    ----------------------------------------------------
    |      ...       |   ...    |        ...           |
    """
    full_list = []
    for criticality in joined_entries.keys():
        this_list = [value for key, value in joined_entries[criticality].items()]
        sorted_list = sorted(this_list, key=itemgetter('hosts'), reverse=True)
        full_list.extend(sorted_list)

    count = 0
    with open("results.txt", 'w') as results_file:
        lines = []
        lines.append("".center(101, "-") + "\n")
        lines.append("|" + "Criticality".center(15, ' ') + "|" + "CVE ID".center(16, ' ') + "|" + "Hosts Affected".center(16, ' ') + "|" + "Vulnerability Name".center(49, " ") + "|\n")
        lines.append("".center(101, "-") + "\n")
        for entry in full_list:
            count += 1
            name = entry['name'][:44] + "..." if len(entry['name']) > 44 else entry['name']
            lines.append("|" + entry['criticality'].center(15, ' ') + "|" + entry['id'].center(16, ' ') + "|" + str(entry['hosts']).center(16, ' ') + "| " + name.ljust(48, " ") + "|\n")
            if count == 10:
                break

        results_file.writelines(lines)

if __name__ == "__main__":
    main()

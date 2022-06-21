"""
Parses a CSV file that contains vulnerability data
and retrieves commonly exploited CVE data from CISA's
website. Merges the information to inform if there
are commonly exploited vulnerabilities present in 
the enterprise network.
"""
# import statements go here
import csv
import requests


def main():
    nessus_csv = import_csv()
    vulns_list = get_cisa_json()
    nessus_entries = create_nessus_entries(nessus_csv)
    cisa_entries = create_cisa_entries(vulns_list)
    joined_entries = join_nessus_and_cisa(nessus_entries, cisa_entries)
    print_table_to_file(joined_entries)


def import_csv():
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

    {
        "cveID":  "CVE-2021-27102",
        "vendorProject":  "Accellion",
        "product":  "FTA",
        "vulnerabilityName":  "Accellion FTA OS Command Injection Vulnerability",
        "dateAdded":  "2021-11-03",
        "shortDescription":  "Accellion FTA 9_12_411 and earlier is affected by OS command execution via a local web service call.",
        "requiredAction":  "Apply updates per vendor instructions.",
        "dueDate":  "2021-11-17",
        "notes":  ""
    }
    """
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    cisa_data = requests.get(URL)
    response_dict = cisa_data.json()
    vulns = response_dict.get('vulnerabilities')  # list of vulnerability dictionaries

    return vulns


def create_nessus_entries(csv_lines):
    """
    Nessus generates a csv file of vulnerabilities. Format of the file:
    Severity,Plugin,Plugin Name,IP Address,CVE,NetBIOS Name

    csv_lines: a list of lists. First list is each line, inner list is
    the fields of each line.

    Returns a dictionary of nessus results. Format:
    {
        <csv_id>: {
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
    # TODO: Finish this function
    raise NotImplementedError
    return nessus_entries


def create_cisa_entries(vulns_list):
    """
    vulns_list: a list of vulnerability dictionaries.
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
    # TODO: Finish this function
    raise NotImplementedError
    return cisa_entries


def join_nessus_and_cisa(nessus_data, cisa_data):
    """
    nessus_data: data returned from nessus in the format as
    shown in create_nessus_entries.

    cisa_data: data returned from cisa data in the format
    as shown in create_cisa_data.

    Returns a dictionary. Format:
    {
        <criticality>: {
            cves: [{
                id: <cve_id>,
                name: <cve_name>,
            }, ...]
        }
    }
    """
    # TODO: Finish this function
    raise NotImplementedError
    return joined_entries


def print_table_to_file(joined_entries):
    """
    Prints a table to a text file that looks like this:
    ----------------------------------------------------
    |   Criticality  |  CVE ID  |  Vulnerability Name  |
    ----------------------------------------------------
    |  <Criticality> | <CVE ID> | <Vulnerability Name> |
    ----------------------------------------------------
    |      ...       |   ...    |        ...           |
    """
    # TODO: Finish this function
    raise NotImplementedError
    return cisa_entries


if __name__ == "__main__":
    main()

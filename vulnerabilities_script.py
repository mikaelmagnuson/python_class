"""
Parses a CSV file that contains vulnerability data
and retrieves commonly exploited CVE data from CISA's
website. Merges the information to inform if there
are commonly exploited vulnerabilities present in 
the enterprise network.
"""
# import statements go here


def main():
    nessus_csv = import_csv()
    cisa_json = get_cisa_json()
    nessus_entries = create_nessus_entries(nessus_csv)
    cisa_entries = create_cisa_entries(cisa_json)
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
    # TODO: Finish this function
    raise NotImplementedError
    return csv


def get_cisa_json():
    """
    CISA keeps a record of "known exploited vulnerabilities."
    CISA Site: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

    Downloads a json object from the website. The vulnerabilities is 
    stored in the JSON as a JSON array. Parses the vulnerabilities out
    and returns the JSON array.
    """
    # TODO: Finish this function
    raise NotImplementedError
    return cisa_json


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


def create_cisa_entries(cisa_json):
    """
    cisa_json: the complete json array containing all vulnerabilities
    as downloaded from CISA

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
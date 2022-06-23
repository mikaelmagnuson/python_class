import unittest
import complete_project as cp

class VulnerabilityScriptTests(unittest.TestCase):
    mock_nessus_entries = { "CVE-2022-1520": {
            'severity': "Medium",
            'plugins': [{
                'name': 'first plugin',
                'id': 'plugin id 1'
            }],
            'ips': set(['192.168.1.1']),
            'computer_names': set(['contoso.us.me/firstcomp'])
        }}


    def test_import_nessus_csv(self):
        csv_entries = cp.import_nessus_csv()
        self.assertEqual(type(csv_entries), list)
        self.assertEqual(type(csv_entries[0]), list)
        self.assertEqual(len(csv_entries), 30222)
        self.assertEqual(len(csv_entries[0]), 6)


    def test_get_cisa_json(self):
        cisa_json_input = cp.get_cisa_json()
        self.assertEqual(type(cisa_json_input), list)
        self.assertEqual(type(cisa_json_input[0]), dict)
        self.assertEqual(len(cisa_json_input[0].keys()), 9)


    def test_create_nessus_entries(self):
        csv_entries = cp.import_nessus_csv()
        nessus_entries = cp.create_nessus_entries(csv_entries)
        self.assertEqual(type(nessus_entries), dict)
        first_key = list(nessus_entries.keys())[0]
        self.assertEqual(type(nessus_entries[first_key]), dict)


    def test_update_entry(self):
        mock_entries = self.mock_nessus_entries.copy()
        mock_cve = "CVE-2022-1520"
        mock_line = ["High", "160527", "Mozilla Thunderbird < 91.9", "10.89.230.23", "CVE-2022-1520,CVE-2022-29909,CVE-2022-29911,CVE-2022-29912,CVE-2022-29913,CVE-2022-29914,CVE-2022-29916,CVE-2022-29917", "contoso.cyberdawn.us\FD2011801-NB"]
        cp.update_entry(mock_entries, mock_cve, mock_line)
        self.assertEqual(mock_entries.get(mock_cve)['severity'], "High")
        self.assertEqual(len(mock_entries.get(mock_cve)['ips']), 2)
        self.assertEqual(len(mock_entries.get(mock_cve)['computer_names']), 2)
        self.assertEqual(len(mock_entries), 1)


    def test_create_cisa_entries(self):
        cisa_json_input = cp.get_cisa_json()
        cisa_output = cp.create_cisa_entries(cisa_json_input)
        self.assertEqual(type(cisa_output), dict)
        first_key = list(cisa_output.keys())[0]
        self.assertEqual(type(cisa_output[first_key]), dict)
        self.assertEqual(len(cisa_output.get(first_key)), 9)


    def test_get_highest_severity(self):
        self.assertEqual("High", cp.get_highest_severity("High", "Medium"))
        self.assertEqual("High", cp.get_highest_severity("Medium", "High"))
        self.assertEqual("Critical", cp.get_highest_severity("Critical", "High"))
        self.assertEqual("Medium", cp.get_highest_severity("Low", "Medium"))
        self.assertEqual("Low", cp.get_highest_severity("Info", "Low"))
        self.assertEqual("Low", cp.get_highest_severity("Low", "Low"))


if __name__ == '__main__':
    unittest.main()
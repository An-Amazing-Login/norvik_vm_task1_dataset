"""json file reading scratchpad"""
import json

kev = open("known_exploited_vulnerabilities - up to 2026-09-21.json", 'r')
kev_data = json.load(kev)

#print(kev_data['vulnerabilities'][0]['cveID'])
"""for i in range(1717):
    print(kev_data['vulnerabilities'][i]['cveID'])"""

for entry in kev_data['vulnerabilities']:
    print(entry['cveID'])

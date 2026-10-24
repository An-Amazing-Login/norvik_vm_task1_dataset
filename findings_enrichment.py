"""data enriching file. 
The point is to connect all the entries in findings.csv with 
the additional information needed to calculate their priority numbers."""

import csv
import json
#from datetime import datetime
#from collections import Counter


assets_list={}

cmdb = open("cmdb_assets.csv", "r")
cmdb_assets = csv.reader(cmdb)
for row in cmdb_assets:
    assets_list[row[10]]=[x for x in row]

scnr = open("scanner_assets.csv", "r")
scnr_assets = csv.reader(scnr)

for row in scnr_assets:
    cmdb_info = assets_list.get((row[2]))
    info = (cmdb_info,[x for x in row])
    assets_list.update({(row[2]): info})

for l in assets_list.values():
    if isinstance(l, list):
        assets_list.update({l[10]:(l, None)})

epss_scores = {}
epss = open("epss_scores-2026-09-21.csv", 'r')
epss_data = csv.reader(epss)
for row in epss_data:
    epss_scores[row[0]]=[x for x in row]

kev = open("known_exploited_vulnerabilities - up to 2026-09-21.json", 'r')
kev_data = json.load(kev)

plugin_cves=[]
pcve = open("plugin_cves.csv",'r')
pcve_data = csv.reader(pcve)
for row in pcve_data:
    info = [x for x in row]
    info.append(False)
    plugin_cves.append(info)

for line in plugin_cves:
    for entry in kev_data['vulnerabilities']:
        if entry['cveID'] == line[1]:
            line[3]=True
    x = epss_scores.get(line[1])
    line.append(x[1])

plugin_cves[0][3]='is_on_kev'
#print(plugin_cves[:10])

plugin_cves_condensed=[['plugin_id','epss_independent_risk_of_exploit','cve_instances_on_kev']]
on_kev=0
probability = 1.0
for i in range(len(plugin_cves)-1):
    if plugin_cves[i][0]=='plugin_id':
        continue
    probability=probability*(1-float(plugin_cves[i][4]))
    on_kev=on_kev+int(plugin_cves[i][3])
    if plugin_cves[i][0]!=plugin_cves[i+1][0]:
        plugin_cves_condensed.append([plugin_cves[i][0], 1-probability, on_kev])
        #do stuff
        on_kev=0
        probability = 1.0
probability=probability*(1-float(plugin_cves[-1][4]))
on_kev=on_kev+int(plugin_cves[-1][3])
plugin_cves_condensed.append([plugin_cves[-1][0], 1-probability, on_kev])

#print(plugin_cves_condensed[:11])

plugins_list={}
plgn = open("plugins.csv", 'r')
plgn_data= csv.reader(plgn)
for row in plgn_data:
    plugins_list[row[0]]=[x for x in row]

for row in plugin_cves_condensed:
    x=plugins_list.get(row[0])
    y=row
    plugins_list.update({(row[0]): (x,y)})

#x = plugins_list.values()
#print(x)
#print(plugins_list.get('plugin_id'))

findings_list={}
f = open("findings.csv",'r')
findings = csv.reader(f)
for row in findings:
    findings_list.update({row[0]:[x for x in row]})

#x=findings_list.get('F-700002')
#print(x)
#x=assets_list.keys()
#print(x)
#print(assets_list.get('ip'))

enriched_findings_list={}
for row in findings_list.values():
    findings_info = findings_list.get(row[0])
    asset_info = assets_list.get(row[3])
    plugin_info = plugins_list.get(row[4])
    enriched_findings_list[row[0]]=(findings_info,asset_info,plugin_info)

#print(enriched_findings_list.get('F-725717'))

cleaned_enriched_findings_list = {}
for line in enriched_findings_list.values():
    if isinstance(line[1][0],tuple):
        if line[0][1]==line[1][1][0]:
            continue
        x=line[0]
        y=line[1][0]
        z=line[2]
        cleaned_enriched_findings_list[line[0][0]] = (x,y,z)
        continue
    if line[1][0] is None:
        cleaned_enriched_findings_list[line[0][0]] = line
        continue
    if line[1][0][11]=='Retired':
        continue
    cleaned_enriched_findings_list[line[0][0]] = line

#print(cleaned_enriched_findings_list.items())
#print(line[0])
#print(cleaned_enriched_findings_list.get('F-725717'))
#print(cleaned_enriched_findings_list.get('F-725719'))
#print(cleaned_enriched_findings_list.get('F-700002'))
#print(cleaned_enriched_findings_list.get('F-700120'))
#print(len(cleaned_enriched_findings_list))
out_list =[]
short_out_list=[]
for element in cleaned_enriched_findings_list.values():
    if element[1][0] is None:
        continue
    if isinstance(element[2][1][1], str):
        entry= (element[0],element[1],element[2],10**15)
        out_list.append(entry)
        short_out_list.append((entry[0],entry[3]))
        continue
    i_facing=1
    b_criticality=1
    on_kev=1
    severity=float(element[2][0][3])
    probability=float(element[2][1][1])
    if element[1][0][7]=='Y':
        i_facing=1000
    if element[1][0][8]=='1 - Critical':
        b_criticality=1000
    if element[1][0][8]=='2 - High':
        b_criticality=100
    if element[1][0][8]=='3 - Medium':
        b_criticality=10
    if element[2][1][2]>0:
        on_kev=500
    priority_value= i_facing*b_criticality*on_kev*severity*probability
    entry= (element[0],element[1],element[2],priority_value)
    out_list.append(entry)
    short_out_list.append((entry[0],entry[3]))

#print(out_list[:12])
s_findings_list= sorted(out_list, key=lambda entry: entry[3],reverse=True)
#print(s_findings_list[0])
"""for i in range(0,300):
    print(s_findings_list[i])"""

s_findings_data = []
for entry in s_findings_list:
    outrow=[]
    for x in entry[0]:
        outrow.append(x)
    for y in entry[1][0]:
        outrow.append(y)
    for z in entry[1][1]:
        outrow.append(z)
    for a in entry[2]:
        outrow.append(a)
    """for b in entry[2][1]:
        outrow.append(b)"""
    outrow.append(entry[3])
    s_findings_data.append(outrow)

s_findings_data[0][-1]='priority_score'
print(s_findings_data[1])

"""fn = "enriched_findings.csv"
with open(fn, 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerows(s_findings_data)"""

"""docstring."""
import csv
#from datetime import datetime
from collections import Counter
issues_counter=0
#r_count=-1
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

"""x=assets_list.get("10.101.0.10")
print(x)
y=assets_list.get("10.111.0.30")
print(y)"""

discrepancies=0
unscanned=0
duplicates=0
duplicates_list=[]
for l in assets_list.values():
    if isinstance(l, list):
        if l[2]!='POS terminal':
            unscanned+=1
        #print(l)
        assets_list.update({l[10]:(l, None)})
        #print(assets_list.get(l[10]))
        continue
    if l[0] is None:
        #print(l)
        discrepancies+=1
        continue
    if isinstance(l[0], tuple):
        duplicates+=1
        #print(l)
        #if l[0][0][11]=='In use' and (l[0][1][6][:7]!= '2026-09' or l[1][6][:7]!='2026-09'):
            #print(l)
        continue
    #if l[0][11]=='In use' and l[1][6][:7]!='2026-09':
        #print(l)


#print(duplicates) #we get 49 duplicate entries for the same machine in the scanner_assets list. 6 of them are dmz-web01 through dmz-web06. They seem to run an agent and also be scanned remotely, which may be the intended behaviour. The rest are laptops seemingly running multiple agents.

#print(discrepancies) #yields 18 discrepancies. They're all network scans of servers from the  lab. I expect them to be already decommissioned and replaced by new test servers, but in a real world situation I would just send the lab guys an email to see if that was them.
#print(unscanned) #yields 565 machines from the CMDB unseen by the scanner, 98 of which are not POS terminals handled by EXC-0003.

#x = assets_list.get("10.101.0.20")
#print(x)

findings_list={}
f = open("findings.csv",'r')
findings = csv.reader(f)
for row in findings:
    findings_list.update({row[0]:[x for x in row]})

plugins_list={}
p = open("plugins.csv", 'r')
plugins = csv.reader(p)
for row in plugins:
    plugins_list.update({row[0]:[x for x in row]})
#print(findings_list['F-700002'])
#print(assets_list.get(findings_list['F-700002'][3])[0])

maximum_vulnerability_counter=0
junk_counter=0
misleading_duplicate_findings=0
#junk_list=[]
occurence_list=[]
for row in findings_list.values():
    
    if row[10]=='Open' and row[12]=='':
        plugin_d=plugins_list.get(row[4])
        maximum_vulnerability_counter = maximum_vulnerability_counter+(int(plugin_d[4]))
        occurence_list.append(row[4])

    asset_d=assets_list.get(row[3])
    if isinstance(asset_d[0], tuple):
        if asset_d[1][0]==row[1]:
            misleading_duplicate_findings+=1
            #print(row)
    cmdb_line= assets_list.get(row[3])[0]
    if cmdb_line is None:
        #print(row[1:4])
        continue
    if len(cmdb_line)!=13:
        continue
    #print(cmdb_line)
    if cmdb_line[11]=='Retired':
        #if junk_counter<10:
            #print(row)
        junk_counter+=1
        #junk_list.append(row)

s_occurrence_list=Counter(occurence_list)
print(len(s_occurrence_list)) #gives 292 plugins with open findings not covered by exceptions.
print(sum(s_occurrence_list.values())) #gives 13328 findings not covered by exceptions.
print(s_occurrence_list)
#print(misleading_duplicate_findings)
#print(assets_list['10.60.2.117'])
#print(junk_counter) #I get 399 counts. But I only get 395 rows printed.
#print(junk_list)
#cve_list={}
#print(maximum_vulnerability_counter) #this is where the million is from. It's not particularly clever.

"""x = findings_list.get('F-700002')
print(x)"""

"""times_to_resolution=[]
for row in findings_list.values():
    start=datetime(int(row[8][0:4]),int(row[8][5:7]), int(row[8][8:]))
    if start-datetime(2026,3,21)
        if row[10]=='Fixed':
            end = datetime(int(row[11][0:4]),int(row[11][5:7]), int(row[11][8:]))
            
            difference = end - start
            times_to_resolution.append(difference.days)"""


"""with open("findings.csv", "r") as f:
    findings = csv.reader(f)
    for row in findings:
        #r_count+=1
        if row[10]=="Open":
            issues_counter+=1
            #if row[12]!="":
            #issues_counter-=1

print(issues_counter) #gives the 14007 issues from the report. Someone forgot to even remove the exceptions..."""

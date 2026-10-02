"""docstring"""
import csv
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
for l in assets_list.values():
    if isinstance(l, list):
        if l[2]!='POS terminal':
            unscanned+=1
        #print(l)
        assets_list.update({l[10]:(l, None)})
        #print(assets_list.get(l[10]))
    if l[0] is None:
        #print(l)
        discrepancies+=1

"""print(discrepancies) #yields 18 discrepancies. They're all network scans of servers from the  lab. I expect them to be already decommissioned and replaced by new test servers, but in a real world situation I would just send the lab guys an email to see if that was them.
print(unscanned) #yields 565 machines from the CMDB unseen by the scanner, 98 of which are not POS terminals handled by EXC-0003. It seems none of them are internet-facing, but most assets that are not internet-facing are still scanned. There is either risk here or """

"""x = assets_list.get("10.101.0.20")
print(x)"""

"""with open("findings.csv", "r") as f:
    findings = csv.reader(f)
    for row in findings:
        #r_count+=1
        if row[10]=="Open":
            issues_counter+=1
        if row[12]!="":
            issues_counter-=1

print(issues_counter)"""

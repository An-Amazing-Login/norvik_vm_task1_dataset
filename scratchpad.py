'''Scratchpad'''
import csv
p = open("plugins.csv", "r")
plugins = csv.reader(p)
cve_count=0
i=0
for row in plugins:
    if i==0:
        i=1
        continue
    else:
        cve_count+= int(row[4])

print(cve_count)

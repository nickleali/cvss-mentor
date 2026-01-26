# core of the record builder functions

from recordfunctions import find_cve_data

dataFolder = str("./data")

jsonRecord = find_cve_data(dataFolder, "CVE-2026-0544")

print(jsonRecord)
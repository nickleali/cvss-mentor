# High level

Look at individual CVEs and determine consistency.

Advise on the specific metrics.

## Setup

Build a script to programatially get all the vendors from the source material. (Done)

Then check the source for each CVE for that vendor and create a file for that CVE, grabbing a few of the items for later comparison. Store the comparisons there in JSON format. Ensure we can update it later. Get the following:

* CVSS for vendor and NIST
* CWE
* vendor / automated description


## Comparisons

### Show don't tell

Just show the differences and what it means.

### Language 
Take the descriptions and examine.

Diff the existing description versus the derived language.

TODO -- where is that generator script?

### CWE

Check the CWE against known examples in the CVSS examples and check if the vector is consistent.

### References

Point to the CVMAP report and grab reasons why for the differences.
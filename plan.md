# CVSS Mentor

Compare aspects of CVE to help determine assessment accuracy 

Goal of improving assessment, come to consensus on assessment and ensure more agreement between different assessors

Reference examples 

Check language 

Build methodology and enforce in software 

Layer on environmental template 


## Data Structures

How much and what to store in the database. How much to do at the presentation layer versus store for long periods of time.

Store all the CVE data and the CVSS assessments

Determine on a per record basis the differences


## Instantiation script

Set up a script that builds everything. So that when I inevitably screw this up I can restart it easily without much manual effort and allows for replicability.

Unzips files based on the data sources desired. 

Builds database and tables.

Processes the data initially and stuffs it into the database.


## Individual Checks

### Multiple data sources

Does NVD and others match? Why not? What are the differences? 

### Language

Scrape the description to see if it relates to the vector. Use the work from the Words Matter guide.

Output the simple description based on the script. How can we update with our language work?

### CWE

See if the CWE matches the examples. Build comparisons from CVSS examples to reference.

## Overall analysis

### Checks by vendor

See compliance on a per vendor basis.

What are the most common differences

### Checks by vulnerability class

Do XSS match or are they different, etc.

### Outliers

What CVSS scores do not match their vectors
Where are some really big gaps in CVSS assessments

## Frameworks and Technologies for implementation

### Storage 

Some kind of SQL to store the records.

How much in the database versus how much in the presentation layer / reporting?

Stored procedures and ready reports that are cached.

Prepopulate derivative tables of various statistics. The front end can hit those reports rather than all the raw data.

Linked value keys of keys where the table is a summary of all the differences in the vector strings.

### SQL tables

#### Main table

| CVE (key) | vendor vector | NVD vector | vendor | 
| data key | CVSS vector | CVSS vector | vendor name (normalized) |

#### Diffs

Useful to have a derived table of diffs? This table can be each CVE and the list of all vectors, different or not. Allows summing stats later. Maybe the easiest way to calculate common values of diffs?

| CVE (key) | vector 1 diff | vector N+1, etc.|
| CVE-2020-12345 | True | False | False | True

#### Relation stats tables

database for building stats so the front-end can hit this

##### Vendor stats
| vendor | count | diffs | summary of diffs (count of metrics that are different) |
| vendor name (from main) | record counts | some stats |

### APIs

Just use FastAPI.

### Presentation layer

What simple framework would work to allow dynamic reporting?

React of some kind of flavor. Next.js. 

Bun https://bun.com/docs/runtime/http/server
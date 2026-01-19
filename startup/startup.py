# set of steps to set up the application

import json

# 0. load database connection parameters from config file
## 

postgresConf = 'postgres-config.json'

try:
    with open(postgresConf, 'r', encoding='utf-8') as file:
        postgresConfLoaded = json.load(file)
        if isinstance(postgresConfLoaded, list):
            print (f"Loaded JSON list from '{postgresConfLoaded}':")
        else:
            print("Error: The file does not contain a top-level JSON list.")
except FileNotFoundError:
    print(f"Error: The file '{postgresConf}' was not found.")
except json.JSONDecodeError:
    print("Error: Failed to decode JSON from the file. Check for invalid JSON syntax.")

# 1. create the database
## call database-build.py functions

# 2. scrape files in the source directory, return JSON list
## call source-scraper.py functions

# 3. store the JSON list in the database
## create new module database-store.py with functions to store data

# 4. create complimentary stats tables
# automatically build database on startup

'''
Using psycopg to connect to a PostgreSQL database and create necessary tables if they do not exist.
https://pypi.org/project/psycopg/
'''

import psycopg
from psycopg import extensions

def setup_postgresql_database(db_params):
# Connection parameters for the default postgres database
    '''db_params = {
        "host": "localhost",
        "user": "dbuser",
        "password": "dbpass",
        "port": "12345"
        }'''

    conn = None
    try:
        # 1. Connect to default 'postgres' database to create the new DB
        conn = psycopg.connect(dbname='postgres', **db_params)
        conn.set_isolation_level(extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()

        # 2. Create the new database
        new_db_name = "cvss-mentor"
        cursor.execute(f"CREATE DATABASE {new_db_name}")
        print(f"Database '{new_db_name}' created successfully.")
        
        # Close connection to 'postgres'
        cursor.close()
        conn.close()

        # 3. Connect to the newly created database
        conn = psycopg.connect(dbname=new_db_name, **db_params)
        cursor = conn.cursor()

        # 4. Define and execute Table creation
        create_table_query = """
        CREATE TABLE employees (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            department VARCHAR(50),
            joined_date DATE DEFAULT CURRENT_DATE
        );
        """
        cursor.execute(create_table_query)
        
        # Commit the table creation
        conn.commit()
        print("Table 'employees' created successfully.")

    except Exception as error:
        print(f"Error: {error}")

    finally:
        # 5. Close the cursor and connection
        if conn:
            cursor.close()
            conn.close()
            print("PostgreSQL connection is closed.")
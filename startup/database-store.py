import psycopg2
import json

def store_json_list(data_to_store):
    # Connection parameters
    # how can we load these from a config file?
    db_params = {
        "host": "localhost",
        "database": "company_db",
        "user": "your_username",
        "password": "your_password",
        "port": "5432"
    }

    conn = None
    try:
        # 1. Connect to the database
        conn = psycopg2.connect(**db_params)
        cursor = conn.cursor()

        # 2. Create a table with a JSONB column (if it doesn't exist)
        # We use JSONB for better performance and indexing capabilities
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                metadata JSONB
            );
        """)

        # 3. Convert Python list to JSON string
        # PostgreSQL's JSONB type accepts a valid JSON string
        json_data = json.dumps(data_to_store)

        # 4. Insert the JSON data
        insert_query = "INSERT INTO logs (metadata) VALUES (%s)"
        cursor.execute(insert_query, (json_data,))

        # 5. Commit the transaction
        conn.commit()
        print("JSON list stored successfully.")

    except Exception as error:
        print(f"Error: {error}")
    
    finally:
        # 6. Close the connection
        if conn:
            cursor.close()
            conn.close()
            print("PostgreSQL connection is closed.")

# Example Usage:
my_list = [
    {"event": "login", "status": "success", "timestamp": "2026-01-19T10:00:00"},
    {"event": "upload", "status": "pending", "timestamp": "2026-01-19T10:05:00"},
    {"event": "logout", "status": "success", "timestamp": "2026-01-19T10:10:00"}
]

# store_json_list(my_list)
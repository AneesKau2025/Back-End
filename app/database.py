import mysql.connector
from mysql.connector import Error
import sqlalchemy as sa


class Database:
    """
    A class to manage MySQL database connections and operations.
    """

    def __init__(self, config=None):
        """
        Initialize the Database object with the given configuration.
        If no configuration is provided, the default settings are used.
        """
        # Database connection configuration
        # You can override this by passing a custom config dictionary.
        if config is None:
            self.config = {
                'user': 'u3umuox74lnakptl',
                'password': '0srpOCGoVPmIztY6dCz6',
                'host': 'by6emhh9nagcum7mbodr-mysql.services.clever-cloud.com',
                'database': 'by6emhh9nagcum7mbodr',
                'port': 3306
            }
        else:
            self.config = config

    def get_db_connection(self):
        """
        Establishes and returns a MySQL database connection.
        """
        try:
            connection = mysql.connector.connect(**self.config)
            if connection.is_connected():
                print("Successfully connected to the database")
                return connection
        except Error as e:
            print("Error while connecting to MySQL:", e)
        return None

    def execute_database_query(self, query, params=None):
        """
        Establishes a connection, executes the given query, returns the results,
        and ensures the connection is closed.
        """
        connection = None
        try:
            connection = self.get_db_connection()
            if connection is None:
                return None
            cursor = connection.cursor()
            cursor.execute(query, params or ())
            results = cursor.fetchall()
            cursor.close()
            return results
        except Error as e:
            print("Error during query execution:", e)
            return None
        finally:
            if connection and connection.is_connected():
                connection.close()
                print("MySQL connection is closed")

    def test_database_connection(self):
        """
        Tests the database connection by executing a sample query.
        
        This method is useful for checking connectivity during development
        or as part of a health-check routine.
        
        :return: True if the connection and query are successful, False otherwise.
        """
        results = self.execute_database_query("SELECT DATABASE();")
        if results is None:
            return False
        print("You're connected to database:", results)
        return True

    def close_resources(self, cursor=None, connection=None):
        """
        Closes the cursor and the connection if they are open.
        
        :param cursor: The database cursor to be closed.
        :param connection: The database connection to be closed.
        """
        if cursor is not None:
            try:
                cursor.close()
                print("Cursor closed successfully.")
            except Exception as e:
                print("Error closing cursor:", e)
        if connection is not None:
            try:
                if connection.is_connected():
                    connection.close()
                    print("MySQL connection is closed.")
            except Exception as e:
                print("Error closing connection:", e)


# ---------------------- SQLAlchemy Connection Handling ----------------------

# Initialize database connection
connection = Database()
DATABASE_URL = f"mysql+mysqlconnector://{connection.config['user']}:{connection.config['password']}@{connection.config['host']}:{connection.config['port']}/{connection.config['database']}"

# Create SQLAlchemy engine
engine = sa.create_engine(DATABASE_URL)

# Reflect metadata to recognize existing tables
metadata = sa.MetaData()
metadata.reflect(bind=engine)

def get_connection():
    """Returns a new SQLAlchemy database connection."""
    return engine.connect()


# Execute the test when running this script directly
if __name__ == "__main__":
    db = Database()  # Create an instance of the Database class
    db.test_database_connection()  # Execute the test connection method

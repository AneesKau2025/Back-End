import sqlalchemy as sa
from sqlalchemy.sql import func
from sqlalchemy import create_engine, MetaData

# Database connection configuration
db_config = {
    'user': 'u3umuox74lnakptl',
    'password': '0srpOCGoVPmIztY6dCz6',
    'host': 'by6emhh9nagcum7mbodr-mysql.services.clever-cloud.com',
    'database': 'by6emhh9nagcum7mbodr',
    'port': 3306
}

# Create a connection URL string for SQLAlchemy
connection_url = f"mysql+mysqlconnector://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['database']}"

# Create the SQLAlchemy engine
engine = create_engine(connection_url)

# Connect to the database
connection = engine.connect()

# Initialize metadata for table creation
metadata = MetaData()

# Function to create tables and test connection
def main():
    # Create all tables
    metadata.create_all(engine)
    
    # Test the connection
    try:
        result = connection.execute(sa.text("SELECT 1"))
        print("Connection works! Test result:", result.fetchone())
    except Exception as e:
        print("Connection failed:", e)

#----------------------------------------------------
#                       Tables
#----------------------------------------------------

parentTable = sa.Table(
    "Parent",
    metadata,
    sa.Column("parentUserName", sa.String(20), primary_key=True),
    sa.Column("passwordHash", sa.String(128), nullable=False),
    sa.Column("firstName", sa.String(20), nullable=False),
    sa.Column("lastName", sa.String(20), nullable=False),
    sa.Column("email", sa.String(50), nullable=False),
)

childTable = sa.Table(
    "Child",
    metadata,
    sa.Column("childUserName", sa.String(20), primary_key=True),
    sa.Column("passwordHash", sa.String(128), nullable=False),
    sa.Column("firstName", sa.String(20), nullable=False),
    sa.Column("lastName", sa.String(20), nullable=False),
    sa.Column("email", sa.String(50), nullable=False),
    sa.Column("dateOfBirth", sa.Date, nullable=False),
    sa.Column("timeControl", sa.Integer, nullable=True),
    sa.Column("parentUserName", sa.String(20), sa.ForeignKey("Parent.parentUserName"), nullable=False),
    sa.Column("profileIcon", sa.String(255), nullable=True),
)

friendshipTable = sa.Table(
    "Friendship",
    metadata,
    sa.Column("friendshipID", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("childUserName1", sa.String(20), sa.ForeignKey("Child.childUserName"), nullable=False),
    sa.Column("childUserName2", sa.String(20), sa.ForeignKey("Child.childUserName"), nullable=False),
    sa.Column("status", sa.Enum("Active", "Blocked", name="friendship_status_enum"), nullable=False, default="Active"),
    sa.Column("friendshipTimeStamp", sa.DateTime, server_default=func.now(), nullable=False)
)

requestTable = sa.Table(
    "Request",
    metadata,
    sa.Column("requestID", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("requestChildUserName", sa.String(20), sa.ForeignKey("Child.childUserName"), nullable=False),
    sa.Column("ReceiverChildUserName", sa.String(20), sa.ForeignKey("Child.childUserName"), nullable=False),
    sa.Column("requestStatus", sa.Enum("Pending", "Accepted", "Declined", name="request_status_enum"), nullable=False, default="Pending"),
    sa.Column("requestTimeStamp", sa.DateTime, server_default=func.now(), nullable=False),
    sa.Column("acceptedTimeStamp", sa.DateTime, nullable=True),
    sa.Column("declinedTimeStamp", sa.DateTime, nullable=True)
)

riskTypeTable = sa.Table(
    "RiskType",
    metadata,
    sa.Column("riskID", sa.Integer, primary_key=True),
    sa.Column("riskType", sa.String(100), nullable=False)
)

messageTable = sa.Table(
    "Message",
    metadata,
    sa.Column("messageID", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("senderChildUserName", sa.String(20), sa.ForeignKey("Child.childUserName"), nullable=False),
    sa.Column("receiverChildUserName", sa.String(20), sa.ForeignKey("Child.childUserName"), nullable=False),
    sa.Column("content", sa.String(255), nullable=False),
    sa.Column("timeStamp", sa.DateTime, server_default=func.now(), nullable=False),
    sa.Column("notificationFlag", sa.Boolean, nullable=False, server_default=sa.text("0")),
    sa.Column("RiskID", sa.Integer, sa.ForeignKey("RiskType.riskID"), server_default="0"),
)

notificationTable = sa.Table(
    "Notification",
    metadata,
    sa.Column("notificationID", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("messageID", sa.Integer, sa.ForeignKey("Message.messageID"), nullable=False),
    sa.Column("parentUserName", sa.String(20), sa.ForeignKey("Parent.parentUserName"), nullable=False),
)

#----------------------------------------------------

if __name__ == "__main__":
    main()

from pydantic import BaseModel
import sqlalchemy as sa
from app.database import get_connection
from fastapi import HTTPException, status
from fastapi import  status, Depends, HTTPException
from fastapi.security import  OAuth2PasswordRequestForm, OAuth2PasswordBearer
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext 
from datetime import timezone


class Child(BaseModel):
    childUserName: str
    email: str
    passwordHash: str
    firstName: str
    lastName: str
    dateOfBirth: str
    timeControl: int | None = None
    parentUserName: str
    profileIcon: str | None = None

class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    username: str or None = None 

#---------------------------------------------------------------------
SECRET_KEY="ca19e71bbdef859185ed9928a973d7af6095d2c6b9a6bed3684570f40439562f"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#----------------------------- create a child --------------------------------
def create_child(child_data: Child):
    """
    Insert new child into the database.
    """
    with get_connection() as conn:
        insert_query = sa.text("""
            INSERT INTO Child (childUserName, email, passwordHash, firstName, lastName, dateOfBirth, timeControl, parentUserName, profileIcon)
            VALUES (:username, :email, :password, :firstName, :lastName, :dob, :timeControl, :parentUserName, :profileIcon)
        """)
        conn.execute(insert_query, {
            "username": child_data.childUserName,
            "email": child_data.email,
            "password": child_data.passwordHash,
            "firstName": child_data.firstName,
            "lastName": child_data.lastName,
            "dob": child_data.dateOfBirth,
            "timeControl": child_data.timeControl,
            "parentUserName": child_data.parentUserName,
            "profileIcon": child_data.profileIcon
        })
        conn.commit()
    
    return {
        "message": "registered successfully!",
        "data": child_data.dict()
    }
    
#-------------------------------------------------------------------------
#-------------              child log ins               ------------------
#-------------------------------------------------------------------------

def authenticate_user(childUserName: str, enteredPassword: str):
    """
    Authenticate a child user by checking their username and password.
    """
    with get_connection() as conn:
        # Fetch the child's password hash and username from the Child table
        query = sa.text("""SELECT passwordHash, childUserName FROM Child WHERE childUserName = :childUserName""")
        result = conn.execute(query, {"childUserName": childUserName}).mappings().first()

    if not result:
        return None  # No child found with the given username

    dbPass = result['passwordHash']
    if enteredPassword == dbPass:
        return result  # Password matches
    return None  # Password does not match
    
#----------------------------------------------------
def createAccessToken(data:dict, expiresDelta: timedelta or None = None):
    toEncode = data.copy()
    if expiresDelta:
        expire = datetime.now(timezone.utc) + expiresDelta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=30)
        
    toEncode.update({"exp": expire})
    encodeJWT = jwt.encode(toEncode, SECRET_KEY, algorithm = ALGORITHM)
    return encodeJWT

#---------------------------------------------------------------------
async def getCurrentUser(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate" : "Bearer"})
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
        
    except JWTError:
        raise credentials_exception
        
    user = get_child(childUserName=token_data.username)  
    if user is None:
        raise credentials_exception
    return user

#---------------------------------- get the child full info------------------------------------
def get_child(childUserName: str):
    """
    Fetch child details from the database and return as a dictionary.
    """
    with get_connection() as conn:
        query = sa.text("SELECT * FROM Child WHERE childUserName = :username")
        result = conn.execute(query, {"username": childUserName}).mappings().fetchone()  

    if result:
        return {
            "message": "Child details retrieved successfully",
            "data": dict(result)
        }
    return {
        "message": "child not found",
        "data": None
    }


#-------------------------- get the name of the child  ----------------------------------

def get_child_name(childUserName: str):
    """
    Fetch the child's first name and last name from the database.
    """
    with get_connection() as conn:
        query = sa.text("""
            SELECT firstName, lastName
            FROM Child
            WHERE childUserName = :childUserName
        """)
        result = conn.execute(query, {"childUserName": childUserName}).mappings().fetchone()
    
    if result:
        return {
            "status": "success",
            "message": "Child name retrieved successfully",
            "data": dict(result)
        }
    return {
        "status": "error",
        "message": "Child not found",
        "data": None
    }

#-------------------------- update settings ----------------------------------
def update_settings(childUserName: str, settings: dict):
    """
    Update child-specific settings (e.g., first name, last name).
    """
    with get_connection() as conn:
        # update query based on the provided settings
        update_fields = []
        update_values = {"childUserName": childUserName}

        if "firstName" in settings:
            update_fields.append("firstName = :firstName")
            update_values["firstName"] = settings["firstName"]

        if "lastName" in settings:
            update_fields.append("lastName = :lastName")
            update_values["lastName"] = settings["lastName"]

        update_query = sa.text(f"""
            UPDATE Child
            SET {", ".join(update_fields)}
            WHERE childUserName = :childUserName
        """)
        conn.execute(update_query, update_values)
        conn.commit()

    return {
        "message": "settings updated successfully!",
        "data": settings
    }
    
#---------------------------------------------------------------------
#-------------------- Friendship between children --------------------
#---------------------------------------------------------------------

# crear friend requests
def create_friend_request(sender: str, receiver: str):
    with get_connection() as conn:
        check_sender_query = sa.text("""SELECT * FROM Child WHERE childUserName = :sender""")
        check_receiver_query = sa.text("""SELECT * FROM Child WHERE childUserName = :receiver""")
        
        sender_exists = conn.execute(check_sender_query, {"sender": sender}).fetchone()
        receiver_exists = conn.execute(check_receiver_query, {"receiver": receiver}).fetchone()
        
        if not sender_exists:
            return {
                "status": "error",
                "message": "Sender child does not exist.",
                "data": None
            }
        if not receiver_exists:
            return {
                "status": "error",
                "message": "Receiver child does not exist.",
                "data": None
            }
        
        check_query = sa.text("""
            SELECT * FROM Request
            WHERE requestChildUserName = :sender AND ReceiverChildUserName = :receiver AND requestStatus = 'Pending'
        """)
        existing_request = conn.execute(check_query, {"sender": sender, "receiver": receiver}).fetchone()
        
        # to maintain redundent request 
        if existing_request:
            return {
                "status": "error",
                "message": "Friend request already exists.",
                "data": None
            }

        insert_query = sa.text("""
            INSERT INTO Request (requestChildUserName, ReceiverChildUserName, requestStatus)
            VALUES (:sender, :receiver, 'Pending')
        """)
        conn.execute(insert_query, {
            "sender": sender,
            "receiver": receiver,
        })
        conn.commit()
    
    return {
        "message": "Friend request sent successfully!",
        "data": None
    }

#----------------------------- accept friends ---------------------

def accept_friend_request(request_id: int):
    with get_connection() as conn:
        # get details first
        select_query = sa.text("""
            SELECT requestChildUserName, ReceiverChildUserName, requestStatus 
            FROM Request 
            WHERE requestID = :request_id
        """)
        request_data = conn.execute(select_query, {"request_id": request_id}).fetchone()

        if not request_data:
            return {
                "status": "error",
                "message": "Friend request not found.",
                "data": None
            }

        if request_data['requestStatus'] != 'Pending':
            return {
                "status": "error",
                "message": "Friend request has already been processed.",
                "data": None
            }

        # mark request as accepted
        update_query = sa.text("""
            UPDATE Request 
            SET requestStatus = 'Accepted' 
            WHERE requestID = :request_id
        """)
        conn.execute(update_query, {"request_id": request_id})
        
        # create friendship record
        insert_query = sa.text("""
            INSERT INTO Friendship (childUserName1, childUserName2, status)
            VALUES (:child1, :child2, 'Active')
        """)
        conn.execute(insert_query, {
            "child1": request_data['requestChildUserName'],
            "child2": request_data['ReceiverChildUserName']
        })
        
        conn.commit()

    return {
        "message": "Friend request accepted!",
        "data": None
    }

#----------------------------- reject friends ---------------------
def reject_friend_request(request_id: int):
    with get_connection() as conn:
        # Fetch the request details first
        select_query = sa.text("""
            SELECT requestChildUserName, ReceiverChildUserName, requestStatus 
            FROM Request 
            WHERE requestID = :request_id
        """)
        request_data = conn.execute(select_query, {"request_id": request_id}).fetchone()

        if not request_data:
            return {
                "status": "error",
                "message": "Friend request not found.",
                "data": None
            }

        if request_data['requestStatus'] != 'Pending':
            return {
                "status": "error",
                "message": "Friend request has already been processed.",
                "data": None
            }

        # Mark the request as declined
        update_query = sa.text("""
            UPDATE Request 
            SET requestStatus = 'Declined' 
            WHERE requestID = :request_id
        """)
        conn.execute(update_query, {"request_id": request_id})
        conn.commit()

    return {
        "message": "Friend request rejected!",
        "data": None
    }
    
    
#----------------------------- fetch friends ---------------------

def get_friends(childUserName: str):
    with get_connection() as conn:
        query = sa.text("""
            SELECT c.childUserName, c.firstName, c.lastName, c.profileIcon
            FROM Friendship f
            JOIN Child c ON (f.childUserName1 = c.childUserName OR f.childUserName2 = c.childUserName)
            WHERE (f.childUserName1 = :childUserName OR f.childUserName2 = :childUserName) AND f.status = 'Active' AND c.childUserName != :childUserName
        """)
        results = conn.execute(query, {"childUserName": childUserName}).mappings().fetchall()
    
    return {
        "message": "Friends retrieved successfully",
        "data": [dict(row) for row in results] if results else []
    }
    
#----------------------------- block friends ---------------------
def block_friend(childUserName: str, friendUserName: str):
    with get_connection() as conn:
        # if already exist
        check_query = sa.text("""
            SELECT * FROM Friendship
            WHERE ((childUserName1 = :childUserName AND childUserName2 = :friendUserName)OR (childUserName1 = :friendUserName AND childUserName2 = :childUserName)) AND status = 'Active'
        """)
        friendship = conn.execute(check_query, {
            "childUserName": childUserName,
            "friendUserName": friendUserName
        }).fetchone()

        if not friendship:
            return {
                "status": "error",
                "message": "Friendship not found.",
                "data": None
            }

        # update status in db
        update_query = sa.text("""
            UPDATE Friendship
            SET status = 'Blocked'
            WHERE ((childUserName1 = :childUserName AND childUserName2 = :friendUserName) OR (childUserName1 = :friendUserName AND childUserName2 = :childUserName))
        """)
        conn.execute(update_query, {
            "childUserName": childUserName,
            "friendUserName": friendUserName
        })
        conn.commit()

    return {
        "message": "Friend blocked successfully!",
        "data": None
    }
    

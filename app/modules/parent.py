from pydantic import BaseModel
import sqlalchemy as sa
from app.database import get_connection
from datetime import timezone
from fastapi import  status, Depends, HTTPException
from fastapi.security import  OAuth2PasswordRequestForm, OAuth2PasswordBearer
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext 

class Parent(BaseModel):
    parentUserName: str
    email: str
    passwordHash: str
    firstName: str
    lastName: str
    
class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    username: str or None = None 

#---------------------------------------------------------------------
SECRET_KEY="ca19e71bbdef859185ed9928a973d7af6095d2c6b9a6bed3684570f40439562f"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#---------------------------------------------------------------------



def get_parent(parentUserName: str):
    with get_connection() as conn:
        query = sa.text("SELECT * FROM Parent WHERE parentUserName = :username")
        result = conn.execute(query, {"username": parentUserName}).mappings().fetchone() 
    
    if result:
        return dict(result)  

def create_parent(parent_data: Parent):
    """
    Insert new parent into the database.
    """
    with get_connection() as conn:
        insert_query = sa.text("""
            INSERT INTO Parent (parentUserName, email, passwordHash, firstName, lastName) 
            VALUES (:username, :email, :password, :firstName, :lastName)
        """)
        conn.execute(insert_query, {
            "username": parent_data.parentUserName,
            "email": parent_data.email,
            "password": parent_data.passwordHash,  
            "firstName": parent_data.firstName,
            "lastName": parent_data.lastName,
        })
        conn.commit()
    
    return {"message": "Parent registered successfully!", "data": parent_data.dict()}



def get_children_of_parent(parentUserName: str):
    """
    Fetch all children associated with the given parent username.
    """
    with get_connection() as conn:
        query = sa.text("SELECT * FROM Child WHERE parentUserName = :parentUsername")
        results = conn.execute(query, {"parentUsername": parentUserName}).mappings().fetchall() 
    
    return [dict(row) for row in results] if results else [] 



def get_parent_name(parentUserName: str):
    with get_connection() as conn:
        query = sa.text("SELECT firstName, lastName FROM Parent WHERE parentUserName = :username")
        result = conn.execute(query, {"username": parentUserName}).mappings().fetchone()
    
    if result:
        return dict(result)
    raise HTTPException(status_code=404, detail="Parent not found")

def get_parent_info(parentUserName: str):
    """
    Fetch the parent's information from the database.
    """
    with get_connection() as conn:
        query = sa.text("SELECT * FROM Parent WHERE parentUserName = :username")
        result = conn.execute(query, {"username": parentUserName}).mappings().fetchone()
    
    if not result:
        return None
    
    return dict(result)

def update_child_settings(parentUserName: str, childUserName: str, settings: dict):
    with get_connection() as conn:
        update_query = sa.text("""
            UPDATE Child
            SET timeControl = :timeControl, profileIcon = :profileIcon
            WHERE childUserName = :childUserName AND parentUserName = :parentUserName
        """)
        conn.execute(update_query, {
            "timeControl": settings.get("timeControl"),
            "profileIcon": settings.get("profileIcon"),
            "childUserName": childUserName,
            "parentUserName": parentUserName,
        })
        conn.commit()
    return {"message": "Child settings updated successfully"}

def delete_parent_account(parentUserName: str):
    with get_connection() as conn:
        # Delete children first (due to foreign key constraints)
        conn.execute(sa.text("DELETE FROM Child WHERE parentUserName = :parentUserName"), {"parentUserName": parentUserName})
        # Delete parent
        conn.execute(sa.text("DELETE FROM Parent WHERE parentUserName = :parentUserName"), {"parentUserName": parentUserName})
        conn.commit()
    return {"message": "Parent account and associated children deleted successfully"}


def update_parent_settings(parentUserName: str, settings: dict):
    with get_connection() as conn:
        update_query = sa.text("""
            UPDATE Parent
            SET email = :email, passwordHash = :passwordHash
            WHERE parentUserName = :parentUserName
        """)
        conn.execute(update_query, {
            "email": settings.get("email"),
            "passwordHash": settings.get("passwordHash"),
            "parentUserName": parentUserName,
        })
        conn.commit()
    return {"message": "Parent settings updated successfully"}

def get_notifications(parentUserName: str):
    with get_connection() as conn:
        query = sa.text("""
            SELECT 
                n.notificationID,
                m.messageID,
                m.content,
                m.timeStamp,
                m.senderChildUserName AS sender,
                m.receiverChildUserName AS receiver,
                c.firstName AS receiverFirstName,
                c.lastName AS receiverLastName,
                m.riskID  -- Include riskID from the Message table
            FROM 
                Notification n
            JOIN 
                Message m ON n.messageID = m.messageID
            JOIN 
                Child c ON m.receiverChildUserName = c.childUserName
            WHERE 
                n.parentUserName = :parentUserName
        """)
        results = conn.execute(query, {"parentUserName": parentUserName}).mappings().fetchall()
    
    return [dict(row) for row in results] if results else []


def set_child_time_control(parentUserName: str, childUserName: str, time_control: int):
    with get_connection() as conn:
        update_query = sa.text("""
            UPDATE Child
            SET timeControl = :timeControl
            WHERE childUserName = :childUserName AND parentUserName = :parentUserName
        """)
        conn.execute(update_query, {
            "timeControl": time_control,
            "childUserName": childUserName,
            "parentUserName": parentUserName,
        })
        conn.commit()
    return {"message": "Child time control updated successfully"}

#-------------------------------------------------------------------------
#-------------            parent log ins                ------------------
#-------------------------------------------------------------------------

def authenticate_user(parentUserName: str, enteredPassword: str):
    with get_connection() as conn:
        query = sa.text("SELECT passwordHash, parentUserName FROM Parent WHERE parentUserName = :parentUsername")
        result = conn.execute(query, {"parentUsername": parentUserName}).mappings().first()

    if not result:
        return None  #  no user found

    dbPass = result['passwordHash']
    if enteredPassword == dbPass:
        return result  #  if password matches
    return None  #  password doesn't match
    
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
        
    user = get_parent(parentUserName=token_data.username)  
    if user is None:
        raise credentials_exception
    return user


#---------------------------------------------------------------
#@app.post("/token", response_model=Token)
async def loginForAccessToken(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail= "Incorrect username or password", headers={"WWW-Authenticat" : "Bearer"})

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = createAccessToken(data={"sub": Parent.userName}, expiresDelta= access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}
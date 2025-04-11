
from pydantic import BaseModel
import sqlalchemy as sa
from app.database import get_connection
from datetime import timezone
from fastapi import status, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext 
from typing import Optional, Union
from app.modules.child import Child  

# --------------------- base models -----------------------
class FriendResponse(BaseModel):
    message: str
    data: Optional[Union[dict, list]] = None

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

#-------------------------- constants -------------------------------
SECRET_KEY = "ca19e71bbdef859185ed9928a973d7af6095d2c6b9a6bed3684570f40439562f"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# tokenUrl path
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/parent/login")

#---------------------------------------------------------------------
def get_parent(parentUserName: str):
    with get_connection() as conn:
        query = sa.text("SELECT * FROM Parent WHERE parentUserName = :username")
        result = conn.execute(query, {"username": parentUserName}).mappings().fetchone()
    return dict(result) if result else None

#---------------------------------------------------------------------
def create_parent(parent_data: Parent):
    hashed_password = get_password_hash(parent_data.passwordHash)
    parent_data.passwordHash = hashed_password

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

#---------------------------------------------------------------------
def create_child(child_data: Child) -> FriendResponse:
    hashed_password = get_password_hash(child_data.passwordHash)
    child_data.passwordHash = hashed_password

    with get_connection() as conn:
        conn.execute(
            sa.text("""
                INSERT INTO Child 
                (childUserName, email, passwordHash, firstName, lastName, dateOfBirth, timeControl, parentUserName, profileIcon)
                VALUES 
                (:username, :email, :password, :firstName, :lastName, :dob, :timeControl, :parentUserName, :profileIcon)
            """),
            {
                "username": child_data.childUserName,
                "email": child_data.email,
                "password": child_data.passwordHash,
                "firstName": child_data.firstName,
                "lastName": child_data.lastName,
                "dob": child_data.dateOfBirth,
                "timeControl": child_data.timeControl,
                "parentUserName": child_data.parentUserName,
                "profileIcon": child_data.profileIcon
            }
        )
        conn.commit()
    
    return FriendResponse(
        message="Child registered successfully!",
        data=child_data.dict()
    )

#---------------------------------------------------------------------
def get_children_of_parent(parentUserName: str):
    with get_connection() as conn:
        query = sa.text("SELECT * FROM Child WHERE parentUserName = :parentUsername")
        results = conn.execute(query, {"parentUsername": parentUserName}).mappings().fetchall()
    return [dict(row) for row in results] if results else []

#---------------------------------------------------------------------
def get_parent_name(parentUserName: str):
    with get_connection() as conn:
        query = sa.text("SELECT firstName, lastName FROM Parent WHERE parentUserName = :username")
        result = conn.execute(query, {"username": parentUserName}).mappings().fetchone()
    if result:
        return dict(result)
    raise HTTPException(status_code=404, detail="Parent not found")
#---------------------------------------------------------------------
def get_parent_info(parentUserName: str):
    with get_connection() as conn:
        query = sa.text("SELECT * FROM Parent WHERE parentUserName = :username")
        result = conn.execute(query, {"username": parentUserName}).mappings().fetchone()
    return dict(result) if result else None
#---------------------------------------------------------------------
def update_parent_settings(parentUserName: str, settings: dict):
    update_fields = []
    update_values = {}

    if "parentUserName" in settings or "passwordHash" in settings:
        raise HTTPException(status_code=400, detail="You cannot update the username or password from this endpoint.")

    if settings.get("email") is not None:
        update_fields.append("email = :email")
        update_values["email"] = settings["email"]

    if settings.get("firstName") is not None:
        update_fields.append("firstName = :firstName")
        update_values["firstName"] = settings["firstName"]

    if settings.get("lastName") is not None:
        update_fields.append("lastName = :lastName")
        update_values["lastName"] = settings["lastName"]

    if not update_fields:
        raise HTTPException(status_code=400, detail="No valid fields provided to update.")

    update_values["parentUserName"] = parentUserName

    query = f"""UPDATE Parent SET {', '.join(update_fields)} WHERE parentUserName = :parentUserName"""

    with get_connection() as conn:
        conn.execute(sa.text(query), update_values)
        conn.commit()

    return {"message": "Parent information updated successfully"}
#---------------------------------------------------------------------
def delete_parent_account(parentUserName: str):
    with get_connection() as conn:
        conn.execute(sa.text("DELETE FROM Child WHERE parentUserName = :parentUserName"), {"parentUserName": parentUserName})
        conn.execute(sa.text("DELETE FROM Parent WHERE parentUserName = :parentUserName"), {"parentUserName": parentUserName})
        conn.commit()
    return {"message": "Parent account and associated children deleted successfully"}
#---------------------------------------------------------------------
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
                m.riskID
            FROM Notification n
            JOIN Message m ON n.messageID = m.messageID
            JOIN Child c ON m.receiverChildUserName = c.childUserName
            WHERE n.parentUserName = :parentUserName
        """)
        results = conn.execute(query, {"parentUserName": parentUserName}).mappings().fetchall()
    return [dict(row) for row in results] if results else []

#---------------------------- child time usage functions -------------------------------------
def get_child_usage_status(parentUserName: str, childUserName: str) -> dict:
    with get_connection() as conn:
        result = conn.execute(
            sa.text("""
                SELECT timeControl, sessionStartTime, isLocked
                FROM Child
                WHERE childUserName = :childUserName AND parentUserName = :parentUserName
            """),
            {"childUserName": childUserName, "parentUserName": parentUserName}
        ).mappings().first()

        if not result:
            raise HTTPException(status_code=404, detail="الطفل غير موجود أو لا يتبع لهذا الأب")

        if result['isLocked']:
            return {"remainingMinutes": 0, "isLocked": True}

        time_allowed = result['timeControl']
        start_time = result['sessionStartTime']

        if not time_allowed or not start_time:
            return {"remainingMinutes": time_allowed or 0, "isLocked": False}

        now = datetime.utcnow()
        elapsed_minutes = (now - start_time).total_seconds() / 60
        remaining = time_allowed - elapsed_minutes

        if remaining <= 0:
            conn.execute(
                sa.text("UPDATE Child SET isLocked = 1 WHERE childUserName = :childUserName"),
                {"childUserName": childUserName}
            )
            conn.commit()
            return {"remainingMinutes": 0, "isLocked": True}

        return {"remainingMinutes": int(remaining), "isLocked": False}

def set_child_usage_limit(parentUserName: str, childUserName: str, minutes: int):
    with get_connection() as conn:

        result = conn.execute(
            sa.text("""
                UPDATE Child
                SET timeControl = :minutes, sessionStartTime = NULL, isLocked = 0
                WHERE childUserName = :childUserName AND parentUserName = :parentUserName
            """),
            {
                "minutes": minutes,
                "childUserName": childUserName,
                "parentUserName": parentUserName
            }
        )
        conn.commit()

    return {"message": f"✅ تم تعيين مدة {minutes} دقيقة لطفلك {childUserName}"}

def reset_child_usage(parentUserName: str, childUserName: str):
    with get_connection() as conn:
        now = datetime.utcnow()
        result = conn.execute(
            sa.text("""
                UPDATE Child
                SET sessionStartTime = :now, isLocked = 0
                WHERE childUserName = :childUserName AND parentUserName = :parentUserName
            """),
            {
                "now": now,
                "childUserName": childUserName,
                "parentUserName": parentUserName
            }
        )
        conn.commit()

    return {"message": f"✅ تم إعادة ضبط وقت الاستخدام للطفل {childUserName} وبداية جلسة جديدة"}


# ---------------------------- Authentication ------------------------------------
def authenticate_user(parentUserName: str, enteredPassword: str):
    with get_connection() as conn:
        query = sa.text("SELECT passwordHash, parentUserName FROM Parent WHERE parentUserName = :parentUsername")
        result = conn.execute(query, {"parentUsername": parentUserName}).mappings().first()
    if not result:
        return None
    if verify_password(enteredPassword, result['passwordHash']):
        return result
    return None

def createAccessToken(data: dict, expiresDelta: timedelta or None = None):
    toEncode = data.copy()
    expire = datetime.now(timezone.utc) + (expiresDelta or timedelta(minutes=30))
    toEncode.update({"exp": expire})
    return jwt.encode(toEncode, SECRET_KEY, algorithm=ALGORITHM)


async def getCurrentUser(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
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

async def loginForAccessToken(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = createAccessToken(data={"sub": user["parentUserName"]}, expiresDelta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# ----------------- encoding and decoding ------------------
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

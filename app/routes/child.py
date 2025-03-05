from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app.modules import child as child_module
from app.modules.parent import getCurrentUser  
from datetime import timedelta



router = APIRouter()

# -------------------- create a child --------------------
@router.post("/child/")
def add_child(child_data: child_module.Child):
    return child_module.create_child(child_data)

# ---------------------- login -----------------------------
@router.post("/child/login", response_model=child_module.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Authenticate the child user
    user = child_module.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate an access token
    access_token_expires = timedelta(minutes=child_module.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = child_module.createAccessToken(
        data={"sub": form_data.username}, expiresDelta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}
# -------------------- get child's info --------------------
@router.get("/child/")
def read_child(current_user: dict = Depends(getCurrentUser)):
    if current_user["userType"] != "child":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access this data"
        )
    childUserName = current_user["childUserName"]
    return child_module.get_child(childUserName)

# ---------------------- get child name ------------------------
@router.get("/child/name")
def get_child_name(current_user: dict = Depends(getCurrentUser)):
    if current_user["userType"] != "child":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access this data"
        )
    childUserName = current_user["childUserName"]
    return child_module.get_child_name(childUserName)
#-------------------- Update child settings --------------------
@router.put("/child/settings")
def update_child_settings(
    child_data: child_module.Child,
    current_user: dict = Depends(getCurrentUser)
):
    if current_user["userType"] != "child":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to update this child's settings"
        )
    childUserName = current_user["childUserName"]
    return child_module.update_settings(childUserName, child_data)

#--------------------- Friends APIs -----------------------------
# send friend request 
@router.post("/friend/request")
def send_friend_request(
    receiverChildUserName: str,
    current_user: dict = Depends(getCurrentUser)
):
    if current_user["userType"] != "child":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to send this request"
        )
    senderChildUserName = current_user["childUserName"]
    return child_module.create_friend_request(senderChildUserName, receiverChildUserName)

#-------------------- accept friend request --------------------
@router.post("/friend/accept/{requestID}")
def accept_request(
    requestID: int,
    current_user: dict = Depends(getCurrentUser)
):
    if current_user["userType"] != "child":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to accept this request"
        )
    return child_module.accept_friend_request(requestID)

#-------------------- reject friend request --------------------
@router.post("/friend/decline/{requestID}")
def decline_request(
    requestID: int,
    current_user: dict = Depends(getCurrentUser)
):
    if current_user["userType"] != "child":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to decline this request"
        )
    return child_module.reject_friend_request(requestID)

# -------------------- block friend --------------------
@router.post("/friend/block/{friendUserName}")
def block_friend(
    friendUserName: str,
    current_user: dict = Depends(getCurrentUser)
):
    if current_user["userType"] != "child":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to block this friend"
        )
    childUserName = current_user["childUserName"]
    return child_module.block_friend(childUserName, friendUserName)

# -------------------- get child's friends --------------------
@router.get("/child/friends")
def get_friends(current_user: dict = Depends(getCurrentUser)):
    if current_user["userType"] != "child":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access this data"
        )
    childUserName = current_user["childUserName"]
    return child_module.get_friends(childUserName)

#--------------------  logging out --------------------------
@router.post("/child/logout")
def logout():
    return {
        "message": "Logged out successfully. ",
        "data": None
    }
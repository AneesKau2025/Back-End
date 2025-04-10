from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta, datetime
from app.modules import child as child_module
from pydantic import BaseModel
from typing import Optional


router = APIRouter()

# ----------------------------------------------
class FriendRequestIn(BaseModel):
    receiverChildUserName: str
    
class FriendRequestOut(BaseModel):
    requestID: int
    requestStatus: str
    requestTimeStamp: datetime
    senderUserName: str
    senderFirstName: str
    senderLastName: str
    senderProfileIcon: Optional[str] = None

# ----------------------- login -----------------------

@router.post("/child/login", response_model=child_module.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """Authenticate and get access token"""
    user = child_module.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = child_module.createAccessToken(
        data={"sub": form_data.username},
        expires_delta=timedelta(minutes=child_module.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# -------------------------- get name ------------------------------------
@router.get("/child/name")
def get_child_name(
    current_user: dict = Depends(child_module.getCurrentUser)
):
    """Get child's first and last name"""
    child_name = child_module.get_child_name(current_user['childUserName'])
    if not child_name:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Child not found"
        )
    return child_name
# -------------------------- get info ------------------------------------
@router.get("/child/info")
def get_child_info(
    current_user: dict = Depends(child_module.getCurrentUser)
):
    """Get complete child information"""
    child_info = child_module.get_child(current_user['childUserName'])
    if not child_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Child not found"
        )
    return child_info
# -------------------------- get settings ------------------------------------
@router.put("/child/settings")
def update_child_settings(
    settings: dict,
    current_user: dict = Depends(child_module.getCurrentUser)
):
    """Update child profile settings"""
    return child_module.update_settings(current_user['childUserName'], settings)


#-------------------------------------------------------------------------
# ---------------------------- friendship --------------------------------
#-------------------------------------------------------------------------

#----------------------- search friends ------------------------
@router.get("/child/search")
def search_users(
    q: str = Query(..., description="Search query for child usernames"),
    current_user: dict = Depends(child_module.getCurrentUser)
):
    """Search for other children to add as friends"""
    return child_module.search_users(q, current_user['childUserName'])

    
# -------------------------- send friendship ------------------------------------
@router.post("/child/friend/request", status_code=status.HTTP_201_CREATED)
def send_friend_request(
    request: FriendRequestIn,
    current_user: dict = Depends(child_module.getCurrentUser)
):
    """Send a friend request to another child"""
    return child_module.create_friend_request(
        sender=current_user['childUserName'],
        receiver=request.receiverChildUserName
    )

# -------------------------- get friendship request ------------------------------------

@router.get("/child/friend/request")
def view_friend_requests(
    current_user: dict = Depends(child_module.getCurrentUser)
):
    try:
        child_username = current_user['childUserName']
        requests = child_module.get_friend_requests(child_username)
        
        if not requests:
            return {
                "message": "No friend requests found",
                "data": []
            }
            
        return {
            "message": "Friend requests retrieved successfully",
            "data": requests
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------- accept request upon request ID provided ------------------------------------

@router.post("/child/friend/accept/{request_id}")
def accept_friend_request(
    request_id: int,
    current_user: dict = Depends(child_module.getCurrentUser)
):
    """Accept a pending friend request"""
    return child_module.accept_friend_request(
        request_id=request_id,
        receiver=current_user['childUserName']
    )
# -------------------------- reject request upon request ID provided ------------------------------------

@router.post("/child/friend/reject/{request_id}")
def reject_friend_request(
    request_id: int,
    current_user: dict = Depends(child_module.getCurrentUser)
):
    """Reject a pending friend request"""
    return child_module.reject_friend_request(
        request_id=request_id,
        receiver=current_user['childUserName']
    )

# -------------------------- get friends ------------------------------------

@router.get("/child/friends")
def get_friends(
    current_user: dict = Depends(child_module.getCurrentUser)
):
    """Get list of all friends"""
    return child_module.get_friends(current_user['childUserName'])

# -------------------------- block friends ------------------------------------

@router.post("/child/friend/block/{friendUserName}")
def block_friend(
    friendUserName: str,
    current_user: dict = Depends(child_module.getCurrentUser)
):
    """Block an existing friend"""
    return child_module.block_friend(
        childUserName=current_user['childUserName'],
        friendUserName=friendUserName
    )

# -------------------------- logout ------------------------------------

@router.post("/child/logout")
def child_logout():
    """Logout the current user (token invalidation handled client-side)"""
    return {
        "message": "Child logged out successfully",
    }
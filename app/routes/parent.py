from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from app.modules import parent as parent_module

router = APIRouter()


#-------------------------------  signup  --------------------------------------
@router.post("/parent/signup")
def add_parent(parent_data: parent_module.Parent):
    return parent_module.create_parent(parent_data)


#--------------------------------  login  ------------------------------------
@router.post("/parent/login", response_model=parent_module.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = parent_module.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=parent_module.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = parent_module.createAccessToken(
        data={"sub": form_data.username}, expiresDelta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

#--------------------- get the parent's name ---------------------------
@router.get("/parent/name")
def get_parent_name(current_user: dict = Depends(parent_module.getCurrentUser)):
    parentUserName = current_user['parentUserName']
    parent_name = parent_module.get_parent_name(parentUserName)
    
    if not parent_name:
        return {
            "status": "error",
            "message": "Parent not found",
            "data": None
        }
    
    return {
        "message": "parent name retrieved successfully",
        "data": parent_name
    }

#----------------- get the children of the parent -----------------------
@router.get("/parent/children")
def get_all_children(current_user: dict = Depends(parent_module.getCurrentUser)):
    parentUserName = current_user['parentUserName']
    children = parent_module.get_children_of_parent(parentUserName)
    
    return {
        "message": "children retrieved successfully",
        "data": children
    }


#---------------------- delete parent account --------------------------
@router.delete("/parent/delete")
def delete_parent_account(current_user: dict = Depends(parent_module.getCurrentUser)):
    parentUserName = current_user['parentUserName']
    result = parent_module.delete_parent_account(parentUserName)
    
    return {
        "message": "parent account and associated children deleted successfully",
        "data": result
    }


#----------------------- update parent settings -------------------------
@router.put("/parent/settings")
def update_parent_settings(
    settings: dict, 
    current_user: dict = Depends(parent_module.getCurrentUser)
):
    parentUserName = current_user['parentUserName']
    result = parent_module.update_parent_settings(parentUserName, settings)
    
    return {
        "message": "parent settings updated successfully",
        "data": result
    }


#------------- setting time limits for parent's child  ------------------
@router.put("/parent/children/{childUserName}/time-control")
def set_child_time_control(
    childUserName: str,
    time_control: int,
    current_user: dict = Depends(parent_module.getCurrentUser)
):
    parentUserName = current_user['parentUserName']
    result = parent_module.set_child_time_control(parentUserName, childUserName, time_control)
    
    return {
        "message": "child time control updated successfully",
        "data": result
    }


#-------------------- get the notifications --------------------------
@router.get("/parent/notifications")
def get_notifications(current_user: dict = Depends(parent_module.getCurrentUser)):
    parentUserName = current_user['parentUserName']
    notifications = parent_module.get_notifications(parentUserName)
    
    return {
        "message": "notifications retrieved successfully",
        "data": notifications
    }

#-------------------- logging out --------------------------

    
@router.post("/parent/logout")
def parent_logout():
    return {
        "status": "success",
        "message": "Parent logged out successfully.",
        "data": None
    }
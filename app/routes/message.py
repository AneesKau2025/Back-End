from fastapi import APIRouter
from app.modules import message as message_module  

router = APIRouter()

@router.get("/messages/{user_id}")
def read_messages(user_id: str):
    return message_module.get_messages(user_id)

@router.post("/messages/")
def create_message(message_data: message_module.MessageSchema):
    return message_module.send_message(message_data)

from fastapi import APIRouter
from app.modules import message as message_module
from pydantic import BaseModel

router = APIRouter()

# Dummy input model 
class TestMessageInput(BaseModel):
    senderChildUserName: str
    receiverChildUserName: str
    content: str
    risk_level: int  # manually injected to simulate AI output

@router.post("/message/test")
def process_message(data: TestMessageInput):
    message = message_module.MessageInput(
        senderChildUserName=data.senderChildUserName,
        receiverChildUserName=data.receiverChildUserName,
        content=data.content,
        riskID=data.risk_level
    )
    return message_module.process_message(message)


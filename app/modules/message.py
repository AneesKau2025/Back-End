from pydantic import BaseModel
import sqlalchemy as sa
from app.database import get_connection 


class MessageSchema(BaseModel):
    senderChildUserName: str
    receiverChildUserName: str
    content: str
    notificationFlag: bool = False
    RiskID: int = 0

def send_message(message_data: MessageSchema):
    """
    Inserts a new message into the database.
    """
    with get_connection() as conn:
        insert_query = sa.text("""
            INSERT INTO Message (senderChildUserName, receiverChildUserName, content, notificationFlag, RiskID)
            VALUES (:sender, :receiver, :content, :notificationFlag, :RiskID)
        """)
        conn.execute(insert_query, {
            "sender": message_data.senderChildUserName,
            "receiver": message_data.receiverChildUserName,
            "content": message_data.content,
            "notificationFlag": message_data.notificationFlag,
            "RiskID": message_data.RiskID
        })
        
        conn.commit()

    return {"message": "Message sent successfully!", "data": message_data.dict()}

def get_messages(user_id: str):
    """
    Retrieves all messages received by the given user and returns them as a list of dictionaries.
    """
    with get_connection() as conn:
        select_query = sa.text("SELECT * FROM Message WHERE receiverChildUserName = :receiver")
        result = conn.execute(select_query, {"receiver": user_id}).mappings().fetchall()  
    
    return [dict(row) for row in result] if result else []  

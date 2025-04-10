from pydantic import BaseModel
import sqlalchemy as sa
from sqlalchemy.sql import func
from datetime import datetime
from app.database import get_connection
from fastapi import HTTPException

class MessageInput(BaseModel):
    senderChildUserName: str
    receiverChildUserName: str
    content: str
    riskID: int

RISK_TYPES = {
    1: "Inappropriate Language",
    2: "Sexual Assault",
    3: "Drugs"
}

def process_message(msg: MessageInput):
    if msg.riskID == 0:
        print("Message is safe.")
        return {"message": "Forward to Firebase."}

    risk_type = RISK_TYPES.get(msg.riskID)
    if not risk_type:
        raise HTTPException(status_code=400, detail="Invalid riskID")

    with get_connection() as conn:
        insert_msg_query = sa.text("""
            INSERT INTO Notification (senderChildUserName, receiverChildUserName, content, RiskID, notificationFlag)
            VALUES (:sender, :receiver, :content, :riskID, 1)
        """)

        conn.execute(insert_msg_query, {
            "sender": msg.senderChildUserName,
            "receiver": msg.receiverChildUserName,
            "content": msg.content,
            "riskID": msg.riskID
        })
        conn.commit()

        message_id = conn.execute(sa.text("SELECT LAST_INSERT_ID() AS id")).scalar()

    create_notification(message_id, msg.receiverChildUserName, risk_type)
    return {"message": f"Risky message stored. Notification for '{risk_type}' created."}

def create_notification(message_id: int, receiverChildUserName: str, risk_type: str):
    with get_connection() as conn:
        parent_query = sa.text("""
            SELECT parentUserName FROM Child WHERE childUserName = :receiver
        """)
        result = conn.execute(parent_query, {"receiver": receiverChildUserName}).mappings().first()

        if not result:
            raise HTTPException(status_code=404, detail="Receiver child not found")

        parent_username = result["parentUserName"]
        print(f"🔔 Notification for {parent_username} regarding message {message_id} with risk: {risk_type}")
        return {"status": "Notification created (log only)"}

def get_notifications(parentUserName: str):
    with get_connection() as conn:
        query = sa.text("""
            SELECT 
                n.messageID,
                n.content,
                n.timeStamp,
                n.senderChildUserName AS sender,
                n.receiverChildUserName AS receiver,
                c.firstName AS receiverFirstName,
                c.lastName AS receiverLastName,
                n.riskID
            FROM 
                Notification n
            JOIN 
                Child c ON n.receiverChildUserName = c.childUserName
            WHERE 
                c.parentUserName = :parentUserName
                AND n.riskID > 0
            ORDER BY n.timeStamp DESC
        """)
        results = conn.execute(query, {"parentUserName": parentUserName}).mappings().fetchall()

    return [dict(row) for row in results] if results else []
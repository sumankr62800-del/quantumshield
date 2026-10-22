from datetime import datetime

from pydantic import BaseModel


class MessageCreate(BaseModel):
    receiver_id: int
    content: str


class MessageResponse(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    content: str
    created_at: datetime


class EncryptedMessageResponse(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    ciphertext: str
    nonce: str | None = None
    sender_kem_ciphertext: str | None = None
    receiver_kem_ciphertext: str | None = None
    created_at: datetime
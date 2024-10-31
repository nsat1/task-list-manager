from pydantic import BaseModel


class CreateTask(BaseModel):
    title: str
    description: str
    status: bool
    user_id: int

class CreateUser(BaseModel):
    id: int
    username: str
    password_hash: str

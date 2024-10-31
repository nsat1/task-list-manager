from pydantic import BaseModel


class CreateTask(BaseModel):
    title: str
    description: str
    status: bool
    user_id: int | None = None

class CreateUser(BaseModel):
    username: str
    password_hash: str

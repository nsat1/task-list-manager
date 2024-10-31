from pydantic import BaseModel


class CreateTask(BaseModel):
    name: str
    description: str
    status: str
    user_id: int


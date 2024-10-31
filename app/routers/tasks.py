from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException

from sqlalchemy.orm import Session
from sqlalchemy import insert, select

from app.backend.db_depends import get_db
from app.schemas.schemas import CreateTask
from app.models.tasks import Task
from app.models.users import User


router = APIRouter(prefix='/tasks', tags=['tasks'])

@router.get('/', status_code=status.HTTP_200_OK)
async def get_all_tasks(db: Annotated[Session, Depends(get_db)]):
    tasks = db.scalars(select(Task).where(Task.status.is_(True))).all()

    return tasks

@router.post('/', status_code=status.HTTP_201_CREATED)
async def create_task(db: Annotated[Session, Depends(get_db)], create_task: CreateTask):
    db.execute(insert(Task).values(
        title=create_task.title,
        description=create_task.description,
        status=create_task.status))
    db.commit()

    return {
        'status_code': status.HTTP_201_CREATED,
        'transaction': 'Task created successfully'
    }

@router.put('/{task_id}')
async def update_task(task_id: int):
    pass

@router.delete('/{task_id}')
async def delete_task(task_id: int):
    pass

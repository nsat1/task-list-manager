from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException

from sqlalchemy.orm import Session
from sqlalchemy import insert, select, update, delete

from app.backend.db_depends import get_db
from app.schemas.schemas import CreateTask
from app.models.tasks import Task


router = APIRouter(prefix='/tasks', tags=['tasks'])

@router.get('/', status_code=status.HTTP_200_OK)
async def get_all_tasks(db: Annotated[Session, Depends(get_db)]):
    tasks = db.scalars(select(Task).where(Task.status == True)).all()

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
async def update_task(db: Annotated[Session, Depends(get_db)], task_id: int, update_task: CreateTask):
    task = db.scalar(select(Task).where(Task.id == task_id))

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='Task not found'
        )

    db.execute(update(Task).where(Task.id == task_id).values(
        title=update_task.title,
        description=update_task.description,
        status=update_task.status))

    db.commit()

    return {
        'status_code': status.HTTP_200_OK,
        'transaction': 'Task update is successful'
    }

@router.delete('/{task_id}')
async def delete_task(db: Annotated[Session, Depends(get_db)], task_id: int):
    task = db.scalar(select(Task).where(Task.id == task_id))

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='Task not found'
        )

    db.execute(delete(Task).where(Task.id == task_id))

    db.commit()

    return {'message': 'Task deleted'}

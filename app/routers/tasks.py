from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException

from sqlalchemy import insert, select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.backend.db_depends import get_db
from app.schemas.schemas import CreateTask
from app.models.tasks import Task
from .auth import get_current_user


router = APIRouter(prefix='/tasks', tags=['tasks'])

@router.get('/', status_code=status.HTTP_200_OK)
async def get_all_tasks(
        db: Annotated[AsyncSession, Depends(get_db)],
        current_user: Annotated[dict, Depends(get_current_user)]):

    tasks = await db.scalars(select(Task).where(Task.status == True))

    return tasks.all()

@router.post('/', status_code=status.HTTP_201_CREATED)
async def create_task(
        db: Annotated[AsyncSession, Depends(get_db)],
        current_user: Annotated[dict, Depends(get_current_user)],
        create_task: CreateTask):

    await db.execute(insert(Task).values(
        title=create_task.title,
        description=create_task.description,
        status=create_task.status))

    await db.commit()

    return {
        'status_code': status.HTTP_201_CREATED,
        'transaction': 'Task created successfully'
    }

@router.put('/{task_id}')
async def update_task(
        db: Annotated[AsyncSession, Depends(get_db)],
        current_user: Annotated[dict, Depends(get_current_user)],
        task_id: int, update_task: CreateTask):

    task = await db.scalar(select(Task).where(Task.id == task_id))

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='Task not found'
        )

    await db.execute(update(Task).where(Task.id == task_id).values(
        title=update_task.title,
        description=update_task.description,
        status=update_task.status))

    await db.commit()

    return {
        'status_code': status.HTTP_200_OK,
        'transaction': 'Task update is successful'
    }

@router.delete('/{task_id}')
async def delete_task(
        db: Annotated[AsyncSession, Depends(get_db)],
        current_user: Annotated[dict, Depends(get_current_user)],
        task_id: int):

    task = await db.scalar(select(Task).where(Task.id == task_id))

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='Task not found'
        )

    await db.execute(delete(Task).where(Task.id == task_id))

    await db.commit()

    return {'message': 'Task deleted'}

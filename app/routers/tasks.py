from fastapi import APIRouter


router = APIRouter(prefix='/tasks', tags=['tasks'])

@router.get('/')
async def get_all_tasks():
    pass

@router.post('/')
async def create_task():
    pass

@router.put('/{task_id}')
async def update_task(task_id: int):
    pass

@router.delete('/{task_id}')
async def delete_task(task_id: int):
    pass

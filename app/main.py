from fastapi import FastAPI

from app.routers import tasks, auth


app = FastAPI()

app.include_router(tasks.router)
app.include_router(auth.router)

# task-list-manager

# How to Use
## Running in Docker

- configure environment variables in `.env` file

- start services
```commandline
docker compose up -d --build
```
- make migrations
```commandline
docker-compose exec app alembic upgrade head
```

## Running on Local Machine
- install dependencies 
```commandline
pip install -r requirements.txt
```
- configure environment variables in `.env` file
- make migrations
```commandline
alembic upgrade head
```
- start 
```commandline
uvicorn app.main:app --reload
```
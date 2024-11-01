FROM python:3.13.0

WORKDIR /usr/src

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
ADD alembic.ini .

ENV PYTHONPATH /usr/src
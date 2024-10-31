from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship

from app.backend.db import Base


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

    tasks = relationship('Task', back_populates='user')

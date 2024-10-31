from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship

from app.backend.db import Base


class Task(Base):
    __tablename__ = 'tasks'

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, unique=True, nullable=False)
    description = Column(String)
    status = Column(Boolean, default=True)
    user_id = Column(Integer, ForeignKey('users.id'))

    user = relationship('User', back_populates='tasks')

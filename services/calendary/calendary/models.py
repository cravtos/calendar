import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, BigInteger
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    register_time = Column(
        DateTime, default=datetime.datetime.now, nullable=False
    )


class Event(Base):
    __tablename__ = "event"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    start = Column(BigInteger, nullable=False)
    end = Column(BigInteger, nullable=False)
    private = Column(Boolean, nullable=False)
    name = Column(String, nullable=False)
    details = Column(String, nullable=False)

event_index = Index('event_idx', Event.private, Event.user_id, Event.start, Event.end)

class EventShare(Base):
    __tablename__ = "shares"
    event_id = Column(
        Integer, ForeignKey("event.id", ondelete="CASCADE"), primary_key=True
    )
    username = Column(
        String, ForeignKey("user.username", ondelete="CASCADE"), primary_key=True
    )

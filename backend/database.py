import os
from sqlalchemy import create_engine, Column, Integer, Text, JSON, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
print("DATABASE_URL =", os.getenv("DATABASE_URL"))

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Text)
    event_type = Column(Text)
    data = Column(JSON)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def save_event(agent_id: str, event_type: str, data: dict):
    session = SessionLocal()
    try:
        event = Event(
            agent_id=agent_id,
            event_type=event_type,
            data=data
        )
        session.add(event)
        session.commit()
    except Exception as e:
        session.rollback()
        print("[DB ERROR]", e)
    finally:
        session.close()
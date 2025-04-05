from sqlmodel import SQLModel, create_engine, Session
from shared.config import settings

# Create a database URL
DATABASE_URL = f"postgresql://{settings.DB_USER}:{settings.DB_PASSWORD}@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"

# Create an engine
engine = create_engine(DATABASE_URL, echo=settings.DB_ECHO)


# Function to create all tables
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


# Session dependency
def get_session():
    with Session(engine) as session:
        yield session

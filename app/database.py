from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# SQLite database URL
SQLALCHEMY_DATABASE_URL = "sqlite:///./sample_app.db"

# Create engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# Create SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create Base class
Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Profile(Base):
    __tablename__ = "profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    full_name = Column(String)
    phone = Column(String)
    address = Column(String)
    ssn = Column(String)  # For demo purposes - would be encrypted in real app
    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables
def create_tables():
    Base.metadata.create_all(bind=engine)

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize database with sample data
def init_db():
    create_tables()
    db = SessionLocal()
    
    # Check if data already exists
    if db.query(User).first():
        return
    
    # Create sample users
    users = [
        User(
            username="admin",
            email="admin@example.com",
            hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.i8e",  # "admin123"
            is_admin=True
        ),
        User(
            username="user1",
            email="user1@example.com",
            hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.i8e",  # "user123"
            is_admin=False
        ),
        User(
            username="user2",
            email="user2@example.com",
            hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.i8e",  # "user123"
            is_admin=False
        )
    ]
    
    profiles = [
        Profile(
            user_id=1,
            full_name="Admin User",
            phone="555-0100",
            address="123 Admin St, City, State",
            ssn="123-45-6789"
        ),
        Profile(
            user_id=2,
            full_name="John Doe",
            phone="555-0101",
            address="456 User Ave, City, State",
            ssn="987-65-4321"
        ),
        Profile(
            user_id=3,
            full_name="Jane Smith",
            phone="555-0102",
            address="789 User Blvd, City, State",
            ssn="456-78-9012"
        )
    ]
    
    db.add_all(users)
    db.add_all(profiles)
    db.commit()
    db.close() 
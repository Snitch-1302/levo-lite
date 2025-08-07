from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

# User Models
class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    is_admin: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

# Profile Models
class ProfileBase(BaseModel):
    full_name: str
    phone: str
    address: str
    ssn: str

class ProfileCreate(ProfileBase):
    user_id: int

class Profile(ProfileBase):
    id: int
    user_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# Authentication Models
class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: User

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Search Models
class SearchRequest(BaseModel):
    query: str
    limit: Optional[int] = 10
    offset: Optional[int] = 0

class SearchResponse(BaseModel):
    results: List[User]
    total: int
    limit: int
    offset: int

# API Response Models
class Message(BaseModel):
    message: str

class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None 
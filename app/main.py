from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional
import json

from app.database import get_db, User, Profile, init_db
from app.models import (
    User as UserModel, 
    Profile as ProfileModel,
    LoginRequest, 
    LoginResponse, 
    SearchRequest, 
    SearchResponse,
    Message
)
from app.auth import (
    authenticate_user, 
    create_access_token, 
    get_current_user, 
    get_current_admin_user,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from datetime import timedelta
from app.dashboard import router as dashboard_router

# Initialize FastAPI app
app = FastAPI(
    title="LevoLite Sample API",
    description="Sample API for demonstrating API security analysis",
    version="1.0.0"
)

# Add CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include dashboard router
app.include_router(dashboard_router, prefix="/api", tags=["dashboard"])

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    init_db()

# Health check endpoint
@app.get("/health", response_model=Message)
async def health_check():
    return {"message": "API is running"}

# Authentication endpoint
@app.post("/login", response_model=LoginResponse)
async def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, login_data.username, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserModel.from_orm(user)
    }

# User endpoints
@app.get("/users/{user_id}", response_model=UserModel)
async def get_user(user_id: int, db: Session = Depends(get_db)):
    """Get user by ID - potential IDOR vulnerability"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserModel.from_orm(user)

@app.get("/users", response_model=List[UserModel])
async def get_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Get all users with pagination"""
    users = db.query(User).offset(skip).limit(limit).all()
    return [UserModel.from_orm(user) for user in users]

@app.post("/users", response_model=UserModel)
async def create_user(user_data: dict, db: Session = Depends(get_db)):
    """Create a new user"""
    # This endpoint doesn't require authentication - potential security issue
    user = User(
        username=user_data["username"],
        email=user_data["email"],
        hashed_password=user_data["password"],  # Should be hashed
        is_admin=user_data.get("is_admin", False)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserModel.from_orm(user)

# Profile endpoints (contain sensitive data)
@app.get("/profile", response_model=ProfileModel)
async def get_my_profile(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current user's profile"""
    profile = db.query(Profile).filter(Profile.user_id == current_user.id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return ProfileModel.from_orm(profile)

@app.get("/profiles/{user_id}", response_model=ProfileModel)
async def get_user_profile(user_id: int, db: Session = Depends(get_db)):
    """Get profile by user ID - potential IDOR vulnerability"""
    profile = db.query(Profile).filter(Profile.user_id == user_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return ProfileModel.from_orm(profile)

@app.put("/profile", response_model=ProfileModel)
async def update_profile(
    profile_data: dict, 
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """Update current user's profile"""
    profile = db.query(Profile).filter(Profile.user_id == current_user.id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    for key, value in profile_data.items():
        setattr(profile, key, value)
    
    db.commit()
    db.refresh(profile)
    return ProfileModel.from_orm(profile)

# Admin endpoints
@app.get("/admin/users", response_model=List[UserModel])
async def admin_get_users(current_user: User = Depends(get_current_admin_user), db: Session = Depends(get_db)):
    """Admin endpoint to get all users"""
    users = db.query(User).all()
    return [UserModel.from_orm(user) for user in users]

@app.delete("/admin/users/{user_id}", response_model=Message)
async def admin_delete_user(
    user_id: int, 
    current_user: User = Depends(get_current_admin_user), 
    db: Session = Depends(get_db)
):
    """Admin endpoint to delete user"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user)
    db.commit()
    return {"message": f"User {user_id} deleted successfully"}

# Search endpoint
@app.get("/search", response_model=SearchResponse)
async def search_users(
    q: str = Query(..., description="Search query"),
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Search users by username or email"""
    query = f"%{q}%"
    users = db.query(User).filter(
        (User.username.like(query)) | (User.email.like(query))
    ).offset(offset).limit(limit).all()
    
    total = db.query(User).filter(
        (User.username.like(query)) | (User.email.like(query))
    ).count()
    
    return SearchResponse(
        results=[UserModel.from_orm(user) for user in users],
        total=total,
        limit=limit,
        offset=offset
    )

# Unprotected sensitive endpoint (security issue)
@app.get("/internal/users", response_model=List[UserModel])
async def internal_get_users(db: Session = Depends(get_db)):
    """Internal endpoint that should be protected but isn't"""
    users = db.query(User).all()
    return [UserModel.from_orm(user) for user in users]

# API info endpoint
@app.get("/api/info")
async def api_info():
    """Get API information"""
    return {
        "name": "LevoLite Sample API",
        "version": "1.0.0",
        "description": "Sample API for security analysis",
        "endpoints": [
            "/login",
            "/users/{user_id}",
            "/users",
            "/profile",
            "/profiles/{user_id}",
            "/admin/users",
            "/search",
            "/internal/users"
        ]
    }

# Debug endpoint (should be removed in production)
@app.get("/debug/users")
async def debug_users(db: Session = Depends(get_db)):
    """Debug endpoint to see all user data"""
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username, "email": u.email, "is_admin": u.is_admin} for u in users]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 
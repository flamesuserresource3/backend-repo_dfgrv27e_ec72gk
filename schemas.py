"""
Database Schemas for Campus Connect

Each Pydantic model corresponds to a MongoDB collection.
Collection name is the lowercase class name (e.g., User -> "user").
"""
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., description="Hashed password")
    college: Optional[str] = Field(None, description="College/University name")
    year: Optional[str] = Field(None, description="Academic year (e.g., Freshman, 3rd Year)")
    skills: List[str] = Field(default_factory=list, description="List of skills")
    interests: List[str] = Field(default_factory=list, description="List of interests")
    connections: List[str] = Field(default_factory=list, description="Connected user IDs as strings")

class Event(BaseModel):
    title: str = Field(..., description="Event title")
    date: str = Field(..., description="ISO date string")
    description: Optional[str] = Field(None, description="Event description")
    link: Optional[str] = Field(None, description="External link for event")

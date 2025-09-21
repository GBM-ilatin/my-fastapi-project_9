```python
from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field
from pydantic import EmailStr, validator
import re


class UserBase(SQLModel):
    """Base user model with common fields."""
    
    email: EmailStr = Field(unique=True, index=True, description="User email address")
    username: str = Field(min_length=3, max_length=50, unique=True, index=True, description="Unique username")
    first_name: str = Field(min_length=1, max_length=100, description="User's first name")
    last_name: str = Field(min_length=1, max_length=100, description="User's last name")
    is_active: bool = Field(default=True, description="Whether the user account is active")
    is_verified: bool = Field(default=False, description="Whether the user email is verified")

    @validator('username')
    def validate_username(cls, v):
        """Validate username contains only alphanumeric characters and underscores."""
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username must contain only letters, numbers, and underscores')
        return v

    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        """Validate names contain only letters, spaces, hyphens, and apostrophes."""
        if not re.match(r"^[a-zA-Z\s\-']+$", v):
            raise ValueError('Names must contain only letters, spaces, hyphens, and apostrophes')
        return v.strip().title()


class User(UserBase, table=True):
    """User database model."""
    
    __tablename__ = "users"
    
    id: Optional[int] = Field(default=None, primary_key=True, description="User ID")
    hashed_password: str = Field(description="Hashed password")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Account creation timestamp")
    updated_at: Optional[datetime] = Field(default=None, description="Last update timestamp")
    last_login: Optional[datetime] = Field(default=None, description="Last login timestamp")


class UserCreate(UserBase):
    """Model for creating a new user."""
    
    password: str = Field(min_length=8, max_length=128, description="User password")
    confirm_password: str = Field(description="Password confirmation")

    @validator('password')
    def validate_password(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        """Validate that password and confirm_password match."""
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v


class UserUpdate(SQLModel):
    """Model for updating user information."""
    
    email: Optional[EmailStr] = Field(default=None, description="User email address")
    username: Optional[str] = Field(default=None, min_length=3, max_length=50, description="Unique username")
    first_name: Optional[str] = Field(default=None, min_length=1, max_length=100, description="User's first name")
    last_name: Optional[str] = Field(default=None, min_length=1, max_length=100, description="User's last name")
    is_active: Optional[bool] = Field(default=None, description="Whether the user account is active")
    is_verified: Optional[bool] = Field(default=None, description="Whether the user email is verified")

    @validator('username')
    def validate_username(cls, v):
        """Validate username contains only alphanumeric characters and underscores."""
        if v is not None and not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username must contain only letters, numbers, and underscores')
        return v

    @validator('first_name', 'last_name')
    def validate_names(cls, v):
        """Validate names contain only letters, spaces, hyphens, and apostrophes."""
        if v is not None:
            if not re.match(r"^[a-zA-Z\s\-']+$", v):
                raise ValueError('Names must contain only letters, spaces, hyphens, and apostrophes')
            return v.strip().title()
        return v


class UserRead(UserBase):
    """Model for reading user data (public view)."""
    
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None


class UserInDB(UserRead):
    """Model for user data stored in database (internal use)."""
    
    hashed_password: str


class UserPasswordUpdate(SQLModel):
    """Model for updating user password."""
    
    current_password: str = Field(description="Current password")
    new_password: str = Field(min_length=8, max_length=128, description="New password")
    confirm_new_password: str = Field(description="New password confirmation")

    @validator('new_password')
    def validate_new_password(cls, v):
        """Validate new password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        return v

    @validator('confirm_new_password')
    def passwords_match(cls, v, values):
        """Validate that new_password and confirm_new_password match."""
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('New passwords do not match')
        return v
```
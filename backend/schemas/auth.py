# backend/schemas/auth.py
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, constr


class RegisterIn(BaseModel):
    email: constr(strip_whitespace=True, min_length=3, max_length=50)
    username: constr(strip_whitespace=True, min_length=3, max_length=50)
    password: constr(min_length=8, max_length=128)


class RegisterOut(BaseModel):
    id: int
    email: EmailStr
    username: str
    created_at: datetime


class LoginIn(BaseModel):
    email: constr(strip_whitespace=True, min_length=3, max_length=50)
    password: constr(min_length=8, max_length=128)


class MeOut(BaseModel):
    id: int
    email: EmailStr
    username: str
    is_admin: bool
    is_active: bool 
    created_at: datetime


class ResendVerificationIn(BaseModel):
    email: Optional[str] = None


class ForgotPasswordIn(BaseModel):
    email: str


class ResetPasswordIn(BaseModel):
    token: constr(strip_whitespace=True, min_length=5, max_length=512)
    password: constr(min_length=8, max_length=128)


class ResetPasswordOut(BaseModel):
    ok: bool

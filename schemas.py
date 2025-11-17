from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field

from models import UserRole, PostType, Difficulty


# ---------- Auth & Core ----------

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: Optional[str] = None


class TokenData(BaseModel):
    user_id: Optional[int] = None


class Message(BaseModel):
    detail: str


class RegisterInit(BaseModel):
    email: EmailStr
    full_name: str
    username: str = Field(
        min_length=3,
        max_length=32,
        pattern=r"^[a-zA-Z0-9_]+$",
    )
    password: str = Field(min_length=8)



class RegisterVerify(BaseModel):
    email: EmailStr
    otp: str


class ForgotPasswordInit(BaseModel):
    email: EmailStr


class ForgotPasswordVerify(BaseModel):
    email: EmailStr
    otp: str
    new_password: str = Field(min_length=8)


# ---------- User ----------

class UserBase(BaseModel):
    email: EmailStr
    username: Optional[str] = None
    full_name: Optional[str] = None


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str = Field(min_length=8)
    username: Optional[str] = None


class UserProfileUpdate(BaseModel):
    username: Optional[str] = Field(
        default=None,
        min_length=3,
        max_length=32,
        pattern=r"^[a-zA-Z0-9_]+$",
    )
    full_name: Optional[str] = None
    bio: Optional[str] = None
    location: Optional[str] = None
    status_text: Optional[str] = None
    security_interests: Optional[str] = None  # comma-separated or JSON
    ctf_team: Optional[str] = None
    ctftime_url: Optional[str] = None
    github_url: Optional[str] = None
    linkedin_url: Optional[str] = None
    twitter_url: Optional[str] = None
    website_url: Optional[str] = None
    # you can keep this if you still want manual URL setting
    avatar_url: Optional[str] = None


class UserOut(BaseModel):
    id: int
    email: EmailStr
    username: Optional[str] = None
    full_name: Optional[str] = None
    role: UserRole
    is_active: bool
    is_email_verified: bool
    reputation: int
    bio: Optional[str]
    location: Optional[str]
    status_text: Optional[str]
    security_interests: Optional[str]
    ctf_team: Optional[str]
    ctftime_url: Optional[str]
    github_url: Optional[str]
    linkedin_url: Optional[str]
    twitter_url: Optional[str]
    website_url: Optional[str]
    avatar_url: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class UserPublic(BaseModel):
    id: int
    username: Optional[str]
    full_name: Optional[str]
    reputation: int
    bio: Optional[str]
    status_text: Optional[str]
    avatar_url: Optional[str]

    class Config:
        from_attributes = True


# ---------- Posts / Tags / Comments ----------

class TagBase(BaseModel):
    name: str
    slug: str
    description: Optional[str] = None


class TagOut(TagBase):
    id: int

    class Config:
        from_attributes = True


class PostBase(BaseModel):
    title: str
    body: str
    post_type: PostType
    is_ctf: bool = False
    difficulty: Optional[Difficulty] = None
    thumbnail_url: Optional[str] = None
    group_id: Optional[int] = None
    tags: List[str] = []  # tag slugs


class ProjectFields(BaseModel):
    repo_url: Optional[str] = None
    tech_stack: Optional[str] = None
    project_category: Optional[str] = None
    license: Optional[str] = None
    looking_for_contributors: bool = False


class PostCreate(PostBase, ProjectFields):
    pass


class PostUpdate(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    is_ctf: Optional[bool] = None
    difficulty: Optional[Difficulty] = None
    thumbnail_url: Optional[str] = None
    tags: Optional[List[str]] = None
    repo_url: Optional[str] = None
    tech_stack: Optional[str] = None
    project_category: Optional[str] = None
    license: Optional[str] = None
    looking_for_contributors: Optional[bool] = None


class PostOut(BaseModel):
    id: int
    title: str
    body: str
    post_type: PostType
    is_ctf: bool
    difficulty: Optional[Difficulty]
    thumbnail_url: Optional[str]
    group_id: Optional[int]
    author: UserPublic
    tags: List[TagOut]
    view_count: int
    repo_url: Optional[str]
    tech_stack: Optional[str]
    project_category: Optional[str]
    license: Optional[str]
    looking_for_contributors: bool
    created_at: datetime
    updated_at: datetime

    score: int                      # total score = sum of all votes
    my_vote: Optional[int] = None 

    class Config:
        from_attributes = True


class CommentCreate(BaseModel):
    body: str
    parent_id: Optional[int] = None


class CommentOut(BaseModel):
    id: int
    body: str
    author: UserPublic
    parent_id: Optional[int]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class VoteValue(int, Enum):
    up = 1
    down = -1


class VoteIn(BaseModel):
    value: VoteValue


# ---------- Admin ----------

class AdminUserUpdate(BaseModel):
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None



class PostSummary(BaseModel):
    id: int
    title: str
    post_type: PostType
    thumbnail_url: Optional[str]
    view_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class UserProfileDetail(BaseModel):
    user: UserPublic
    recent_posts: List[PostSummary]
    followers_count: int
    following_count: int
    bookmarks_count: int

    class Config:
        from_attributes = True
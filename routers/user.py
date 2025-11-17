from typing import Optional
import os
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from auth import get_current_user, get_current_user_optional
from database import get_db
from models import User, Post, Follow, Bookmark
from schemas import UserOut, UserPublic, UserProfileUpdate, UserProfileDetail, PostSummary
from config import settings


router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    """
    Return the currently authenticated user (private view).
    Used by the frontend to show logged-in user info.
    """
    return current_user

@router.put("/me", response_model=UserOut)
def update_me(
    payload: UserProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Update the current user's own profile (bio, links, etc.).
    """
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(current_user, field, value)

    db.commit()
    db.refresh(current_user)
    return current_user


@router.get("/{username}", response_model=UserPublic)
def get_user_public(
    username: str,
    db: Session = Depends(get_db),
):
    """
    PUBLIC profile lookup by username only.

    Frontend calls:
      GET /users/{username}
    Example:
      /users/aathilducky
    """
    user: Optional[User] = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user



@router.put("/me", response_model=UserOut)
def update_me(
    payload: UserProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Update the current user's own profile (bio, links, etc.).
    """

    data = payload.model_dump(exclude_unset=True)

    # Handle username separately for uniqueness
    new_username = data.get("username")
    if new_username and new_username != current_user.username:
        existing = (
            db.query(User)
            .filter(User.username == new_username)
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=400,
                detail="Username already taken",
            )
        current_user.username = new_username

    # Update the rest of the fields
    updatable_fields = {
        "full_name",
        "bio",
        "location",
        "status_text",
        "security_interests",
        "ctf_team",
        "ctftime_url",
        "github_url",
        "linkedin_url",
        "twitter_url",
        "website_url",
        "avatar_url",  # optional – or remove if only avatar upload endpoint should control this
    }

    for field, value in data.items():
        if field in updatable_fields and value is not None:
            setattr(current_user, field, value)

    db.commit()
    db.refresh(current_user)
    return current_user


@router.post("/me/avatar", response_model=UserOut)
async def upload_avatar(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Upload / update the current user's avatar.
    Saves file to MEDIA_ROOT/avatars and updates avatar_url on user.
    """
    # Basic content-type / extension checks
    allowed_extensions = {".jpg", ".jpeg", ".png", ".webp"}
    _, ext = os.path.splitext(file.filename.lower())
    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Use JPG, PNG, or WEBP.",
        )

    contents = await file.read()
    max_size = 2 * 1024 * 1024  # 2 MB
    if len(contents) > max_size:
        raise HTTPException(
            status_code=400,
            detail="File too large. Max size is 2MB.",
        )

    # Generate path
    avatar_dir = os.path.join(settings.MEDIA_ROOT, "avatars")
    os.makedirs(avatar_dir, exist_ok=True)

    filename = f"user_{current_user.id}_{uuid4().hex}{ext}"
    file_path = os.path.join(avatar_dir, filename)

    # Save file
    with open(file_path, "wb") as f:
        f.write(contents)

    # URL that frontend can use (e.g., http://api-host/media/avatars/xxx.png)
    current_user.avatar_url = f"{settings.MEDIA_URL}/avatars/{filename}"

    db.commit()
    db.refresh(current_user)
    return current_user

@router.get("/{username}/profile", response_model=UserProfileDetail)
def get_user_profile(
    username: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Full public profile: user + related content (recent posts, counts, etc.)
    """
    user: Optional[User] = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Recent posts
    posts = (
        db.query(Post)
        .filter(Post.author_id == user.id, Post.is_deleted == False)
        .order_by(Post.created_at.desc())
        .limit(10)
        .all()
    )

    followers_count = db.query(Follow).filter(Follow.following_id == user.id).count()
    following_count = db.query(Follow).filter(Follow.follower_id == user.id).count()
    bookmarks_count = db.query(Bookmark).filter(Bookmark.user_id == user.id).count()

    return UserProfileDetail(
        user=UserPublic.from_orm(user),
        recent_posts=[PostSummary.from_orm(p) for p in posts],
        followers_count=followers_count,
        following_count=following_count,
        bookmarks_count=bookmarks_count,
    )
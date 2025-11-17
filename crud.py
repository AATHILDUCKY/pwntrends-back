from typing import List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import func

from models import (
    User,
    UserRole,
    Tag,
    Post,
    PostTag,
    Comment,
    Vote,
    RefreshToken,
)
from schemas import PostCreate, PostUpdate
from config import settings
from datetime import datetime, timedelta
import secrets


# ---------- Users ----------

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()



def create_user(
    db: Session,
    email: str,
    full_name: str,
    hashed_password: str,
    username: Optional[str] = None,
    role: UserRole = UserRole.user,
) -> User:
    user = User(
        email=email,
        full_name=full_name,
        hashed_password=hashed_password,
        username=username,
        role=role,
        is_active=True,
        is_email_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ---------- Tags ----------

def get_or_create_tags(db: Session, slugs: List[str]) -> List[Tag]:
    tags: List[Tag] = []
    for slug in slugs:
        slug_norm = slug.strip().lower()
        if not slug_norm:
            continue
        tag = db.query(Tag).filter(Tag.slug == slug_norm).first()
        if not tag:
            tag = Tag(
                name=slug_norm.replace("-", " ").title(),
                slug=slug_norm,
                description=None,
            )
            db.add(tag)
            db.flush()
        tags.append(tag)
    db.commit()
    return tags


# ---------- Posts ----------

def create_post(db: Session, author_id: int, data: PostCreate) -> Post:
    tags = get_or_create_tags(db, data.tags)

    post = Post(
        title=data.title,
        body=data.body,
        post_type=data.post_type,
        author_id=author_id,
        group_id=data.group_id,
        is_ctf=data.is_ctf,
        difficulty=data.difficulty,
        thumbnail_url=data.thumbnail_url,
        repo_url=data.repo_url,
        tech_stack=data.tech_stack,
        project_category=data.project_category,
        license=data.license,
        looking_for_contributors=data.looking_for_contributors,
    )
    db.add(post)
    db.flush()

    for tag in tags:
        db.add(PostTag(post_id=post.id, tag_id=tag.id))

    db.commit()
    db.refresh(post)
    return post


def update_post(
    db: Session,
    post: Post,
    data: PostUpdate,
) -> Post:
    if data.title is not None:
        post.title = data.title
    if data.body is not None:
        post.body = data.body
    if data.is_ctf is not None:
        post.is_ctf = data.is_ctf
    if data.difficulty is not None:
        post.difficulty = data.difficulty
    if data.thumbnail_url is not None:
        post.thumbnail_url = data.thumbnail_url
    if data.repo_url is not None:
        post.repo_url = data.repo_url
    if data.tech_stack is not None:
        post.tech_stack = data.tech_stack
    if data.project_category is not None:
        post.project_category = data.project_category
    if data.license is not None:
        post.license = data.license
    if data.looking_for_contributors is not None:
        post.looking_for_contributors = data.looking_for_contributors

    if data.tags is not None:
        db.query(PostTag).filter(PostTag.post_id == post.id).delete()
        tags = get_or_create_tags(db, data.tags)
        for tag in tags:
            db.add(PostTag(post_id=post.id, tag_id=tag.id))

    db.commit()
    db.refresh(post)
    return post


def list_posts(
    db: Session,
    post_type: Optional[str] = None,
    tag_slug: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 20,
) -> List[Post]:
    q = db.query(Post).filter(Post.is_deleted == False)

    if post_type:
        q = q.filter(Post.post_type == post_type)

    if tag_slug:
        q = q.join(PostTag).join(Tag).filter(Tag.slug == tag_slug)

    if search:
        ilike = f"%{search.lower()}%"
        q = q.filter(
            func.lower(Post.title).like(ilike)
            | func.lower(Post.body).like(ilike)
        )

    q = q.order_by(Post.created_at.desc())
    return q.offset(skip).limit(limit).all()


# ---------- Comments / Votes ----------

def create_comment(
    db: Session,
    post_id: int,
    author_id: int,
    body: str,
    parent_id: Optional[int] = None,
) -> Comment:
    comment = Comment(
        post_id=post_id,
        author_id=author_id,
        body=body,
        parent_id=parent_id,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment


def cast_vote_on_post(
    db: Session, user_id: int, post_id: int, value: int
) -> Vote:
    vote = (
        db.query(Vote)
        .filter(
            Vote.user_id == user_id,
            Vote.post_id == post_id,
            Vote.comment_id.is_(None),
        )
        .first()
    )
    if vote:
        vote.value = value
    else:
        vote = Vote(
            user_id=user_id,
            post_id=post_id,
            comment_id=None,
            value=value,
        )
        db.add(vote)

    db.commit()
    db.refresh(vote)
    return vote


# ---------- Refresh Tokens ----------

def create_refresh_token(db: Session, user_id: int) -> RefreshToken:
    token = secrets.token_urlsafe(48)
    expires_at = datetime.utcnow() + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    rt = RefreshToken(
        user_id=user_id,
        token=token,
        expires_at=expires_at,
        revoked=False,
    )
    db.add(rt)
    db.commit()
    db.refresh(rt)
    return rt


def get_refresh_token(db: Session, token: str) -> Optional[RefreshToken]:
    return (
        db.query(RefreshToken)
        .filter(RefreshToken.token == token)
        .first()
    )


def revoke_refresh_token(db: Session, rt: RefreshToken) -> None:
    rt.revoked = True
    db.commit()

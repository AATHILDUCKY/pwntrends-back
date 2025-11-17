from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from auth import get_current_user, get_current_user_optional
from database import get_db
from models import Post, Tag, Comment, User, Vote
from schemas import (
    PostCreate,
    PostUpdate,
    PostOut,
    CommentCreate,
    CommentOut,
    VoteIn,
    UserPublic,
    Message,
)
from crud import list_posts, create_post, update_post, create_comment, cast_vote_on_post

router = APIRouter(prefix="/posts", tags=["Posts"])


def to_post_out(
    post: Post,
    db: Session,
    current_user: Optional[User] = None,
) -> PostOut:
    author_public = UserPublic.from_orm(post.author)
    tags = [t.tag for t in post.tags]  # PostTag -> Tag

    # Total score (sum of all +1 / -1 votes for this post)
    score = (
        db.query(func.coalesce(func.sum(Vote.value), 0))
        .filter(Vote.post_id == post.id, Vote.comment_id.is_(None))
        .scalar()
    )

    # Current user's vote
    my_vote_val: Optional[int] = None
    if current_user:
        v = (
            db.query(Vote)
            .filter(
                Vote.post_id == post.id,
                Vote.comment_id.is_(None),
                Vote.user_id == current_user.id,
            )
            .first()
        )
        if v:
            my_vote_val = v.value

    return PostOut(
        id=post.id,
        title=post.title,
        body=post.body,
        post_type=post.post_type,
        is_ctf=post.is_ctf,
        difficulty=post.difficulty,
        thumbnail_url=post.thumbnail_url,
        group_id=post.group_id,
        author=author_public,
        tags=tags,
        view_count=post.view_count,
        repo_url=post.repo_url,
        tech_stack=post.tech_stack,
        project_category=post.project_category,
        license=post.license,
        looking_for_contributors=post.looking_for_contributors,
        created_at=post.created_at,
        updated_at=post.updated_at,
        score=score,
        my_vote=my_vote_val,
    )


# 🎯 IMPORTANT CHANGE: remove trailing slash
@router.post("", response_model=PostOut)
def create_post_endpoint(
    payload: PostCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    post = create_post(db, current_user.id, payload)
    return to_post_out(post, db, current_user)


# 🎯 IMPORTANT CHANGE: remove trailing slash
@router.get("", response_model=List[PostOut])
def list_posts_endpoint(
    post_type: Optional[str] = Query(default=None),
    tag: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None),
    skip: int = 0,
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    posts = list_posts(
        db,
        post_type=post_type,
        tag_slug=tag,
        search=q,
        skip=skip,
        limit=limit,
    )
    return [to_post_out(p, db, current_user) for p in posts]


@router.get("/{post_id}", response_model=PostOut)
def get_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    post = db.query(Post).filter(Post.id == post_id, Post.is_deleted == False).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    post.view_count += 1
    db.commit()
    db.refresh(post)

    return to_post_out(post, db, current_user)


@router.put("/{post_id}", response_model=PostOut)
def update_post_endpoint(
    post_id: int,
    payload: PostUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post or post.is_deleted:
        raise HTTPException(status_code=404, detail="Post not found")

    if post.author_id != current_user.id:
        raise HTTPException(
            status_code=403, detail="Not allowed to edit this post"
        )

    post = update_post(db, post, payload)
    return to_post_out(post, db, current_user)


@router.post("/{post_id}/comments", response_model=CommentOut)
def create_comment_endpoint(
    post_id: int,
    payload: CommentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    post = db.query(Post).filter(Post.id == post_id, Post.is_deleted == False).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    comment = create_comment(
        db,
        post_id=post_id,
        author_id=current_user.id,
        body=payload.body,
        parent_id=payload.parent_id,
    )

    author_public = UserPublic.from_orm(comment.author)
    return CommentOut(
        id=comment.id,
        body=comment.body,
        author=author_public,
        parent_id=comment.parent_id,
        created_at=comment.created_at,
        updated_at=comment.updated_at,
    )


@router.get("/{post_id}/comments", response_model=List[CommentOut])
def list_comments(
    post_id: int,
    db: Session = Depends(get_db),
):
    comments = (
        db.query(Comment)
        .filter(Comment.post_id == post_id, Comment.is_deleted == False)
        .order_by(Comment.created_at.asc())
        .all()
    )

    out: List[CommentOut] = []
    for c in comments:
        author_public = UserPublic.from_orm(c.author)
        out.append(
            CommentOut(
                id=c.id,
                body=c.body,
                author=author_public,
                parent_id=c.parent_id,
                created_at=c.created_at,
                updated_at=c.updated_at,
            )
        )
    return out


@router.post("/{post_id}/vote", response_model=Message)
def vote_post(
    post_id: int,
    payload: VoteIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    post = db.query(Post).filter(Post.id == post_id, Post.is_deleted == False).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    cast_vote_on_post(db, current_user.id, post_id, int(payload.value))
    return {"detail": "Vote recorded"}

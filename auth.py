import json
import secrets
import smtplib
import ssl
from datetime import datetime, timedelta
from typing import Optional

from email.message import EmailMessage

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Request,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from database import get_db
from models import User, EmailOTP, RefreshToken, UserRole
from schemas import (
    UserOut,
    Token,
    TokenData,
    RegisterInit,
    RegisterVerify,
    ForgotPasswordInit,
    ForgotPasswordVerify,
    Message,
)
from config import settings
from crud import get_user_by_email, create_refresh_token, get_refresh_token, revoke_refresh_token, get_user_by_username

from models import UserRole
# ==========================
# JWT / Auth Config
# ==========================

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

router = APIRouter(prefix="/auth", tags=["Auth"])


# ==========================
# Email / OTP Config
# ==========================

SMTP_HOST = settings.SMTP_HOST
SMTP_PORT = settings.SMTP_PORT
SMTP_USERNAME = settings.SMTP_USERNAME
SMTP_PASSWORD = settings.SMTP_PASSWORD
SMTP_USE_TLS = settings.SMTP_USE_TLS
EMAIL_FROM = settings.EMAIL_FROM or SMTP_USERNAME or "no-reply@localhost"

OTP_EXP_MINUTES = settings.OTP_EXP_MINUTES
OTP_LENGTH = settings.OTP_LENGTH


# ==========================
# Password / Token Helpers
# ==========================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": str(user_id), "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def authenticate_user(
    db: Session,
    email: str,
    password: str,
) -> Optional[User]:
    user = get_user_by_email(db, email)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    if not user.is_email_verified:
        return None
    return user


# ==========================
# Email Helpers
# ==========================

def generate_otp(length: int = OTP_LENGTH) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(length))


def send_email(subject: str, recipient: str, body: str) -> None:
    msg = (
        f"Subject: {subject}\r\n"
        f"From: {EMAIL_FROM}\r\n"
        f"To: {recipient}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"\r\n"
        f"{body}"
    )

    if not (SMTP_HOST and SMTP_PORT and SMTP_USERNAME and SMTP_PASSWORD):
        print("\n===== DEV EMAIL (SMTP NOT CONFIGURED) =====")
        print(f"To      : {recipient}")
        print(f"Subject : {subject}")
        print("Body:")
        print(body)
        print("===========================================\n")
        return

    context = ssl.create_default_context()

    try:
        if SMTP_USE_TLS and SMTP_PORT == 587:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(EMAIL_FROM, [recipient], msg)
        else:
            with smtplib.SMTP_SSL(
                SMTP_HOST,
                SMTP_PORT,
                context=context,
                timeout=15,
            ) as server:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(EMAIL_FROM, [recipient], msg)
    except Exception as e:
        print("\n[EMAIL ERROR] Failed to send email via SMTP:")
        print(f"Host: {SMTP_HOST}:{SMTP_PORT}")
        print(f"Error: {e}")
        print("Subject:", subject)
        print("To:", recipient)
        print("Body:", body)
        print("==================================================\n")


def send_email_with_attachment(
    subject: str,
    recipient: str,
    body: str,
    attachment_filename: str,
    attachment_bytes: bytes,
    attachment_mime: str = "application/pdf",
) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = recipient
    msg.set_content(body)

    try:
        maintype, subtype = attachment_mime.split("/", 1)
    except ValueError:
        maintype, subtype = "application", "octet-stream"

    msg.add_attachment(
        attachment_bytes,
        maintype=maintype,
        subtype=subtype,
        filename=attachment_filename,
    )

    if not (SMTP_HOST and SMTP_PORT and SMTP_USERNAME and SMTP_PASSWORD):
        print("\n===== DEV EMAIL WITH ATTACHMENT (SMTP NOT CONFIGURED) =====")
        print(f"To      : {recipient}")
        print(f"Subject : {subject}")
        print("Body:")
        print(body)
        print(f"[Attachment: {attachment_filename}, {len(attachment_bytes)} bytes]")
        print("===========================================================\n")
        return

    context = ssl.create_default_context()

    try:
        if SMTP_USE_TLS and SMTP_PORT == 587:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP_SSL(
                SMTP_HOST,
                SMTP_PORT,
                context=context,
                timeout=15,
            ) as server:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
    except Exception as e:
        print("\n[EMAIL ERROR] Failed to send email with attachment via SMTP:")
        print(f"Host: {SMTP_HOST}:{SMTP_PORT}")
        print(f"Error: {e}")
        print("Subject:", subject)
        print("To:", recipient)
        print(f"Attachment: {attachment_filename}")
        print("==================================================\n")


# ==========================
# OTP Persistence
# ==========================

def create_otp_record(
    db: Session,
    email: str,
    purpose: str,
    data: Optional[dict] = None,
) -> str:
    db.query(EmailOTP).filter(
        EmailOTP.email == email,
        EmailOTP.purpose == purpose,
        EmailOTP.is_used == False,
    ).update({"is_used": True})

    code = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=OTP_EXP_MINUTES)

    otp = EmailOTP(
        email=email,
        code=code,
        purpose=purpose,
        data=json.dumps(data) if data else None,
        expires_at=expires_at,
        is_used=False,
    )
    db.add(otp)
    db.commit()
    db.refresh(otp)
    return code


def verify_otp_record(
    db: Session,
    email: str,
    purpose: str,
    code: str,
) -> EmailOTP:
    now = datetime.utcnow()
    otp = (
        db.query(EmailOTP)
        .filter(
            EmailOTP.email == email,
            EmailOTP.purpose == purpose,
            EmailOTP.code == code,
            EmailOTP.is_used == False,
            EmailOTP.expires_at >= now,
        )
        .order_by(EmailOTP.created_at.desc())
        .first()
    )

    if not otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP",
        )

    otp.is_used = True
    db.commit()
    db.refresh(otp)
    return otp


# ==========================
# Dependencies
# ==========================

def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=int(user_id))
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == token_data.user_id).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )
    return user


def get_current_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.role != UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user



def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[User]:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            return None
    except JWTError:
        return None

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        return None
    if not user.is_active:
        return None
    return user


# ==========================
# Routes
# ==========================

@router.get("/me", response_model=UserOut)
def read_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/register/init", response_model=Message)
def register_init(
    payload: RegisterInit,
    db: Session = Depends(get_db),
):
    # Check email uniqueness
    if get_user_by_email(db, payload.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Check username uniqueness
    if get_user_by_username(db, payload.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken",
        )

    password_hash = get_password_hash(payload.password)

    code = create_otp_record(
        db,
        email=payload.email,
        purpose="register",
        data={
            "full_name": payload.full_name,
            "username": payload.username,
            "password_hash": password_hash,
        },
    )

    send_email(
        subject="Your registration OTP",
        recipient=payload.email,
        body=(
            f"Hi {payload.full_name},\n\n"
            f"Your OTP for account registration is: {code}\n"
            f"It is valid for {OTP_EXP_MINUTES} minutes.\n\n"
            f"If you did not request this, please ignore this email."
        ),
    )

    return Message(detail="OTP sent to your email address.")



@router.post("/register/verify", response_model=UserOut)
def register_verify(
    payload: RegisterVerify,
    db: Session = Depends(get_db),
):
    # Email should not already be registered
    if get_user_by_email(db, payload.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Validate OTP record
    otp = verify_otp_record(
        db,
        email=payload.email,
        purpose="register",
        code=payload.otp,
    )

    # OTP data contains full_name, username, password_hash from init step
    data = json.loads(otp.data or "{}")
    full_name = data.get("full_name")
    username = data.get("username")
    password_hash = data.get("password_hash")

    if not full_name or not username or not password_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP payload. Please restart registration.",
        )

    # Create new user – NOTE: no `is_admin` argument here
    user = User(
        full_name=full_name,
        username=username,
        email=payload.email,
        hashed_password=password_hash,
        role=UserRole.user,
        is_active=True,
        is_email_verified=True,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user



@router.post("/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    # form_data.username is actually email
    user = authenticate_user(
        db,
        form_data.username,
        form_data.password,
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    access_token = create_access_token(user.id)
    refresh = create_refresh_token(db, user.id)
    return Token(access_token=access_token, refresh_token=refresh.token)


@router.post("/refresh", response_model=Token)
def refresh_token(
    token: str,
    db: Session = Depends(get_db),
):
    rt: Optional[RefreshToken] = get_refresh_token(db, token)
    if not rt or rt.revoked or rt.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    access_token = create_access_token(rt.user_id)
    return Token(access_token=access_token, refresh_token=rt.token)


@router.post("/logout", response_model=Message)
def logout(
    token: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rt = get_refresh_token(db, token)
    if not rt or rt.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token",
        )

    revoke_refresh_token(db, rt)
    return Message(detail="Logged out successfully.")


@router.post("/forgot-password/init", response_model=Message)
def forgot_password_init(
    payload: ForgotPasswordInit,
    db: Session = Depends(get_db),
):
    user = get_user_by_email(db, payload.email)

    if user:
        code = create_otp_record(
            db,
            email=payload.email,
            purpose="reset_password",
            data=None,
        )
        send_email(
            subject="Your password reset OTP",
            recipient=payload.email,
            body=(
                f"Hi,\n\n"
                f"Your OTP to reset your password is: {code}\n"
                f"It is valid for {OTP_EXP_MINUTES} minutes.\n\n"
                f"If you did not request this, please ignore this email."
            ),
        )

    return Message(detail="If this email is registered, an OTP has been sent.")


@router.post("/forgot-password/verify", response_model=Message)
def forgot_password_verify(
    payload: ForgotPasswordVerify,
    db: Session = Depends(get_db),
):
    user = get_user_by_email(db, payload.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or OTP",
        )

    verify_otp_record(
        db,
        email=payload.email,
        purpose="reset_password",
        code=payload.otp,
    )

    user.hashed_password = get_password_hash(payload.new_password)
    db.commit()

    return Message(detail="Password has been reset successfully.")

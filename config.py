from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "DuckySec Forum API"
    BACKEND_CORS_ORIGINS: str = "*"  # comma-separated origins if needed

    DATABASE_URL: str = (
        "postgresql+psycopg2://postgres:postgres@localhost:5432/ducky_forum"
    )

    SECRET_KEY: str = "CHANGE_ME"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = True
    EMAIL_FROM: str | None = None

    OTP_EXP_MINUTES: int = 10
    OTP_LENGTH: int = 6

    MEDIA_ROOT: str = "media"            # folder on disk
    MEDIA_URL: str = "/media" 

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

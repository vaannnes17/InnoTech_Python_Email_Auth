import os
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

import jwt
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, ConfigDict
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.future import select

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/appdb")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-must-be-32-chars-long")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.yandex.ru")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(title="Auth Service", lifespan=lifespan)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_jwt_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def send_verification_email(email_to: str, token: str):
    activation_link = f"http://localhost:8000/auth/verify?token={token}"

    msg = EmailMessage()
    msg['Subject'] = 'Подтверждение регистрации'
    msg['From'] = SMTP_USER if SMTP_USER else "noreply@app.com"
    msg['To'] = email_to

    msg.set_content(f"Для активации перейдите по ссылке: {activation_link}")
    msg.add_alternative(
        f"""\
        <html>
          <body>
            <h2>Подтверждение регистрации</h2>
            <p><a href="{activation_link}" style="padding: 10px 15px; background: #28a745; color: white; text-decoration: none; border-radius: 4px;">Активировать аккаунт</a></p>
            <p>Или скопируйте ссылку: <a href="{activation_link}">{activation_link}</a></p>
          </body>
        </html>
        """,
        subtype='html'
    )

    if SMTP_USER and SMTP_PASSWORD:
        try:
            if SMTP_PORT == 465:
                with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                    server.starttls()
                    server.login(SMTP_USER, SMTP_PASSWORD)
                    server.send_message(msg)
        except Exception as e:
            print(f"SMTP error: {e}")
    else:
        print(f"Verify URL for {email_to}: {activation_link}")


class RegisterSchema(BaseModel):
    email: EmailStr
    password: str


class TokenSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    is_active: bool


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
async def register(data: RegisterSchema, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == data.email))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Пользователь с таким Email уже существует")

    hashed_pw = hash_password(data.password)
    user = User(email=data.email, hashed_password=hashed_pw, is_active=False)

    db.add(user)
    await db.commit()

    token = create_jwt_token(
        data={"sub": data.email, "type": "email_verify"},
        expires_delta=timedelta(minutes=15)
    )
    background_tasks.add_task(send_verification_email, data.email, token)

    return {"message": "Регистрация успешна. Ссылка для подтверждения отправлена на email."}


@app.get("/auth/verify", response_model=TokenSchema)
async def verify(token: str, db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")
        if token_type != "email_verify" or not email:
            raise HTTPException(status_code=400, detail="Невалидный токен")
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail="Ссылка недействительна или её срок истек")

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    user.is_active = True
    await db.commit()

    access_token = create_jwt_token(
        data={"sub": user.email, "type": "access"},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return TokenSchema(access_token=access_token)


@app.post("/auth/login", response_model=TokenSchema)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalars().first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Неверный email или пароль")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Аккаунт не активирован. Перейдите по ссылке из письма.")

    access_token = create_jwt_token(
        data={"sub": user.email, "type": "access"},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return TokenSchema(access_token=access_token)


@app.get("/auth/me", response_model=UserResponseSchema)
async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Невалидный токен")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Токен просрочен или недействителен")

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    return user


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
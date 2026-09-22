import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from main import app, Base, get_db

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine_test = create_async_engine(TEST_DATABASE_URL, echo=False)
TestingSessionLocal = sessionmaker(engine_test, class_=AsyncSession, expire_on_commit=False)


async def override_get_db():
    async with TestingSessionLocal() as session:
        yield session


app.dependency_overrides[get_db] = override_get_db


@pytest_asyncio.fixture(autouse=True, scope="function")
async def prepare_database():
    async with engine_test.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine_test.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.mark.asyncio
async def test_full_auth_flow(monkeypatch):
    captured_tokens = []

    def mock_send_email(email_to, token):
        captured_tokens.append(token)

    monkeypatch.setattr("main.send_verification_email", mock_send_email)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        reg_response = await ac.post("/auth/register", json={
            "email": "user@example.com",
            "password": "strongpassword123"
        })
        assert reg_response.status_code == 201
        assert len(captured_tokens) == 1

        token = captured_tokens[0]

        login_before_verify = await ac.post("/auth/login", data={
            "username": "user@example.com",
            "password": "strongpassword123"
        })
        assert login_before_verify.status_code == 403

        verify_response = await ac.get(f"/auth/verify?token={token}")
        assert verify_response.status_code == 200
        assert "access_token" in verify_response.json()

        login_response = await ac.post("/auth/login", data={
            "username": "user@example.com",
            "password": "strongpassword123"
        })
        assert login_response.status_code == 200
        access_token = login_response.json()["access_token"]

        me_response = await ac.get("/auth/me", headers={
            "Authorization": f"Bearer {access_token}"
        })
        assert me_response.status_code == 200
        assert me_response.json()["email"] == "user@example.com"
        assert me_response.json()["is_active"] is True
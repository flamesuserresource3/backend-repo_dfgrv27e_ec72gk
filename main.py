import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db
from schemas import User as UserSchema, Event as EventSchema

# App setup
app = FastAPI(title="Campus Connect API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security / Auth constants
SECRET_KEY = os.getenv("JWT_SECRET", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Helpers

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def user_to_public(u: dict) -> dict:
    if not u:
        return u
    u = {**u}
    u["id"] = str(u.get("_id")) if u.get("_id") else None
    u.pop("_id", None)
    u.pop("password", None)
    return u


# Dependency: get current user
class TokenData(BaseModel):
    user_id: Optional[str] = None
    email: Optional[EmailStr] = None


def get_user_by_email(email: str) -> Optional[dict]:
    return db["user"].find_one({"email": email})


def get_user_by_id(user_id: str) -> Optional[dict]:
    try:
        return db["user"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        return None


async def get_current_user(token: str = Depends(oauth2_scheme)):
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
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception

    user = get_user_by_id(token_data.user_id)
    if user is None:
        raise credentials_exception
    return user


# Models for requests/responses
class SignUpBody(BaseModel):
    name: str
    email: EmailStr
    password: str
    college: Optional[str] = None
    year: Optional[str] = None
    skills: List[str] = []
    interests: List[str] = []


class LoginBody(BaseModel):
    email: EmailStr
    password: str


class UpdateUserBody(BaseModel):
    name: Optional[str] = None
    college: Optional[str] = None
    year: Optional[str] = None
    skills: Optional[List[str]] = None
    interests: Optional[List[str]] = None
    connections: Optional[List[str]] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# Auth Endpoints
@app.post("/api/auth/signup", response_model=TokenResponse)
def signup(body: SignUpBody):
    if db is None:
        raise HTTPException(500, "Database not configured")

    if get_user_by_email(body.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = UserSchema(
        name=body.name,
        email=body.email,
        password=hash_password(body.password),
        college=body.college,
        year=body.year,
        skills=body.skills or [],
        interests=body.interests or [],
        connections=[],
    ).model_dump()

    inserted_id = db["user"].insert_one(user_doc).inserted_id

    token = create_access_token({"sub": str(inserted_id), "email": body.email})
    return TokenResponse(access_token=token)


@app.post("/api/auth/login", response_model=TokenResponse)
def login(body: LoginBody):
    if db is None:
        raise HTTPException(500, "Database not configured")

    user = get_user_by_email(body.email)
    if not user or not verify_password(body.password, user.get("password", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    token = create_access_token({"sub": str(user["_id"]), "email": user["email"]})
    return TokenResponse(access_token=token)


# Users Endpoints
@app.get("/api/users")
def get_all_users(current=Depends(get_current_user)):
    users = list(db["user"].find())
    return [user_to_public(u) for u in users]


@app.get("/api/users/{user_id}")
def get_user(user_id: str, current=Depends(get_current_user)):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(404, "User not found")
    return user_to_public(user)


@app.put("/api/users/{user_id}")
def update_user(user_id: str, body: UpdateUserBody, current=Depends(get_current_user)):
    update = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    if not update:
        return user_to_public(get_user_by_id(user_id))
    if "connections" in update:
        # Ensure connections are strings
        update["connections"] = [str(x) for x in (update["connections"] or [])]
    res = db["user"].update_one({"_id": ObjectId(user_id)}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(404, "User not found")
    return user_to_public(get_user_by_id(user_id))


# Events Endpoints
@app.get("/api/events")
def get_events(current=Depends(get_current_user)):
    events = list(db["event"].find())
    # Seed a few defaults if empty (non-destructive)
    if len(events) == 0:
        seed = [
            EventSchema(title="Hackathon 101", date="2025-01-20", description="Beginner-friendly campus hackathon", link="https://example.com/h1").model_dump(),
            EventSchema(title="AI Study Jam", date="2025-02-10", description="Collaborative ML learning session", link="https://example.com/ai").model_dump(),
            EventSchema(title="Dev Meetup", date="2025-03-05", description="Networking for developers", link="https://example.com/dev").model_dump(),
        ]
        if db is None:
            raise HTTPException(500, "Database not configured")
        db["event"].insert_many(seed)
        events = list(db["event"].find())
    # Convert ids
    for e in events:
        e["id"] = str(e.get("_id"))
        e.pop("_id", None)
    return events


# Matchmaking using cosine similarity
from collections import Counter
import math

def vectorize(tags: List[str]) -> Counter:
    # Lowercase and deduplicate via Counter
    return Counter([t.strip().lower() for t in (tags or []) if t and isinstance(t, str)])


def cosine_similarity(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    common = set(a.keys()) & set(b.keys())
    dot = sum(a[t] * b[t] for t in common)
    mag_a = math.sqrt(sum(v * v for v in a.values()))
    mag_b = math.sqrt(sum(v * v for v in b.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


@app.get("/api/match/{user_id}")
def get_matches(user_id: str, limit: int = 5, current=Depends(get_current_user)):
    me = get_user_by_id(user_id)
    if not me:
        raise HTTPException(404, "User not found")

    my_vec = vectorize((me.get("skills") or []) + (me.get("interests") or []))

    candidates = list(db["user"].find({"_id": {"$ne": ObjectId(user_id)}}))
    scored = []
    for u in candidates:
        v = vectorize((u.get("skills") or []) + (u.get("interests") or []))
        score = cosine_similarity(my_vec, v)
        scored.append({"user": user_to_public(u), "score": score})
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[: limit]


@app.get("/")
def read_root():
    return {"message": "Campus Connect API is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

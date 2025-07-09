from fastapi import FastAPI, HTTPException, Depends, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, constr
from passlib.hash import bcrypt
import jwt
from datetime import datetime, timedelta
import psycopg2
import psycopg2.extras
import requests

# --- Config ---
JWT_SECRET = "super-secret-key"
JWT_ALGORITHM = "HS256"
SPOONACULAR_API_KEY = "3b4bc2c9a636462e96b2db614005efcf"

# --- App & Middleware ---
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security ---
security = HTTPBearer()

# --- DB Connection ---
def get_db():
    return psycopg2.connect(
        dbname="Recipe_management",
        user="postgres",
        password="Akshay@2003",
        host="localhost",
        port="5432"
    )

# --- Models ---
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: constr(min_length=8)

class UserLogin(BaseModel):
    identifier: str
    password: str

class Review(BaseModel):
    recipe_id: int
    rating: int
    comment: str

# --- JWT helpers ---
def create_jwt_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(hours=12)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- User helpers ---
def get_user_by_username(username: str):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    token = credentials.credentials
    username = decode_jwt_token(token)
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# --- Startup: create tables ---
@app.on_event("startup")
def startup():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id SERIAL PRIMARY KEY,
            user_id INT NOT NULL,
            recipe_id INT NOT NULL,
            rating INT CHECK (rating >= 1 AND rating <= 5),
            comment TEXT
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

# --- Routes ---
@app.post("/register")
def register(user: UserRegister):
    hashed_pw = bcrypt.hash(user.password)
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (user.username, user.email, hashed_pw)
        )
        conn.commit()
        return {"message": "User registered successfully"}
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Username or email already exists")
    finally:
        cur.close()
        conn.close()

@app.post("/login")
def login(data: UserLogin):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM users WHERE username=%s OR email=%s", (data.identifier, data.identifier))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if not user or not bcrypt.verify(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_jwt_token(user["username"])
    return {"access_token": token}

@app.get("/recipes")
def get_recipes(
    query: str,
    dietary_preferences: str = None,
    ingredient_preferences: str = None,
    ingredient_avoidance: str = None,
    user=Depends(get_current_user)
):
    url = "https://api.spoonacular.com/recipes/complexSearch"
    params = {
        "query": query,
        "number": 5,
        "apiKey": SPOONACULAR_API_KEY
    }
    if dietary_preferences:
        params["diet"] = dietary_preferences
    if ingredient_preferences:
        params["includeIngredients"] = ingredient_preferences
    if ingredient_avoidance:
        params["excludeIngredients"] = ingredient_avoidance

    response = requests.get(url, params=params)
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Failed to fetch recipes")
    return response.json()

@app.post("/review")
def submit_review(review: Review, user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO reviews (user_id, recipe_id, rating, comment) VALUES (%s, %s, %s, %s)",
        (user["id"], review.recipe_id, review.rating, review.comment)
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Review submitted"}

@app.get("/reviews/{recipe_id}")
def get_reviews(recipe_id: int, user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(
        "SELECT * FROM reviews WHERE recipe_id = %s AND user_id = %s",
        (recipe_id, user["id"])
    )
    reviews = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in reviews]

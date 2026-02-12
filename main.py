# app.py
import os
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from typing import List, Optional

# ================= FASTAPI APP =================
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Angular or any front-end
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= DATABASE =================
# Use PostgreSQL from Railway ENV variable
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise Exception("DATABASE_URL environment variable not set!")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ================= USERS TABLE =================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String)
    password = Column(String)
    role = Column(String, default="user")

# ================= MOVIES TABLE =================
class Movie(Base):
    __tablename__ = "movies"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, unique=True)
    year = Column(Integer)
    rank = Column(Float)
    img_poster = Column(String)
    imdb_url = Column(String)
    trailer = Column(String)
    actors = Column(String)
    description = Column(String)

Base.metadata.create_all(bind=engine)

# ================= PASSWORD HASH =================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def hash_password(password: str):
    return pwd_context.hash(password)
def verify_password(password: str, hashed: str):
    return pwd_context.verify(password, hashed)

# ================= JWT CONFIG =================
SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ================= SCHEMAS =================
class Register(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[str] = "user"

class Login(BaseModel):
    username: str
    password: str

class MovieSchema(BaseModel):
    title: str
    year: int
    rank: float
    img_poster: str
    imdb_url: str
    trailer: str
    actors: str
    description: str

# ================= DATABASE DEP =================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ================= REGISTER =================
@app.post("/register")
def register(user: Register, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    new_user = User(
        username=user.username,
        email=user.email,
        password=hash_password(user.password),
        role=user.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "Registered successfully", "username": new_user.username, "role": new_user.role}

# ================= LOGIN =================
@app.post("/login")
def login(user: Login, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_access_token({"sub": db_user.username, "role": db_user.role})
    return {"access_token": token, "token_type": "bearer", "role": db_user.role}

# ================= AUTH SYSTEM =================
security = HTTPBearer()
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload

# ================= PROTECTED ROUTES =================
@app.get("/profile")
def profile(user=Depends(get_current_user)):
    return {"message": f"Welcome {user['sub']}", "role": user["role"]}

@app.get("/admin")
def admin_only(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return {"message": "Welcome Admin 🔥"}

# ================= MOVIES ENDPOINTS =================
@app.get("/movies", response_model=List[MovieSchema])
def get_all_movies(db: Session = Depends(get_db)):
    movies = db.query(Movie).all()
    return movies

@app.get("/movies/{title}", response_model=List[MovieSchema])
def get_movie_by_title(title: str, db: Session = Depends(get_db)):
    movies = db.query(Movie).filter(Movie.title.ilike(f"%{title}%")).all()
    if not movies:
        raise HTTPException(status_code=404, detail="Movie not found")
    return movies

# ================= ADD MOVIE (for Angular) =================
@app.post("/movies/add", response_model=MovieSchema)
def add_movie(movie: MovieSchema, db: Session = Depends(get_db)):
    if db.query(Movie).filter(Movie.title == movie.title).first():
        raise HTTPException(status_code=400, detail="Movie already exists")
    new_movie = Movie(
        title=movie.title,
        year=movie.year,
        rank=movie.rank,
        img_poster=movie.img_poster,
        imdb_url=movie.imdb_url,
        trailer=movie.trailer,
        actors=movie.actors,
        description=movie.description
    )
    db.add(new_movie)
    db.commit()
    db.refresh(new_movie)
    return new_movie

# ================= STARTUP EVENT: Add sample movies =================
@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    sample_movies = [
        Movie(
            title="The Dark Knight",
            year=2008,
            rank=9.0,
            img_poster="https://m.media-amazon.com/images/I/51EbJjlCj-L._AC_.jpg",
            imdb_url="https://www.imdb.com/title/tt0468569/",
            trailer="https://www.youtube.com/watch?v=EXeTwQWrcwY",
            actors="Christian Bale, Heath Ledger, Aaron Eckhart",
            description="Batman faces the Joker, a criminal mastermind who wants to create chaos in Gotham City."
        ),
        Movie(
            title="Inception",
            year=2010,
            rank=8.8,
            img_poster="https://m.media-amazon.com/images/I/51s+3HZ3GaL._AC_.jpg",
            imdb_url="https://www.imdb.com/title/tt1375666/",
            trailer="https://www.youtube.com/watch?v=YoHD9XEInc0",
            actors="Leonardo DiCaprio, Joseph Gordon-Levitt, Ellen Page",
            description="A thief who steals corporate secrets through the use of dream-sharing technology."
        ),
        Movie(
            title="Interstellar",
            year=2014,
            rank=8.6,
            img_poster="https://m.media-amazon.com/images/I/71niXI3lxlL._AC_SY679_.jpg",
            imdb_url="https://www.imdb.com/title/tt0816692/",
            trailer="https://www.youtube.com/watch?v=zSWdZVtXT7E",
            actors="Matthew McConaughey, Anne Hathaway, Jessica Chastain",
            description="A team of explorers travel through a wormhole in space in an attempt to ensure humanity's survival."
        )
    ]
    for movie in sample_movies:
        if not db.query(Movie).filter(Movie.title == movie.title).first():
            db.add(movie)
    db.commit()
    db.close()
    print("Sample movies added successfully ✅")

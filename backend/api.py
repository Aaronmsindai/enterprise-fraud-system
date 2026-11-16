from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, Float, String, DateTime, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from kafka import KafkaProducer
import json
import random
import re
import uuid

# ==========================================
# 1. DATABASE SETUP & PSYCOPG2 FIX
# ==========================================
DATABASE_URL = "postgresql://admin:Password123!@localhost:5432/fraud_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ==========================================
# 2. DATABASE MODELS
# ==========================================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="teller")

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String, unique=True)
    card_network = Column(String)
    card_number = Column(String)
    amount = Column(Float)
    currency = Column(String, default="USD")
    hour_of_day = Column(Integer)
    user_age = Column(Integer)
    is_international = Column(Integer)
    ip_address = Column(String) 
    device_id = Column(String)
    typing_speed = Column(Float)
    prediction = Column(String, default="PENDING")
    probability = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    card_network = Column(String)
    card_number = Column(String)
    amount = Column(Float)
    prediction = Column(String)
    probability = Column(Float)
    model_version = Column(String)
    risk_factors = Column(String)

class PendingWire(Base):
    __tablename__ = "pending_wires"
    id = Column(Integer, primary_key=True, index=True)
    initiator_id = Column(Integer)
    card_number = Column(String)
    amount = Column(Float)
    status = Column(String, default="PENDING") 
    timestamp = Column(DateTime, default=datetime.utcnow)

class SARLog(Base):
    __tablename__ = "sar_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    transaction_id = Column(Integer)
    reason = Column(String)
    reported_to_fincen = Column(Boolean, default=True)

# NEW: Analyst Feedback Table
class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"
    id = Column(Integer, primary_key=True, index=True)
    audit_id = Column(Integer)
    is_confirmed_fraud = Column(Boolean)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ==========================================
# 3. SECURITY & JWT SETUP
# ==========================================
SECRET_KEY = "super_secret_bank_key_123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def verify_password(plain_password, hashed_password): return pwd_context.verify(plain_password, hashed_password)
def get_password_hash(password): return pwd_context.hash(password)
def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"username": payload.get("sub"), "role": payload.get("role")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin": raise HTTPException(status_code=403, detail="Admin only.")
    return current_user

# ==========================================
# 4. HELPER FUNCTIONS
# ==========================================
def is_valid_luhn(card_number: str) -> bool:
    clean_number = re.sub(r'[\s-]', '', card_number)
    if not clean_number.isdigit(): return False
    digits = [int(d) for d in clean_number]
    checksum = 0
    for i, digit in enumerate(digits[::-1]):
        if i % 2 == 1:
            digit *= 2
            if digit > 9: digit -= 9
        checksum += digit
    return checksum % 10 == 0

def detect_card_network(card_number: str) -> str:
    clean_number = re.sub(r'[\s-]', '', card_number)
    if re.match(r"^4", clean_number): return "Visa"
    if re.match(r"^(5[1-5]|2[2-7])", clean_number): return "Mastercard"
    if re.match(r"^3[47]", clean_number): return "American Express"
    if re.match(r"^62", clean_number): return "UnionPay"
    return "Unknown"

# ==========================================
# 5. PYDANTIC SCHEMAS
# ==========================================
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    password: str = Field(..., min_length=8)
    @field_validator('username')
    def validate_username(cls, v):
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", v): raise ValueError('Invalid username format.')
        return v
    @field_validator('password')
    def validate_password(cls, v):
        if not re.search(r"[A-Z]", v): raise ValueError("Needs an uppercase letter.")
        if not re.search(r"[a-z]", v): raise ValueError("Needs a lowercase letter.")
        if not re.search(r"\d", v): raise ValueError("Needs a number.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v): raise ValueError("Needs a special character.")
        return v

class AccountValidationInput(BaseModel):
    account_number: str
    routing_number: str

class TransactionInput(BaseModel):
    card_network: str
    card_number: str = Field(..., min_length=16, max_length=19)
    amount: float = Field(..., gt=0, lt=1000000)
    currency: str = Field(default="USD")
    hour_of_day: int = Field(..., ge=0, le=23)
    user_age: int = Field(..., ge=18, le=100)
    is_international: int = Field(..., ge=0, le=1)
    ip_address: str
    device_id: str = Field(..., min_length=3, max_length=50)
    typing_speed: float = Field(..., ge=0.0)
    is_wire_transfer: int = Field(default=0)
    @field_validator('card_number')
    def validate_card_number(cls, v: str) -> str:
        if not is_valid_luhn(v): raise ValueError('Invalid card number (Luhn check failed).')
        return v
    @field_validator('ip_address')
    def validate_ip_address(cls, v: str) -> str:
        ip_regex = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if not re.match(ip_regex, v): raise ValueError('Invalid IPv4 address format.')
        return v

class HistoryItem(BaseModel):
    id: int
    transaction_id: str
    card_network: str
    card_number: str
    amount: float
    currency: str
    hour_of_day: int
    user_age: int
    prediction: str
    probability: float
    timestamp: datetime
    class Config: from_attributes = True

class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    card_network: str
    card_number: str
    amount: float
    prediction: str
    probability: float
    model_version: str
    class Config: from_attributes = True

class WireResponse(BaseModel):
    id: int
    card_number: str
    amount: float
    status: str
    timestamp: datetime
    class Config: from_attributes = True

class SARResponse(BaseModel):
    id: int
    timestamp: datetime
    transaction_id: int
    reason: str
    reported_to_fincen: bool
    class Config: from_attributes = True

# ==========================================
# 6. FASTAPI APP & KAFKA SETUP
# ==========================================
app = FastAPI(title="Enterprise Fraud API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False, 
    allow_methods=["*"],
    allow_headers=["*"],
)

producer = KafkaProducer(
    bootstrap_servers=['localhost:29092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

@app.post("/verify_account")
def verify_account(data: AccountValidationInput, current_user: dict = Depends(get_current_user)):
    if len(data.account_number) < 8 or len(data.routing_number) != 9:
        raise HTTPException(status_code=400, detail="Invalid ACH routing or account number length.")
    is_active = random.random() > 0.10
    if not is_active: raise HTTPException(status_code=400, detail="Nacha Validation Failed: Account is closed.")
    return {"status": "valid", "message": "Account verified and active for ACH transfers."}

@app.post("/predict")
def predict_fraud(tx: TransactionInput, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    detected_network = detect_card_network(tx.card_number)
    tx_id = f"tx_{uuid.uuid4().hex[:8]}"
    
    new_tx = Transaction(
        transaction_id=tx_id, card_network=detected_network, card_number=tx.card_number, amount=tx.amount, 
        currency=tx.currency, hour_of_day=tx.hour_of_day, user_age=tx.user_age, is_international=tx.is_international, 
        ip_address=tx.ip_address, device_id=tx.device_id, typing_speed=tx.typing_speed, prediction="PENDING"
    )
    db.add(new_tx)
    db.commit()
    db.refresh(new_tx)

    event = {
        "transaction_id": tx_id,
        "card_number": tx.card_number,
        "amount": tx.amount,
        "device_id": tx.device_id,
        "ip_address": tx.ip_address,
        "hour_of_day": tx.hour_of_day,
        "user_age": tx.user_age,
        "is_international": tx.is_international,
        "typing_speed": tx.typing_speed,
        "is_wire_transfer": tx.is_wire_transfer
    }
    producer.send('transactions', event)
    producer.flush()
    
    return {
        "transaction_id": tx_id,
        "status": "PENDING", 
        "message": "Transaction queued for real-time risk evaluation."
    }

@app.get("/transaction/{tx_id}")
def get_transaction_status(tx_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    tx = db.query(Transaction).filter(Transaction.transaction_id == tx_id).first()
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return tx

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first(): 
        raise HTTPException(status_code=400, detail="Username already registered")
    role = "admin" if user.username.lower() == "admin" else "teller"
    db.add(User(username=user.username, hashed_password=get_password_hash(user.password), role=role))
    db.commit()
    return {"message": f"User created successfully as {role}"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password): 
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token(data={"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer", "role": user.role}

@app.get("/history", response_model=List[HistoryItem])
def get_history(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    return db.query(Transaction).order_by(Transaction.timestamp.desc()).limit(10).all()

@app.get("/admin/audit", response_model=List[AuditLogResponse])
def get_audit_logs(db: Session = Depends(get_db), current_user: dict = Depends(get_current_admin_user)):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(10).all()

@app.get("/admin/wires", response_model=List[WireResponse])
def get_pending_wires(db: Session = Depends(get_db), current_user: dict = Depends(get_current_admin_user)):
    return db.query(PendingWire).order_by(PendingWire.timestamp.desc()).all()

@app.post("/admin/wires/{wire_id}/approve")
def approve_wire(wire_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_admin_user)):
    wire = db.query(PendingWire).filter(PendingWire.id == wire_id).first()
    if not wire: raise HTTPException(status_code=404, detail="Wire not found")
    if wire.status != "PENDING": raise HTTPException(status_code=400, detail="Wire already processed")
    wire.status = "APPROVED"
    db.commit()
    return {"message": "Wire transfer approved and funds released."}

@app.post("/admin/generate_sar/{audit_id}")
def generate_sar(audit_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_admin_user)):
    audit = db.query(AuditLog).filter(AuditLog.id == audit_id).first()
    if not audit: raise HTTPException(status_code=404, detail="Audit log not found")
    new_sar = SARLog(transaction_id=audit_id, reason=f"Fraud blocked: {audit.risk_factors}")
    db.add(new_sar)
    db.commit()
    return {"message": f"SAR successfully filed to FinCEN for Transaction #{audit_id}"}

@app.get("/admin/sars", response_model=List[SARResponse])
def get_sars(db: Session = Depends(get_db), current_user: dict = Depends(get_current_admin_user)):
    return db.query(SARLog).order_by(SARLog.timestamp.desc()).all()

# NEW: Submit Feedback Endpoint
@app.post("/admin/feedback/{audit_id}")
def submit_feedback(audit_id: int, is_fraud: bool, db: Session = Depends(get_db), current_user: dict = Depends(get_current_admin_user)):
    existing = db.query(AnalystFeedback).filter(AnalystFeedback.audit_id == audit_id).first()
    if existing:
        existing.is_confirmed_fraud = is_fraud
    else:
        new_feedback = AnalystFeedback(audit_id=audit_id, is_confirmed_fraud=is_fraud)
        db.add(new_feedback)
    db.commit()
    return {"message": "Analyst feedback recorded. Model will learn from this."}
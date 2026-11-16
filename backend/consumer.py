import json
import redis
import pandas as pd
import pickle
import os
from sklearn.ensemble import GradientBoostingClassifier
from kafka import KafkaConsumer
from neo4j import GraphDatabase
from sqlalchemy import create_engine, Column, Integer, Float, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

# --- 1. SETUP POSTGRESQL ---
DATABASE_URL = "postgresql://admin:Password123!@localhost:5432/fraud_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String, unique=True)
    card_number = Column(String)
    amount = Column(Float)
    prediction = Column(String)
    probability = Column(Float)

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

Base.metadata.create_all(bind=engine)
db = SessionLocal()

# --- 2. SETUP ML MODEL ---
MODEL_PATH = "model.pkl"
if os.path.exists(MODEL_PATH):
    print("🧠 Loading pre-trained ML model from disk...")
    with open(MODEL_PATH, "rb") as f:
        ml_model = pickle.load(f)
else:
    print("⚠️ No model.pkl found. Training baseline model...")
    X_dummy = pd.DataFrame([[100.0], [5000.0], [50.0]], columns=['amount'])
    y_dummy = [0, 1, 0]
    ml_model = GradientBoostingClassifier(n_estimators=10, random_state=42)
    ml_model.fit(X_dummy, y_dummy)

# --- 3. SETUP KAFKA, REDIS, NEO4J ---
consumer = KafkaConsumer(
    'transactions', bootstrap_servers=['localhost:29092'],
    auto_offset_reset='earliest', enable_auto_commit=True,
    group_id='risk-engine-group', value_deserializer=lambda x: json.loads(x.decode('utf-8'))
)

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "Password123!"))

def check_fraud_ring(tx_data):
    query = """
    MERGE (c:Card {number: $card})
    MERGE (d:Device {id: $device})
    MERGE (c)-[:USED_ON]->(d)
    WITH d, COUNT { (d)<-[:USED_ON]-(:Card) } AS card_count
    RETURN card_count
    """
    with driver.session() as session:
        result = session.run(query, card=tx_data['card_number'], device=tx_data['device_id'])
        record = result.single()
        return record["card_count"] if record else 0

print("🎧 Enterprise Risk Engine is LIVE. Listening for transactions...")

for message in consumer:
    tx = message.value
    tx_id = tx['transaction_id']
    card = tx['card_number']
    amount = tx['amount']
    device = tx.get('device_id', 'Unknown')
    
    print(f"\n🔥 Processing {tx_id} | Card: ...{card[-4:]} | Amount: ${amount}")
    
    # --- EVALUATION 1: REDIS (Velocity) ---
    redis_key = f"velocity:{card}"
    current_count = r.incr(redis_key)
    if current_count == 1: r.expire(redis_key, 60)
    
    # --- EVALUATION 2: NEO4J (Graph Fraud Ring) ---
    card_count_for_device = check_fraud_ring(tx)
    
    # --- EVALUATION 3: ML CLASSIFIER ---
    features = pd.DataFrame([[amount]], columns=['amount'])
    ml_probability = float(ml_model.predict_proba(features)[0][1])
    
    print(f"   📊 Redis Velocity: {current_count} | Neo4j Linked Cards: {card_count_for_device} | ML Risk: {ml_probability*100:.1f}%")

    # --- FINAL DECISION ENGINE ---
    final_decision = "APPROVE"
    
    if current_count >= 3:
        final_decision = "BLOCK_VELOCITY"
        print("   🛑 BLOCK: VELOCITY RULE TRIGGERED")
    elif card_count_for_device > 1:
        final_decision = "BLOCK_FRAUD_RING"
        print("   🛑 BLOCK: FRAUD RING DETECTED")
    elif ml_probability > 0.50:
        final_decision = "BLOCK_ML"
        print("   🛑 BLOCK: ML MODEL FLAGGED HIGH RISK")
    else:
        print("   ✅ APPROVED: Passed all checks")

    # --- UPDATE TRANSACTION IN POSTGRESQL ---
    tx_record = db.query(Transaction).filter(Transaction.transaction_id == tx_id).first()
    if tx_record:
        tx_record.prediction = final_decision
        tx_record.probability = ml_probability * 100
        db.commit()

    # --- SAVE TO AUDIT LOG ---
    card_network = "Visa" if card.startswith('4') else "Mastercard" if card.startswith('5') else "Unknown"
    new_log = AuditLog(
        card_network=card_network,
        card_number=card,
        amount=amount,
        prediction=final_decision,
        probability=ml_probability * 100,
        model_version="Enterprise-v1.1",
        risk_factors=json.dumps({"Redis_Velocity": current_count, "Neo4j_Links": card_count_for_device, "ML_Score": round(ml_probability*100, 2)})
    )
    db.add(new_log)
    db.commit()
    print(f"   💾 Updated Transaction status and Saved Audit Log.")
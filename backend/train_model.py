import pandas as pd
import pickle
from sqlalchemy import create_engine
from sklearn.ensemble import GradientBoostingClassifier

DATABASE_URL = "postgresql://admin:Password123!@localhost:5432/fraud_db"
engine = create_engine(DATABASE_URL)

print("🧠 Starting MLOps Retraining Pipeline...")

# 1. Fetch historical data and merge with analyst feedback
query = """
    SELECT a.amount, f.is_confirmed_fraud 
    FROM audit_logs a
    LEFT JOIN analyst_feedback f ON a.id = f.audit_id
"""
df = pd.read_sql(query, con=engine)

# 2. Prepare labels (1 = Fraud, 0 = Safe)
# Drop rows where we don't have a definitive label yet
df = df.dropna(subset=['is_confirmed_fraud'])
df['label'] = df['is_confirmed_fraud'].apply(lambda x: 1 if x is True else 0)

# If we don't have enough real data yet, mix in synthetic data so the model doesn't crash
if len(df) < 10:
    print("⚠️ Not enough feedback data. Blending with baseline synthetic data.")
    dummy_data = pd.DataFrame({'amount': [100.0, 5000.0, 50.0], 'label': [0, 1, 0]})
    df = pd.concat([df, dummy_data], ignore_index=True)

# 3. Train the new Champion Model
X = df[['amount']]
y = df['label']

model = GradientBoostingClassifier(n_estimators=50, random_state=42)
model.fit(X, y)

# 4. Save the model to disk
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print(f"✅ Model retrained on {len(df)} records and saved to model.pkl!")
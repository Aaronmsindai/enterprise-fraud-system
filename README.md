🏦 Enterprise Fraud Detection System

A high-throughput, event-driven microservices architecture designed to evaluate transaction risk in real-time. Originally built as a monolithic application, this project was re-architected to handle high concurrency, avoid database race conditions, and align with OCC/FDIC Fraud Risk Management Principles.

🏗️ Architecture Overview

This system is built using an event-driven architecture to decouple transaction ingestion from the heavy risk-evaluation engine.

· Frontend: React.js (Asynchronous polling for PENDING states)
· Ingestion API: FastAPI (Validates payloads via Pydantic and produces to Kafka)
· Event Broker: Apache Kafka (Decouples ingestion from processing to prevent backpressure)
· Risk Engine (Consumer): Python (Consumes Kafka events)
· Feature Store: Redis (In-memory atomic rate limiting/velocity checks)
· Graph Database: Neo4j (Real-time Fraud Ring / Money Mule detection)
· Machine Learning: Scikit-Learn (Gradient Boosting Classifier + MLOps Feedback Loop)
· Database: PostgreSQL (Immutable audit logs and transaction state)

⚙️ Core Features

· Real-Time Velocity Checks: Uses Redis to block cards used 3+ times in 60 seconds. This prevents SQL database race conditions under high load.
· Graph Fraud Ring Detection: Uses Neo4j to instantly detect if a single device (Device ID) is linked to multiple credit cards, catching money mule networks.
· Maker-Checker Pattern: High-value wire transfers require Admin dual-approval before funds are released.
· Regulatory Compliance:
  · Automated SAR (Suspicious Activity Report) generation.
  · Immutable Audit Trails stored in PostgreSQL for examiner review.
· MLOps Feedback Loop: Analysts can flag transactions as "False Positive" or "Confirm Fraud" in the UI. An automated train_model.py pipeline pulls this feedback to retrain the Machine Learning model.
· Multi-Currency Support: Frontend accepts multiple currencies; backend normalizes to USD before feeding features to the ML model to maintain a stable feature space.

🚀 How to Run Locally

Prerequisites

· Docker Desktop
· Python 3.10+
· Node.js (for the frontend)

1. Start the Infrastructure

Spin up PostgreSQL, Redis, Kafka, Zookeeper, and Neo4j:

```bash
docker compose up -d
```

2. Start the Ingestion API

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --reload --port 8000
```

3. Start the Risk Engine (Consumer)

Open a new terminal:

```bash
cd backend
source .venv/bin/activate
python3 -u consumer.py
```

4. Start the React Frontend

Open a new terminal:

```bash
cd frontend
npm install
npm run dev
```

🔐 Demo Credentials

· Username: admin
· Password: Password123!
  (Note: If the database is wiped, you can register this user directly on the login screen).

🧠 How to Test the MLOps Retraining Pipeline

1. Submit a transaction in the React UI.
2. Go to Admin Settings and click "False Positive" or "Confirm Fraud" on the audit log.
3. Run the training script in the backend terminal:
   ```bash
   python3 train_model.py
   ```
4. Restart the Consumer (python3 -u consumer.py). It will automatically load the newly trained model.pkl into memory.

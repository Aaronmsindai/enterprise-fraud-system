import json
import time
from kafka import KafkaProducer

# Connect to Kafka using the external listener port (29092)
producer = KafkaProducer(
    bootstrap_servers=['localhost:29092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

TOPIC_NAME = 'transactions'

# The transaction payload
transaction = {
    "transaction_id": "tx_1001",
    "card_number": "4242424242424242",
    "amount": 250.00,
    "currency": "USD",
    "device_id": "iPhone-12",
    "ip_address": "192.168.1.1",
    "timestamp": time.time()
}

print(f"Sending transaction to Kafka topic '{TOPIC_NAME}'...")
producer.send(TOPIC_NAME, transaction)
producer.flush() # Force it to send immediately
print("✅ Transaction sent successfully!")
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest

# Load collected network traffic
traffic_data = pd.read_csv(
    "traffic_data.csv",
    header=None,
    names=["packet_rate", "average_packet_size"]
)

print("Total measurements:", len(traffic_data))
print(traffic_data.head())

print("\nDataset statistics:")
print(traffic_data.describe())

print("\nMissing values:")
print(traffic_data.isnull().sum())

print("\nTop 10 highest packet rates:")

print(
    traffic_data.nlargest(10, "packet_rate")
)

# Separate training and testing measurements
X_train, X_test = train_test_split(
    traffic_data,
    test_size=0.20,
    random_state=42,
    shuffle=False
)

print("\nTraining measurements:", len(X_train))
print("Testing measurements:", len(X_test))

# Train Isolation Forest using collected network traffic
model = IsolationForest(
    contamination=0.10,
    random_state=42
)

model.fit(X_train)

joblib.dump(model, "ids_model.pkl")

print("Machine-learning model saved!")

print("\nIsolation Forest training completed!")

# Test the model using unseen measurements
predictions = model.predict(X_test)

normal_count = sum(predictions == 1)
anomaly_count = sum(predictions == -1)

print("\nMachine Learning Evaluation:")
print(f"Normal measurements: {normal_count}")
print(f"Anomalous measurements: {anomaly_count}")

# Show the measurements classified as anomalies
test_results = X_test.copy()

test_results["prediction"] = predictions

anomalies = test_results[
    test_results["prediction"] == -1
]

print("\nDetected anomalies:")
print(anomalies)

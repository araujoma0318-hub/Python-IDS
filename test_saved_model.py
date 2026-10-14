
import joblib
import pandas as pd
# Load our saved machine-learning model
model = joblib.load("ids_model.pkl")

# Features: [packet rate, average packet size]
test_traffic = [
    [15, 300],
    [40, 500],
    [100, 1200]
]


test_data = pd.DataFrame(
    test_traffic,
    columns=["packet_rate", "average_packet_size"]
)

predictions = model.predict(test_data)


for traffic, prediction in zip(test_traffic, predictions):
    if prediction == -1:
        print(f"Traffic {traffic} - Anomaly detected!")
    else:
        print(f"Traffic {traffic} - Normal")

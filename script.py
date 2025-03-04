import pyshark
import numpy as np
import tensorflow as tf
import streamlit as st
import pandas as pd
from keras.models import load_model
from scapy.all import *
import os
import logging

# Suppress TensorFlow INFO and WARNING messages
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Set as string, not integer
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'  # Disable oneDNN optimizations

# Suppress logging messages from TensorFlow
logging.getLogger("tensorflow").setLevel(logging.ERROR)
tf.get_logger().setLevel('ERROR')
tf.autograph.set_verbosity(0)

# Load the trained Semi-2DCAE model
model_path = r"C:\Users\Ramakrishna\OneDrive\Desktop\Major Project\Semi-2DCAE-main\semi_2dcae_model.keras"
model = load_model(model_path)

# Define categories
class_labels = {0: 'Chat', 1: 'Email', 2: 'File', 3: 'P2P', 4: 'Streaming', 5: 'VoIP'}

def preprocess_packet(packet):
    """Extracts features from the packet and reshapes it for model input."""
    try:
        features = np.zeros((28, 28, 1))  # Example shape, adjust based on preprocessing needs
        if 'IP' in packet:
            features[0, 0, 0] = int(packet.len) / 1500  # Normalize packet length
        return features.reshape(1, 28, 28, 1)
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

def classify_packet(packet):
    """Processes a live network packet and classifies it using the Semi-2DCAE model."""
    processed_data = preprocess_packet(packet)
    if processed_data is not None:
        prediction = model.predict(processed_data)
        class_index = np.argmax(prediction[1])  # Get class from classifier output
        return class_labels.get(class_index, "Unknown")
    return "Unknown"

def process_packet(packet):
    """Handles packet classification in real time."""
    classification = classify_packet(packet)
    print(f"Packet classified as: {classification}")
    return classification

def dashboard():
    """Streamlit dashboard for real-time encrypted traffic classification."""
    st.title("🔍 Encrypted Traffic Classification Dashboard")
    st.write("### Capturing and classifying network traffic in real time.")

    if st.button("Start Capture"):
        st.write("**Capturing traffic...**")
        captured_data = []
        sniff(iface="Wi-Fi", filter="", prn=lambda x: captured_data.append(process_packet(x)), store=False, count = 30)

        df = pd.DataFrame(captured_data, columns=['Packet Classification'])
        st.write(df)

    st.write("### Real-Time Visualization")
    if 'df' in locals() and not df.empty:
        st.line_chart(df['Packet Classification'].value_counts())

if __name__ == "__main__":
    dashboard()
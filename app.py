import requests
import re
import socket
from datetime import datetime
import whois
import pickle
import pandas as pd
import streamlit as st
from requests.exceptions import RequestException
from urllib3.exceptions import NewConnectionError


# Load the trained model
model_path = 'XGBoostClassifier.pkl'  # Path to your saved model
model = pickle.load(open(model_path, 'rb'))


def fetch_website_data(url):
    try:
        # Helper functions to extract features from the URL
        def has_ip(url):
            ip_pattern = r"^(http[s]?://)?(\d{1,3}\.){3}\d{1,3}"
            return bool(re.match(ip_pattern, url))

        def has_at_symbol(url):
            return '@' in url

        def url_length(url):
            return len(url)

        def url_depth(url):
            return url.count('/') - 2 if '//' in url else url.count('/')

        def has_redirection(url):
            return url.count('//') > 1

        def uses_https(url):
            return url.startswith('https')

        def is_tinyurl(url):
            tinyurl_patterns = ['bit.ly', 't.co', 'goo.gl', 'tinyurl', 'is.gd', 'buff.ly']
            return any(shortener in url for shortener in tinyurl_patterns)

        def has_prefix_suffix(url):
            domain = re.findall(r'://([^/]+)', url)[0] if '://' in url else url
            return '-' in domain

        def dns_record_exists(url):
            try:
                domain = re.findall(r'://([^/]+)', url)[0] if '://' in url else url
                socket.gethostbyname(domain)
                return True
            except Exception:
                return False

        def domain_age(url):
            try:
                domain = re.findall(r'://([^/]+)', url)[0] if '://' in url else url
                domain_info = whois.whois(domain)
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if creation_date:
                    age = (datetime.now() - creation_date).days // 365
                    return 1 if age > 1 else 0
                return "Unknown"
            except Exception:
                return "Unknown"

        def domain_end_period(url):
            try:
                domain = re.findall(r'://([^/]+)', url)[0] if '://' in url else url
                domain_info = whois.whois(domain)
                expiration_date = domain_info.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                if expiration_date:
                    days_left = (expiration_date - datetime.now()).days
                    return 1 if days_left > 180 else 0
                return "Unknown"
            except Exception:
                return "Unknown"

        def has_iframe(response_text):
            return '<iframe' in response_text.lower()

        def has_mouse_over(response_text):
            return 'onmouseover' in response_text.lower()

        def blocks_right_click(response_text):
            return 'event.button==2' in response_text.lower()

        def has_web_forwards(response):
            return response.url != url

        # Send a GET request to the URL
        response = requests.get(url)
        response.raise_for_status()

        # Extract features
        features = {
            "Have_IP": int(has_ip(url)),
            "Have_At": int(has_at_symbol(url)),  # Changed here from "Have_@" to "Have_At"
            "URL_Length": url_length(url),
            "URL_Depth": url_depth(url),
            "Redirection": int(has_redirection(url)),
            "https_Domain": int(uses_https(url)),
            "TinyURL": int(is_tinyurl(url)),
            "Prefix/Suffix": int(has_prefix_suffix(url)),
            "DNS_Record": int(dns_record_exists(url)),
            "Domain_Age": domain_age(url),
            "Domain_End": domain_end_period(url),
            "iFrame": int(has_iframe(response.text)),
            "Mouse_Over": int(has_mouse_over(response.text)),
            "Right_Click": int(blocks_right_click(response.text)),
            "Web_Forwards": int(has_web_forwards(response))
        }

        return features

    except (RequestException, NewConnectionError, socket.gaierror) as e:
        # Return an empty dictionary to signify phishing without error message
        return {}


def predict_phishing(features):
    # Convert features to a DataFrame for model prediction
    df = pd.DataFrame([features])

    # Predict using the loaded model
    prediction = model.predict(df)
    return prediction[0]


# Streamlit app
st.title("Phishing URL Detection")
st.write("Enter a URL to analyze its features.")

url = st.text_input("Website URL")

if st.button("Analyze"):
    if url:
        result = fetch_website_data(url)
        if not result:  # If result is an empty dictionary, it's phishing
            prediction = 1
        else:
            # Predict if the URL is phishing or not
            prediction = predict_phishing(result)

        # Display prediction with aesthetic background color based on prediction
        st.subheader("Prediction:")
        if prediction == 1:
            st.markdown(
                '<div style="background-color:#FF4C4C; color:white; padding: 15px; border-radius: 10px; font-size: 20px; text-align: center;">Phishing</div>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                '<div style="background-color:#4CAF50; color:white; padding: 15px; border-radius: 10px; font-size: 20px; text-align: center;">Legitimate</div>',
                unsafe_allow_html=True
            )
    else:
        st.warning("Please enter a valid URL.")

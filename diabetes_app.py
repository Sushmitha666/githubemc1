import streamlit as st
from PIL import Image
import pytesseract
import tempfile
import os
import base64
import pdfkit
from datetime import date
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# Configure external tools
TESSERACT_PATH = r"C:\\Program Files\\Tesseract-OCR\\tesseract.exe"
WKHTMLTOPDF_PATH = r"C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe"
pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH
pdf_config = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)

st.set_page_config(page_title="🯪 Diabetes Risk Assistant", layout="centered")

# AES Encryption Utilities
def encrypt_pdf(data, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return salt + cipher.iv + ct_bytes

def decrypt_pdf(data, password):
    try:
        salt = data[:16]
        iv = data[16:32]
        ct = data[32:]
        key = PBKDF2(password, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size)
    except Exception:
        return None

# HTML Report Generator
def generate_html_report(name, gender, age, today, glucose, blood_pressure, skin_thickness,
                         insulin, bmi, dpf, pregnancies, result, confidence, ocr_text, normal_ranges):
    if ocr_text:
        return f"""<html>
<head>
    <style>
        body {{ font-family: Arial; padding: 40px; }}
        h1 {{ color: #0A75AD; }}
        pre {{ background-color: #f4f4f4; padding: 10px; border: 1px solid #ccc; }}
    </style>
</head>
<body>
    <h1>Sunrise Medical Diagnostics</h1>
    <h2>Diabetes Risk Evaluation Report</h2>
    <p><strong>Status:</strong> {result}</p>
    <p><strong>Confidence:</strong> {confidence}%</p>
    <div>
        <h3>Doctor's Note</h3>
        <p>Based on the provided report, there's a {confidence:.1f}% chance of diabetes. This assessment is derived from textual data in the uploaded document.</p>
        <p>It is advised to consult your healthcare provider for clinical confirmation, and additional testing such as HbA1c or fasting plasma glucose may be recommended.</p>
        <p><em>This report was generated digitally for informational use only and is not a clinical diagnosis.</em></p>
    </div>
    <h3>Extracted Report Text</h3>
    <pre>{ocr_text}</pre>
</body>
</html>"""
    else:
        return f"""<html>
<head>
    <style>
        body {{ font-family: Segoe UI; padding: 40px; }}
        h1 {{ color: #2980b9; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Sunrise Medical Diagnostics</h1>
    <h2>Diabetes Risk Evaluation Report</h2>
    <p><strong>Name:</strong> {name}</p>
    <p><strong>Gender:</strong> {gender}</p>
    <p><strong>Age:</strong> {age}</p>
    <p><strong>Date:</strong> {today}</p>
    <table>
        <tr><th>Parameter</th><th>Value</th><th>Reference</th></tr>
        <tr><td>Glucose</td><td>{glucose}</td><td>{normal_ranges['Glucose']}</td></tr>
        <tr><td>Blood Pressure</td><td>{blood_pressure}</td><td>{normal_ranges['Blood Pressure']}</td></tr>
        <tr><td>Skin Thickness</td><td>{skin_thickness}</td><td>{normal_ranges['Skin Thickness']}</td></tr>
        <tr><td>Insulin</td><td>{insulin}</td><td>{normal_ranges['Insulin']}</td></tr>
        <tr><td>BMI</td><td>{bmi}</td><td>{normal_ranges['BMI']}</td></tr>
        <tr><td>DPF</td><td>{dpf}</td><td>{normal_ranges['DPF']}</td></tr>
        <tr><td>Pregnancies</td><td>{pregnancies}</td><td>{normal_ranges['Pregnancies']}</td></tr>
    </table>
    <p><strong>Result:</strong> {result}</p>
    <p><strong>Confidence:</strong> {confidence}%</p>
    <h3>Doctor's Note</h3>
    <p>Based on the entered health parameters, there's a {confidence:.1f}% chance of diabetes.</p>
    <p>It's recommended to consult a healthcare provider for further evaluation. Tests like HbA1c or a fasting glucose test may be helpful.</p>
    <p><em>This report is for informational purposes only and does not replace professional medical advice.</em></p>
</body>
</html>"""

# Session State
for key in ["analysis_done", "ocr_text", "result", "confidence", "show_chatbot"]:
    if key not in st.session_state:
        st.session_state[key] = "" if key == "ocr_text" else False if key in ["analysis_done", "show_chatbot"] else 0.0

# UI Title
st.title("🯪 Diabetes Risk Assistant")
st.subheader("Assess your diabetes risk using manual entry or health report image 📊")
st.markdown("---")

# Name Input
name = st.text_input("🧑 Full Name:")

# Manual Inputs
st.markdown("### ✍ Manual Health Data Entry")
normal_ranges = {
    "Glucose": "70 - 99 mg/dL",
    "Blood Pressure": "80 - 120 mm Hg",
    "Skin Thickness": "10 - 40 mm",
    "Insulin": "16 - 166 mu U/ml",
    "BMI": "18.5 - 24.9",
    "DPF": "0 - 1.0",
    "Pregnancies": "N/A"
}

gender = st.radio("Gender:", ["Male", "Female"], horizontal=True)
pregnancies = st.number_input("🧰 Pregnancies (Normal: N/A):", 0, 20, 1) if gender == "Female" else 0
glucose = st.number_input(f"🩸 Glucose (mg/dL) (Normal: {normal_ranges['Glucose']}):", 0, 300, 0)
blood_pressure = st.number_input(f"❤ Blood Pressure (mm Hg) (Normal: {normal_ranges['Blood Pressure']}):", 0, 200, 0)
skin_thickness = st.number_input(f"🧤 Skin Thickness (mm) (Normal: {normal_ranges['Skin Thickness']}):", 0, 100, 0)
insulin = st.number_input(f"💉 Insulin (mu U/ml) (Normal: {normal_ranges['Insulin']}):", 0.0, 846.0, 0.0)
bmi = st.number_input(f"⚖ BMI (Normal: {normal_ranges['BMI']}):", 0.0, 67.1, 0.0)
dpf = st.number_input(f"✨ Diabetes Pedigree Function (Normal: {normal_ranges['DPF']}):", 0.0, 2.5, 0.0)
age = st.slider("🎂 Age:", 1, 100, 0)

# Image Upload
st.markdown("### 📄 Or Upload Your Health Report")
uploaded_image = st.file_uploader("Upload a report image (JPG/PNG):", type=["jpg", "jpeg", "png"])
manual_fields = [glucose, blood_pressure, skin_thickness, insulin, bmi, dpf, age]
use_manual = any(val > 0 for val in manual_fields)

# Analysis Button
if st.button("🔍 Analyze My Risk"):
    if not name.strip():
        st.warning("Please enter your full name.")
    else:
        today = date.today().strftime("%Y-%m-%d")
        if use_manual:
            if glucose > 140 or bmi > 30 or dpf > 1.0:
                result, confidence = "Diabetic", 85.0
            elif glucose > 110 or bmi > 25:
                result, confidence = "At Risk", 60.0
            else:
                result, confidence = "Non-Diabetic", 30.0
            st.session_state["ocr_text"] = ""
        elif uploaded_image:
            image = Image.open(uploaded_image)
            extracted = pytesseract.image_to_string(image)
            st.session_state["ocr_text"] = extracted
            if "diabetes" in extracted.lower() or "high glucose" in extracted.lower():
                result, confidence = "Likely Diabetic", 85.0
            elif "glucose" in extracted.lower() or "bmi" in extracted.lower():
                result, confidence = "Possibly At Risk", 60.0
            else:
                result, confidence = "Unclear Risk", 30.0
        else:
            st.warning("Please either fill in the form or upload a report.")
            st.stop()

        st.session_state["result"] = result
        st.session_state["confidence"] = confidence
        st.session_state["analysis_done"] = True

# Result Display
if st.session_state["analysis_done"]:
    result = st.session_state["result"]
    confidence = st.session_state["confidence"]
    ocr_text = st.session_state["ocr_text"]
    today = date.today().strftime("%Y-%m-%d")

    st.success(f"📊 *Result:* {result} | 🔒 Confidence: {confidence}%")

    html = generate_html_report(name, gender, age, today, glucose, blood_pressure,
                                skin_thickness, insulin, bmi, dpf, pregnancies,
                                result, confidence, ocr_text, normal_ranges)

    st.markdown("### 🔐 Secure PDF Report Download")
    password_input = st.text_input("Enter password to protect the PDF:", type="password")

    if password_input:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
            pdfkit.from_string(html, tmp_file.name, configuration=pdf_config)
            with open(tmp_file.name, "rb") as f:
                encrypted_data = encrypt_pdf(f.read(), password_input)
                encoded_encrypted = base64.b64encode(encrypted_data).decode("utf-8")

        st.success("Your report has been encrypted.")
        st.markdown(f"""
        <a href="data:application/octet-stream;base64,{encoded_encrypted}" download="diabetes_report.enc">
        📅 Download Encrypted Report (.enc)
        </a>
        """, unsafe_allow_html=True)

# Decryption
st.markdown("---")
st.markdown("### 🔓 Upload & Decrypt Report")
uploaded_enc = st.file_uploader("Upload your encrypted report (.enc)", type=["enc"])
decrypt_password = st.text_input("Enter password to decrypt:", type="password")

if uploaded_enc and decrypt_password:
    enc_bytes = uploaded_enc.read()
    decrypted = decrypt_pdf(enc_bytes, decrypt_password)

    if decrypted:
        st.success("✅ Decryption successful!")
        st.download_button("📄 Download Decrypted PDF", decrypted, file_name="diabetes_report.pdf", mime="application/pdf")
    else:
        st.error("❌ Incorrect password or corrupted file.")

# Chatbot
st.markdown("---")
st.markdown("### 💬 Diabetes Chat Assistant")
user_prompt = st.chat_input("Ask something about diabetes...")

if user_prompt:
    st.session_state["show_chatbot"] = True
    with st.chat_message("user"):
        st.markdown(user_prompt)
    with st.chat_message("assistant"):
        prompt = user_prompt.lower()
        if "glucose" in prompt:
            st.markdown("Glucose is the sugar in your blood. Normal fasting glucose is 70–99 mg/dL.")
        elif "bmi" in prompt:
            st.markdown("BMI helps assess weight status. Over 25 is overweight; over 30 is obese.")
        elif "pregnancy" in prompt:
            st.markdown("Pregnancy can lead to gestational diabetes, a temporary but serious condition.")
        elif "dpf" in prompt:
            st.markdown("DPF measures genetic risk. >1.0 suggests higher family-related diabetes risk.")
        else:
            st.markdown("Ask me about glucose, BMI, blood pressure, insulin, or diabetes risk.")
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pandas as pd
import joblib
import json
import os
from dotenv import load_dotenv

# Load environment variables
env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(env_path)

# Load model and scaler
try:
    model = joblib.load("local_model.joblib")
    scaler = joblib.load("scaler.joblib")
except Exception as e:
    raise RuntimeError(f"❌ Failed to load model or scaler: {e}")

# Load feature importance from model_evaluation.json
try:
    with open("model_evaluation.json", "r") as f:
        model_metadata = json.load(f)
    feature_importance = model_metadata.get("feature_importance", {})
except Exception as e:
    raise RuntimeError(f"❌ Failed to load model_evaluation.json: {e}")

# FastAPI app
app = FastAPI()

# Pydantic input model
class DiabetesInput(BaseModel):
    Pregnancies: int
    Glucose: float
    BloodPressure: float
    SkinThickness: float
    Insulin: float
    BMI: float
    DiabetesPedigreeFunction: float
    Age: int

def generate_local_llm_explanation(probability: float, input_data: dict) -> str:
    lines = []
    key_features = sorted(feature_importance.items(), key=lambda x: abs(x[1]), reverse=True)[:3]

    if probability >= 0.5:  # High risk
        lines.append(f"🔴 **High Risk:** There's a significant chance of diabetes (~{probability * 100:.1f}%).")
        for feature, _ in key_features:
            value = input_data[feature]
            lines.append(f"- **{feature}** is relatively high at {value}. This strongly contributes to your risk.")
        lines.append("👉 Please consult a healthcare professional for further evaluation and tests.")
    elif probability > 0 and probability < 0.5:  # Low to medium risk
        lines.append(f"🟡 **Medium Risk:** Your estimated risk of diabetes is around {probability * 100:.1f}%.")
        lines.append("✅ Consider maintaining a balanced lifestyle and consult a healthcare provider.")
    else:  # Extremely low risk
        lines.append(f"🟢 **Low Risk:** Your estimated risk of diabetes is low (~{probability * 100:.1f}%).")
        lines.append("✅ Maintain a balanced lifestyle to stay healthy.")
        lines.append("📅 Regular check-ups are still recommended.")

    return "\n".join(lines)

@app.post("/predict")
def predict(input: DiabetesInput):
    try:
        input_data = input.dict()
        df = pd.DataFrame([input_data])
        
        # Check the raw input data and scaled values
        print(f"Raw input data: {input_data}")
        
        df_scaled = scaler.transform(df)
        print(f"Scaled input data: {df_scaled}")
        
        probability = model.predict_proba(df_scaled)[0][1]
        print(f"Model raw probability: {probability}")
        
        prediction = int(probability > 0.5)
        explanation = generate_local_llm_explanation(probability, input_data)

        return {
            "prediction": prediction,
            "probability": round(probability, 3),
            "explanation": explanation
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")

@app.get("/")
def read_root():
    return {"message": "Welcome to the Diabetes Risk Prediction API. Use /predict for predictions."}

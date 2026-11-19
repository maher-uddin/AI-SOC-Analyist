# AI-Powered SOC Analyst (local, no external APIs)

React + Vite + Tailwind + Recharts frontend, FastAPI + scikit-learn + SQLite backend. A Streamlit frontend is also included for simple cloud deployment.

## Run on Windows (two terminals)
Terminal 1 - backend
    cd backend
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    uvicorn main:app --reload
Terminal 2 - frontend (needs Node.js 18+)
    cd frontend
    npm install
    npm run dev
Open http://localhost:5173  (API docs: http://127.0.0.1:8000/docs)

## Quick demo flow
1. Dashboard -> "Run simulated traffic" (labelled SIMULATED) -> charts fill from SQLite.
2. Network Monitoring -> filter/search events, upload a CSV.
3. Threat Detection -> metrics, confusion matrix, feature importances; retrain.
4. AI SOC Analyst -> run the 6-agent workflow, ask the chat questions.
5. Incidents -> change status/severity, add notes, download PDF/CSV.
6. MITRE ATT&CK and Reports pages.

## Using your real CICIDS2017 file
Threat Detection -> "Train on my labelled CSV" first, then Network Monitoring -> upload the same file.
The default model is trained on SYNTHETIC data and mislabels real CICIDS rows.

## Honest notes
- Friday-Afternoon-DDoS.csv has no IP/timestamp columns and only BENIGN/DDoS labels; IPs/timestamps are simulated (marked * in the table).
- Random-split scores (~99.98%) are optimistic for single-capture data.
- Threat intel is a small offline list of fictional IPs. Responses are recommendations; "block" is a simulated flag only.
- Large uploads are randomly sampled to 20,000 rows.

## Run with Streamlit
    pip install -r requirements.txt
    streamlit run streamlit_app.py

`streamlit_app.py` imports the backend modules directly, so it does not need the React frontend or a separate FastAPI server.

## Deploy to Streamlit Community Cloud
1. Push this repository to GitHub.
2. Open https://share.streamlit.io and sign in.
3. Select **New app**, choose this repository, branch `main`, and main file `streamlit_app.py`.
4. Click **Deploy**. No secrets or environment variables are required.

Streamlit Community Cloud uses the root `requirements.txt`; the SQLite database and uploaded/generated state are ephemeral on the hosted app.

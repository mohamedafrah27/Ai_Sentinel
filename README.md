# AI-Sentinel

AI-powered phishing website detection and browser protection system.

## Project Structure

- `backend/` — Python Flask backend service
- `extension/` — Browser extension (Chrome Manifest V3)
- `dashboard/` — Frontend dashboard

## Running the Backend

Install Flask if it is not already installed:

```bash
pip install flask
```

Start the Flask development server:

```bash
python backend/app.py
```

### Health Check

```bash
GET /health
```

Returns:

```json
{"status": "AI Sentinel is running"}
```

# FraudGuard Backend Server

FastAPI backend service for fraud detection analysis.

## Setup

**Note:** This project requires Python 3.11 or 3.12. Python 3.13 may have compatibility issues with some dependencies (particularly pydantic-core).

1. Install dependencies:
```bash
pip install -r requirements.txt
```

**Troubleshooting:** If you encounter build errors with `pydantic-core`:
- Use Python 3.11 or 3.12 instead of 3.13
- Or try: `pip install --upgrade pip setuptools wheel` before installing requirements

2. Create a `.env` file (copy from `.env.example` if available):
```bash
BACKEND_URL=http://localhost:8000
# Optional Azure OpenAI config if you want AI-based explanations
# AZURE_OPENAI_ENDPOINT=
# AZURE_OPENAI_KEY=
# AZURE_OPENAI_DEPLOYMENT=
# AZURE_OPENAI_API_VERSION=2023-12-01-preview
```

3. Run the server:
```bash
python -m server.main
```

Or using uvicorn directly:
```bash
uvicorn server.main:app --reload
```

## API Endpoints

### GET `/`
Health check endpoint.

### GET `/health`
Health check endpoint.

### POST `/analyze`
Analyze a URL for fraud risk.

**Request:**
```json
{
  "url": "https://example-bank.com/login"
}
```

**Response:**
```json
{
  "url": "https://example-bank.com/login",
  "risk_score": 75.5,
  "risk_level": "Dangerous",
  "signals": [
    {
      "name": "URL Similarity",
      "score": 85.0,
      "description": "High similarity to known bank domain"
    }
  ],
  "explanation": "This website shows multiple indicators of potential fraud...",
  "recommendation": "Do not enter any personal or financial information..."
}
```

## Testing

Test the API using curl:
```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Or visit the interactive API docs at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc


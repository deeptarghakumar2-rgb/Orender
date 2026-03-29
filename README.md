# FinTrack — Personal Finance Tracker

Full-stack Flask app: JWT auth, SQLite, REST API, Chart.js analytics.

## Quick Start

```bash
# 1. Install
pip install flask

# 2. Run
python app.py

# 3. Open
http://localhost:5000
```

## Termux (Android)
```bash
pkg install python
pip install flask
python app.py
```

## Deploy to Render (Free)
1. Push to GitHub
2. Go to render.com → New Web Service → Connect repo
3. Done! render.yaml handles everything automatically.

## API Routes
- POST /api/auth/signup  /login
- GET  /api/dashboard
- CRUD /api/transactions
- CRUD /api/budgets
- GET  /api/analytics
- GET  /api/notifications

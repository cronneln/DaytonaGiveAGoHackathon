#!/usr/bin/env bash
set -e

# Load nvm so we get the managed Node version instead of the system one
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && source "$NVM_DIR/nvm.sh"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Dependency Auditor Setup ==="

# ── API ───────────────────────────────────────────────────────────────────────
echo ""
echo "--- Setting up API (FastAPI) ---"
cd "$REPO_DIR/api"

if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "Created api/.env from template — fill in your ANTHROPIC_API_KEY and DAYTONA_API_KEY"
    echo "Edit api/.env now, then re-run this script."
    exit 0
fi

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

echo "API setup complete."

# ── Frontend ──────────────────────────────────────────────────────────────────
echo ""
echo "--- Setting up Frontend (Next.js) ---"
cd "$REPO_DIR/frontend"

if [ ! -f ".env.local" ]; then
    echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
fi

npm install

echo "Frontend setup complete."

# ── Start both services ───────────────────────────────────────────────────────
echo ""
echo "=== Starting services ==="

cd "$REPO_DIR/api"
source venv/bin/activate
uvicorn main:app --port 8000 &
API_PID=$!

cd "$REPO_DIR/frontend"
npm run dev &
WEB_PID=$!

trap "echo ''; echo 'Stopping...'; kill $API_PID $WEB_PID 2>/dev/null; exit 0" INT TERM

echo ""
echo "API running at  http://localhost:8000"
echo "Dashboard at    http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop both."

wait $API_PID $WEB_PID

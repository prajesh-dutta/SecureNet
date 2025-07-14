# SecureNet

SecureNet is a demonstration cybersecurity dashboard. It contains a Flask backend that exposes REST and WebSocket APIs and a React/TypeScript frontend built with Vite.

## Prerequisites

- Node.js 18+
- Python 3.11+

## Setup

Install Node dependencies:

```bash
npm install --legacy-peer-deps
```

Install Python dependencies (ideally inside a virtual environment):

```bash
python3 -m pip install -r flask_backend/requirements.txt
```

## Running locally

Start the backend on port `5001`:

```bash
python3 flask_backend/websocket_app.py
```

In another terminal start the frontend dev server:

```bash
npm run dev
```

The dashboard will be available at [http://localhost:5173](http://localhost:5173) and will proxy API calls to the backend.

## Building

To create a production build run:

```bash
npm run build
```

The compiled files will be placed under `dist/public`.

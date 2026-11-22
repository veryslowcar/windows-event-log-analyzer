# Windows Event Log Analyzer

A web application for uploading and analyzing Windows Event Log (`.evtx`) files.

## Planned technology

- **Frontend:** React
- **Backend:** Python and Flask
- **Database:** SQLite
- **Containers:** Docker and Docker Compose
- **CI/CD:** GitHub Actions
- **Deployment:** Google Cloud Run

## Current status

The initial backend scaffold exposes a health endpoint. React, EVTX parsing,
database storage, and event analysis will be added incrementally.

## Run the backend

With Docker Compose:

```bash
docker compose up --build
```

The health endpoint is available at <http://localhost:5000/api/health>.

To run locally, install the development dependencies and start Flask:

```bash
python -m pip install -r backend/requirements-dev.txt
python -m flask --app backend.app run
```

## Run tests

```bash
python -m pytest backend/tests
```

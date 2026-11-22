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

The application supports EVTX uploads through the React interface and Flask
API. Uploaded files are stored in a Docker volume. EVTX parsing, database
storage, and event analysis will be added incrementally.

## Run the application

Start the frontend and backend with Docker Compose:

```bash
docker compose up --build
```

Open the upload interface at <http://localhost:5173>. The backend health
endpoint is available at <http://localhost:5000/api/health>.

To run the backend locally:

```bash
python -m pip install -r backend/requirements-dev.txt
python -m flask --app backend.app run
```

To run the frontend locally, use a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

The upload API accepts multipart form data with a `file` field and an `.evtx`
filename. Uploads are limited to 100 MB.

## Troubleshooting uploads

If the page displays "Failed to fetch", confirm both containers are running:

```bash
docker compose ps
docker compose up --build -d
```

Then reload <http://localhost:5173> and select the file again. The upload is
limited to 100 MB.

## Run tests

```bash
python -m pytest backend/tests
```

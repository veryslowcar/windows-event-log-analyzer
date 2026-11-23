# Windows Event Log Analyzer

A web application for uploading and analyzing Windows Event Log (`.evtx`) files. (Uploads are limited to 100 MB.)

## Planned technology

- **Frontend:** React
- **Backend:** Flask
- **Database:** SQLite
- **Containers:** Docker and Docker Compose
- **CI/CD:** Github Actions
- **Deployment:** Google Cloud Run

## Current status

The application uploads and summarizes EVTX files, then displays structured event
summaries in the dashboard. Locally uploaded files are stored in a Docker
volume. Database storage, filtering, and deeper event analysis will be added later on as this is just the beginning.
This is public, and the upload page doesn't require sign-in yet. Files that are uploaded will be lost after refreshing the page or leaving.

## Run the application

Start the frontend and backend with Docker Compose:

```bash
docker compose up --build
```

Open the upload interface at <http://localhost:5173>. The backend health
endpoint is available at <http://localhost:5000/api/health>.


## Deploying to Google Cloud Run

The project has 2 cloud configurations: `cloudbuild-backend.yaml` and `cloudbuild-frontend.yaml`.

1. In Google Cloud, create an Artifact Registry repository for the container
   images.
2. In Cloud Build, create a trigger for each configuration file. Run the
   backend trigger as the FIRST deployment, then the frontend trigger.
3. After setup, the repository will deploy the
   services automatically.


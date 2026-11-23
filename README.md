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

The application uploads and parses EVTX files, then displays structured event
summaries in the React dashboard. Uploaded files are stored in a Docker volume.
Database storage, filtering, and deeper event analysis will be added
incrementally.

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
filename. Uploads are limited to 100 MB. Successful responses include an
`events` array with event ID, timestamp, source, severity, and message fields
when available. Files that cannot be parsed return a processing error.

## Deploy to Google Cloud Run

The root `cloudbuild-backend.yaml` and `cloudbuild-frontend.yaml` independently
build, push, and deploy the public API and web services. The frontend proxies
`/api` requests to the backend service.

1. Select a Google Cloud project, enable billing, and enable the Cloud Build,
   Artifact Registry, and Cloud Run APIs.
2. Create the Artifact Registry Docker repository in the deployment region:

   ```bash
   gcloud artifacts repositories create windows-event-log-analyzer \
     --repository-format=docker \
     --location=us-central1
   ```

3. Give the Cloud Build trigger's service account permission to push images
   (`roles/artifactregistry.writer`) and deploy Cloud Run services
   (`roles/run.admin`), plus `roles/iam.serviceAccountUser` on the runtime
   service account.
4. In Cloud Build, create two triggers for the connected repository:
   - Backend trigger: select `cloudbuild-backend.yaml`.
   - Frontend trigger: select `cloudbuild-frontend.yaml`.

   For an initial deployment, run the backend trigger first; the frontend
   trigger looks up that Cloud Run service to configure its API proxy. Both
   configs share `_REGION` and `_AR_REPOSITORY`; keep those substitutions the
   same in both triggers. The backend service name is `_BACKEND_SERVICE`, and
   the frontend service name is `_FRONTEND_SERVICE`.

The configured services are publicly accessible. The upload endpoint currently
has no authentication or rate limiting; do not use this public configuration
for sensitive or production workloads until those protections are added.
Cloud Run's standard HTTP/1 request limit is 32 MiB, below the application's
100 MB upload limit. Large-file uploads need direct-to-Cloud-Storage upload
support (or a lower application limit). Uploaded files are stored on the
container filesystem and are not durable across Cloud Run instance restarts.
See the [Cloud Run quotas](https://cloud.google.com/run/quotas) and
[container filesystem](https://cloud.google.com/run/docs/container-contract#filesystem)
documentation.

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

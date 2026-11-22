import os
from uuid import uuid4

from flask import Flask
from flask import jsonify
from flask import request
from werkzeug.exceptions import RequestEntityTooLarge


MAX_UPLOAD_SIZE = 100 * 1024 * 1024


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        MAX_CONTENT_LENGTH=MAX_UPLOAD_SIZE + 1024 * 1024,
        MAX_UPLOAD_SIZE=MAX_UPLOAD_SIZE,
        UPLOAD_FOLDER=os.path.join(os.path.dirname(__file__), "uploads"),
    )
    if test_config:
        app.config.update(test_config)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(_error):
        return jsonify(error="The upload exceeds the 100 MB limit."), 413

    @app.post("/api/upload")
    def upload():
        uploaded_file = request.files.get("file")
        if uploaded_file is None or not uploaded_file.filename:
            return jsonify(error="Choose an .evtx file to upload."), 400

        if os.path.splitext(uploaded_file.filename)[1].lower() != ".evtx":
            return jsonify(error="Unsupported file format. Please choose an .evtx file."), 400

        uploaded_file.seek(0, os.SEEK_END)
        file_size = uploaded_file.tell()
        uploaded_file.seek(0)
        if file_size > app.config["MAX_UPLOAD_SIZE"]:
            return jsonify(error="The file exceeds the 100 MB limit."), 413

        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        upload_id = uuid4().hex
        uploaded_file.save(os.path.join(app.config["UPLOAD_FOLDER"], f"{upload_id}.evtx"))

        return jsonify(
            message="File uploaded successfully.",
            filename=uploaded_file.filename,
            upload_id=upload_id,
        ), 201

    return app


app = create_app()

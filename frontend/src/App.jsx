import React, { useRef, useState } from "react";

function App() {
  const fileInput = useRef(null);
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState(null);

  function chooseFile(event) {
    setFile(event.target.files?.[0] ?? null);
    setMessage(null);
  }

  async function uploadFile(event) {
    event.preventDefault();
    setMessage(null);

    if (!file) {
      setMessage({ type: "error", text: "Choose an .evtx file to continue." });
      return;
    }

    if (!file.name.toLowerCase().endsWith(".evtx")) {
      setMessage({ type: "error", text: "Unsupported file format. Please choose an .evtx file." });
      return;
    }

    const formData = new FormData();
    formData.append("file", file);
    setUploading(true);

    try {
      const response = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });
      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.error || "The file could not be uploaded.");
      }

      setMessage({ type: "success", text: `${result.filename} uploaded successfully.` });
      setFile(null);
      if (fileInput.current) {
        fileInput.current.value = "";
      }
    } catch (error) {
      setMessage({
        type: "error",
        text: error instanceof Error ? error.message : "The file could not be uploaded.",
      });
    } finally {
      setUploading(false);
    }
  }

  return (
    <main className="page-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="Windows Event Log Analyzer home">
          <span className="brand-mark" aria-hidden="true">W</span>
          <span>Event Log Analyzer</span>
        </a>
        <span className="topbar-note">Windows event diagnostics</span>
      </header>

      <section className="content">
        <div className="intro">
          <span className="eyebrow">LOG WORKSPACE</span>
          <h1>Make sense of your event logs.</h1>
          <p>Start by uploading a Windows Event Log file. Your file is stored by the application for analysis.</p>
        </div>

        <form className="upload-card" onSubmit={uploadFile} noValidate>
          <div className="card-heading">
            <div className="upload-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none">
                <path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5M5 14.5v4A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5v-4" />
              </svg>
            </div>
            <div>
              <h2>Upload an event log</h2>
              <p>Select an .evtx file from your computer to get started.</p>
            </div>
          </div>

          <label className="file-picker" htmlFor="event-log">
            <span className="file-name">{file ? file.name : "Choose a file to upload"}</span>
            <span className="browse-button">Browse files</span>
            <input
              ref={fileInput}
              id="event-log"
              type="file"
              accept=".evtx"
              onChange={chooseFile}
              aria-describedby="file-guidance"
            />
          </label>

          <div className="file-guidance" id="file-guidance">
            <span>Windows Event Log</span>
            <span>Maximum file size: 100 MB</span>
          </div>

          {message && (
            <div className={`feedback ${message.type}`} role={message.type === "error" ? "alert" : "status"}>
              {message.text}
            </div>
          )}

          <button className="submit-button" type="submit" disabled={uploading}>
            {uploading ? (
              <>
                <span className="spinner" aria-hidden="true" />
                Uploading…
              </>
            ) : (
              "Upload event log"
            )}
          </button>
        </form>

        <p className="privacy-note">
          <span aria-hidden="true">●</span> Files are kept in your application&apos;s local upload storage.
        </p>
      </section>
    </main>
  );
}

export default App;

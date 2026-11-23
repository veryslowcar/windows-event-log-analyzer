import React, { useEffect, useMemo, useRef, useState } from "react";

const EVENTS_PER_PAGE = 100;
const LONG_MESSAGE_THRESHOLD = 240;

function App() {
  const fileInput = useRef(null);
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState(null);
  const [summary, setSummary] = useState(null);
  const [uploadedLogs, setUploadedLogs] = useState([]);
  const [currentPage, setCurrentPage] = useState("upload");
  const [uploadProgress, setUploadProgress] = useState(0);
  const [processing, setProcessing] = useState(false);
  const [eventPage, setEventPage] = useState(0);

  useEffect(() => {
    function syncPage() {
      const isDashboard = window.location.pathname === "/dashboard";
      if (isDashboard && !summary) {
        window.history.replaceState(null, "", "/");
        setCurrentPage("upload");
        return;
      }

      setCurrentPage(isDashboard ? "dashboard" : "upload");
      if (!isDashboard) {
        setMessage(null);
      }
    }

    window.addEventListener("popstate", syncPage);
    syncPage();
    return () => window.removeEventListener("popstate", syncPage);
  }, [summary]);

  const dashboardStats = useMemo(() => {
    if (!summary) {
      return { errorCount: 0, warningCount: 0, informationalCount: 0 };
    }

    return summary.events.reduce(
      (counts, event) => {
        if (event.severity === "Critical" || event.severity === "Error") {
          counts.errorCount += 1;
        } else if (event.severity === "Warning") {
          counts.warningCount += 1;
        } else if (event.severity === "Information") {
          counts.informationalCount += 1;
        }
        return counts;
      },
      { errorCount: 0, warningCount: 0, informationalCount: 0 },
    );
  }, [summary]);
  const totalEvents = summary?.events.length ?? 0;
  const otherEventCount = Math.max(
    0,
    totalEvents
      - dashboardStats.errorCount
      - dashboardStats.warningCount
      - dashboardStats.informationalCount,
  );
  const donutBackground = useMemo(() => {
    if (totalEvents === 0) {
      return "conic-gradient(#e8ebf2 0% 100%)";
    }

    const segments = [
      { count: dashboardStats.errorCount, color: "#a43838" },
      { count: dashboardStats.warningCount, color: "#8a5a10" },
      { count: dashboardStats.informationalCount, color: "#276047" },
      { count: otherEventCount, color: "#4268d8" },
    ];
    let position = 0;
    const gradientStops = segments.map(({ count, color }) => {
      const start = position;
      position += (count / totalEvents) * 100;
      return `${color} ${start}% ${position}%`;
    });

    return `conic-gradient(${gradientStops.join(", ")})`;
  }, [dashboardStats, otherEventCount, totalEvents]);
  const pageCount = summary ? Math.ceil(summary.events.length / EVENTS_PER_PAGE) : 0;
  const pageStart = eventPage * EVENTS_PER_PAGE;
  const visibleEvents = summary
    ? summary.events.slice(pageStart, pageStart + EVENTS_PER_PAGE)
    : [];
  const eventLogType = useMemo(() => {
    if (!summary) {
      return null;
    }

    const channels = [...new Set(
      summary.events.map((event) => event.channel?.toLowerCase()).filter(Boolean),
    )];
    return channels.length === 1 ? channels[0] : null;
  }, [summary]);
  const isKnownEventLog = ["application", "security", "setup", "system"].includes(eventLogType);
  const isSecurityLog = eventLogType === "security";

  function chooseFile(event) {
    setFile(event.target.files?.[0] ?? null);
    setMessage(null);
    setEventPage(0);
  }

  function selectUploadedLog(event) {
    const selectedLog = uploadedLogs.find((log) => log.upload_id === event.target.value);
    if (selectedLog) {
      setSummary(selectedLog);
      setEventPage(0);
      setMessage(null);
    }
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
    setUploadProgress(0);
    setProcessing(false);
    setUploading(true);

    try {
      const result = await new Promise((resolve, reject) => {
        const request = new XMLHttpRequest();
        request.open("POST", "/api/upload");
        request.upload.addEventListener("progress", (progressEvent) => {
          if (progressEvent.lengthComputable) {
            setUploadProgress(Math.round((progressEvent.loaded / progressEvent.total) * 100));
          }
        });
        request.upload.addEventListener("load", () => setProcessing(true));
        request.addEventListener("load", () => {
          let response;
          try {
            response = JSON.parse(request.responseText);
          } catch {
            reject(new Error("The server returned an invalid upload response."));
            return;
          }

          if (request.status < 200 || request.status >= 300) {
            reject(new Error(response.error || "The file could not be processed."));
            return;
          }

          resolve(response);
        });
        request.addEventListener("error", () => {
          reject(new Error("The upload connection was interrupted. Check that the application is running and try again."));
        });
        request.addEventListener("abort", () => reject(new Error("The upload was cancelled.")));
        request.send(formData);
      });

      setUploadedLogs((logs) => [...logs, result]);
      setSummary(result);
      setEventPage(0);
      setMessage({
        type: "success",
        text: `${result.filename} processed. ${result.event_count} event${result.event_count === 1 ? "" : "s"} found.`,
      });
      if (window.location.pathname !== "/dashboard") {
        window.history.pushState(null, "", "/dashboard");
      }
      setCurrentPage("dashboard");
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
      setProcessing(false);
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

      <section className={`content ${currentPage === "dashboard" ? "dashboard-content" : ""}`}>
        {currentPage === "upload" && (
          <>
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
                  disabled={uploading}
                  aria-describedby="file-guidance"
                />
              </label>

              <div className="file-guidance" id="file-guidance">
                <span>Windows Event Log</span>
                <span>Maximum file size: 100 MB</span>
              </div>

              {uploading && (
                <div className="upload-progress" role="status" aria-live="polite">
                  <div className={`upload-progress-track ${processing ? "processing" : ""}`} aria-hidden="true">
                    <div
                      className="upload-progress-bar"
                      style={processing ? undefined : { width: `${uploadProgress}%` }}
                    />
                  </div>
                  <span>
                    {processing ? "Upload complete. Processing event records…" : `Uploading file… ${uploadProgress}%`}
                  </span>
                </div>
              )}

              {message && (
                <div className={`feedback ${message.type}`} role={message.type === "error" ? "alert" : "status"}>
                  {message.text}
                </div>
              )}

              <button className="submit-button" type="submit" disabled={uploading}>
                {uploading ? (
                  <>
                    <span className="spinner" aria-hidden="true" />
                    {processing ? "Processing log…" : `Uploading ${uploadProgress}%…`}
                  </>
                ) : (
                  "Upload event log"
                )}
              </button>
            </form>

            <p className="privacy-note">
              <span aria-hidden="true">●</span> Files are kept in your application&apos;s local upload storage.
            </p>
          </>
        )}

        {currentPage === "dashboard" && summary && (
          <>
            <div className="dashboard-page-heading">
              <div>
                <span className="eyebrow">ANALYSIS DASHBOARD</span>
                <h1>Event log dashboard</h1>
                <p>Review the summarized events from your uploaded Windows Event Log.</p>
              </div>
            </div>

            <div className="dashboard-log-actions">
              <div className="log-switcher">
                <label htmlFor="uploaded-log-select">Uploaded logs ({uploadedLogs.length})</label>
                <select
                  id="uploaded-log-select"
                  value={summary.upload_id}
                  onChange={selectUploadedLog}
                  aria-label="Select an uploaded log"
                >
                  {uploadedLogs.map((log, index) => (
                    <option key={log.upload_id} value={log.upload_id}>
                      {index + 1}. {log.filename} — {log.event_count} events
                    </option>
                  ))}
                </select>
              </div>
              <form className="dashboard-upload" onSubmit={uploadFile} noValidate>
                <label className="dashboard-file-picker" htmlFor="event-log">
                  <span className="file-name">{file ? file.name : "Choose another .evtx file"}</span>
                  <span className="dashboard-browse-button">Browse</span>
                  <input
                    ref={fileInput}
                    id="event-log"
                    type="file"
                    accept=".evtx"
                    onChange={chooseFile}
                    disabled={uploading}
                    aria-label="Choose another EVTX file"
                  />
                </label>
                <button className="dashboard-upload-button" type="submit" disabled={uploading || !file}>
                  {uploading ? (
                    <>
                      <span className="spinner" aria-hidden="true" />
                      {processing ? "Processing log…" : `Uploading ${uploadProgress}%…`}
                    </>
                  ) : (
                    "Upload another log"
                  )}
                </button>
                {uploading && (
                  <div className="upload-progress" role="status" aria-live="polite">
                    <div className={`upload-progress-track ${processing ? "processing" : ""}`} aria-hidden="true">
                      <div
                        className="upload-progress-bar"
                        style={processing ? undefined : { width: `${uploadProgress}%` }}
                      />
                    </div>
                    <span>
                      {processing ? "Upload complete. Processing event records…" : `Uploading file… ${uploadProgress}%`}
                    </span>
                  </div>
                )}
                {message && (
                  <div className={`feedback ${message.type}`} role={message.type === "error" ? "alert" : "status"}>
                    {message.text}
                  </div>
                )}
              </form>
            </div>

            <section className="summary-card" aria-labelledby="summary-heading">
              <div className="summary-header">
                <div>
                  <span className="eyebrow">UPLOADED LOG</span>
                  <h2 id="summary-heading">{summary.filename}</h2>
                </div>
              </div>

              <div className="dashboard-overview" role="group" aria-label="Event totals and severity distribution">
                <div
                  className="dashboard-donut"
                  role="img"
                  aria-label={`Event distribution: ${dashboardStats.errorCount} errors, ${dashboardStats.warningCount} warnings, ${dashboardStats.informationalCount} informational, ${otherEventCount} other`}
                  style={{ background: donutBackground }}
                >
                  <div className="dashboard-donut-center">
                    <span>Total events</span>
                    <strong>{totalEvents}</strong>
                  </div>
                </div>
                <div className="dashboard-stat-list">
                  <div className="dashboard-stat-row error-stat">
                    <span className="dashboard-stat-swatch" aria-hidden="true" />
                    <span>Errors</span>
                    <strong>{dashboardStats.errorCount}</strong>
                  </div>
                  <div className="dashboard-stat-row warning-stat">
                    <span className="dashboard-stat-swatch" aria-hidden="true" />
                    <span>Warnings</span>
                    <strong>{dashboardStats.warningCount}</strong>
                  </div>
                  <div className="dashboard-stat-row information-stat">
                    <span className="dashboard-stat-swatch" aria-hidden="true" />
                    <span>Informational</span>
                    <strong>{dashboardStats.informationalCount}</strong>
                  </div>
                  <div className="dashboard-stat-row other-stat">
                    <span className="dashboard-stat-swatch" aria-hidden="true" />
                    <span>Other events</span>
                    <strong>{otherEventCount}</strong>
                  </div>
                </div>
              </div>

              {summary.events.length > 0 ? (
                <>
                  <h3 className="event-table-heading" id="event-table-heading">Event details</h3>
                  <div
                    className="event-table-scroll"
                    role="region"
                    aria-labelledby="event-table-heading"
                    tabIndex={0}
                  >
                    <table className={`event-table ${isKnownEventLog ? "event-viewer-table" : ""}`}>
                      <thead>
                        <tr>
                          {isKnownEventLog ? (
                            <th scope="col">{isSecurityLog ? "Keywords" : "Level"}</th>
                          ) : (
                            <th scope="col">Event ID</th>
                          )}
                          <th scope="col">Date and Time</th>
                          <th scope="col">Source</th>
                          {isKnownEventLog ? (
                            <>
                              <th scope="col">Event ID</th>
                              <th scope="col">Task Category</th>
                            </>
                          ) : (
                            <th scope="col">Severity</th>
                          )}
                          <th scope="col">Message</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visibleEvents.map((event, index) => {
                          const messageContent = isKnownEventLog ? (
                            event.message ? (
                              <details className="message-details">
                                <summary>
                                  {event.message.length > LONG_MESSAGE_THRESHOLD ? "View full message" : "View message"}
                                </summary>
                                <pre>{event.message}</pre>
                              </details>
                            ) : (
                              "No message available"
                            )
                          ) : event.message && event.message.length > LONG_MESSAGE_THRESHOLD ? (
                            <details className="message-details">
                              <summary>View full message</summary>
                              <pre>{event.message}</pre>
                            </details>
                          ) : (
                            event.message ?? "No message available"
                          );

                          return (
                            <tr key={`${event.timestamp ?? "unknown"}-${event.event_id ?? "unknown"}-${pageStart + index}`}>
                              <td>
                                {isKnownEventLog ? (
                                  isSecurityLog ? event.keywords || "—" : (
                                    <span className={`severity-badge ${event.severity.toLowerCase()}`}>
                                      {event.severity}
                                    </span>
                                  )
                                ) : (
                                  event.event_id ?? "—"
                                )}
                              </td>
                              <td>{event.timestamp ?? "—"}</td>
                              <td>{event.source ?? "—"}</td>
                              <td>
                                {isKnownEventLog ? (
                                  event.event_id ?? "—"
                                ) : (
                                  <span className={`severity-badge ${event.severity.toLowerCase()}`}>
                                    {event.severity}
                                  </span>
                                )}
                              </td>
                              {isKnownEventLog && <td>{event.task_category || "—"}</td>}
                              <td className="message-cell">{messageContent}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                    <div className="event-pagination">
                      <span>
                        Showing {pageStart + 1}–{Math.min(pageStart + EVENTS_PER_PAGE, summary.events.length)} of{" "}
                        {summary.events.length} events
                      </span>
                      {pageCount > 1 && (
                        <div className="pagination-controls">
                          <button
                            type="button"
                            onClick={() => setEventPage((page) => page - 1)}
                            disabled={eventPage === 0}
                          >
                            Previous
                          </button>
                          <span>
                            Page {eventPage + 1} of {pageCount}
                          </span>
                          <button
                            type="button"
                            onClick={() => setEventPage((page) => page + 1)}
                            disabled={eventPage === pageCount - 1}
                          >
                            Next
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </>
              ) : (
                <p className="empty-events">No events were found in this log.</p>
              )}
            </section>
          </>
        )}
      </section>
    </main>
  );
}

export default App;

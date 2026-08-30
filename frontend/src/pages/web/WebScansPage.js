import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { io } from "socket.io-client";
import { API_BASE_URL } from "../../api";
import webApi from "../../webApi";
import Badge from "../../components/ui/Badge";
import Button from "../../components/ui/Button";
import { getStoredToken, hasPermission } from "../../auth";

const STAGES = [
  "VALIDATING",
  "DISCOVERING",
  "CRAWLING",
  "SCANNING",
  "ANALYZING",
  "FINALIZING",
  "COMPLETED",
];

export function renderScanStatusBadge(scan) {
  if (!scan) return null;
  const status = (scan.status || "UNKNOWN").toUpperCase();

  if (status !== "PARTIAL") {
    return (
      <Badge
        tone={
          status === "COMPLETED"
            ? "ok"
            : status === "FAILED"
            ? "danger"
            : status === "RUNNING"
            ? "info"
            : "warn"
        }
      >
        {status}
      </Badge>
    );
  }

  // Parse error_message to surface which engines were skipped/unavailable
  const notes = scan.error_message || "";
  const skipped = [];
  if (/nmap/i.test(notes)) skipped.push("Nmap");
  if (/nuclei/i.test(notes)) skipped.push("Nuclei");
  if (/zap/i.test(notes)) skipped.push("ZAP");

  const label = skipped.length > 0
    ? `PARTIAL (${skipped.join(", ")} skipped)`
    : "PARTIAL (sub-engines skipped)";

  return (
    <Badge
      tone="warn"
      title={notes ? `Partial scan: ${notes}` : "Scan completed with some engines skipped"}
      style={{ cursor: notes ? "help" : "default" }}
    >
      {label}
    </Badge>
  );
}

export default function WebScansPage() {
  const canRun = hasPermission("webscan.run");
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const preselect = params.get("target") || "";

  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [error, setError] = useState("");
  const [wizard, setWizard] = useState({
    step: 1,
    target_id: preselect,
    profile: "QUICK",
    confirm: false,
  });
  const [activeScan, setActiveScan] = useState(null);
  const [compareId, setCompareId] = useState("");
  const [comparison, setComparison] = useState(null);

  const authorizedTargets = useMemo(
    () =>
      (targets || []).filter(
        (t) => (t.authorization_status || "").toUpperCase() === "AUTHORIZED" && t.enabled
      ),
    [targets]
  );

  const load = useCallback(async () => {
    try {
      const [t, s] = await Promise.all([webApi.getTargets(), webApi.getScans({ limit: 50 })]);
      setTargets(t.data.targets || []);
      setScans(s.data.scans || []);
    } catch (err) {
      setError(err.response?.data?.error?.message || "Failed to load scans.");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (preselect) setWizard((w) => ({ ...w, target_id: preselect, step: 2 }));
  }, [preselect]);

  // Live progress via Socket.IO + polling fallback
  useEffect(() => {
    if (!activeScan?.id) return undefined;
    const token = getStoredToken();
    // Connect via API_BASE_URL if set, or fall back to current origin (Nginx proxy)
    const socketURL = API_BASE_URL || window.location.origin;
    const socket = io(socketURL, {

      path: "/socket.io/",
      transports: ["websocket", "polling"],
      auth: token ? { token } : undefined,
    });
    const onProgress = (payload) => {
      if (payload?.scan_id !== activeScan.id) return;
      setActiveScan((prev) =>
        prev
          ? {
              ...prev,
              progress: payload.progress,
              current_stage: payload.stage,
              findings_count: payload.findings_count ?? prev.findings_count,
              status: ["COMPLETED", "FAILED", "CANCELLED"].includes(payload.stage)
                ? payload.stage
                : "RUNNING",
            }
          : prev
      );
    };
    const onDone = (payload) => {
      if (payload?.scan_id !== activeScan.id) return;
      webApi.getScan(activeScan.id).then((res) => {
        setActiveScan(res.data);
        load();
      });
    };
    socket.on("web_scan_progress", onProgress);
    socket.on("web_scan_stage", onProgress);
    socket.on("web_scan_completed", onDone);
    socket.on("web_scan_failed", onDone);
    socket.on("web_scan_cancelled", onDone);

    const poll = setInterval(async () => {
      try {
        const res = await webApi.getScanProgress(activeScan.id);
        setActiveScan((prev) =>
          prev
            ? {
                ...prev,
                ...res.data,
                current_stage: res.data.stage || prev.current_stage,
              }
            : prev
        );
        if (["COMPLETED", "FAILED", "CANCELLED"].includes(res.data.status)) {
          const full = await webApi.getScan(activeScan.id);
          setActiveScan(full.data);
          load();
        }
      } catch {
        /* ignore transient poll errors */
      }
    }, 2000);

    return () => {
      clearInterval(poll);
      socket.disconnect();
    };
  }, [activeScan?.id, load]);

  const startScan = async () => {
    setError("");
    if (!wizard.confirm) {
      setError("Confirm authorization acknowledgment before starting.");
      return;
    }
    try {
      const res = await webApi.createScan({
        target_id: Number(wizard.target_id),
        profile: wizard.profile,
        confirm: true,
      });
      setActiveScan(res.data);
      setWizard({ step: 1, target_id: "", profile: "QUICK", confirm: false });
      await load();
      // Open Website Map immediately so the tree grows live
      navigate(`/webscan/map?scan=${res.data.id}`);
    } catch (err) {
      setError(err.response?.data?.error?.message || "Failed to start scan.");
    }
  };

  const cancel = async (id) => {
    await webApi.cancelScan(id);
    await load();
    if (activeScan?.id === id) {
      const res = await webApi.getScan(id);
      setActiveScan(res.data);
    }
  };

  const runCompare = async (scanId) => {
    if (!compareId) return;
    try {
      const res = await webApi.compareScans(scanId, Number(compareId));
      setComparison(res.data);
    } catch (err) {
      setError(err.response?.data?.error?.message || "Compare failed.");
    }
  };

  const selectedTarget = authorizedTargets.find(
    (t) => String(t.id) === String(wizard.target_id)
  );

  const latestTargetScan = useMemo(() => {
    if (!wizard.target_id) return null;
    return scans.find((s) => String(s.target_id) === String(wizard.target_id)) || null;
  }, [wizard.target_id, scans]);

  const downloadReportPdf = (scanId, targetName = "Target") => {
    const token = getStoredToken();
    const bust = Date.now();
    const baseUrl = API_BASE_URL || window.location.origin;
    window.open(
      `${baseUrl}/api/web-scans/${scanId}/report.pdf?token=${encodeURIComponent(token)}&v=${bust}`,
      "_blank",
      "noopener,noreferrer"
    );
  };


  return (
    <div className="websec__stack">
      {error ? <div className="surface websec__panel error-text">{error}</div> : null}

      {canRun ? (
        <div className="surface websec__panel">
          <h2>Scan wizard</h2>
          <div className="websec__wizard-steps">
            {[1, 2, 3, 4, 5].map((n) => (
              <span
                key={n}
                className={`websec__step${wizard.step === n ? " is-active" : ""}`}
              >
                {n}
              </span>
            ))}
          </div>

          {wizard.step === 1 ? (
            <div>
              <p>Select an AUTHORIZED target.</p>
              <select
                className="field__input"
                value={wizard.target_id}
                onChange={(e) =>
                  setWizard({ ...wizard, target_id: e.target.value })
                }
              >
                <option value="">Choose target…</option>
                {authorizedTargets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} — {t.url}
                  </option>
                ))}
              </select>
              {selectedTarget ? (
                <div
                  style={{
                    marginTop: 12,
                    padding: "12px 14px",
                    background: "rgba(31, 111, 139, 0.08)",
                    border: "1px solid rgba(31, 111, 139, 0.25)",
                    borderRadius: 6,
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    flexWrap: "wrap",
                    gap: 8,
                  }}
                >
                  <div>
                    <strong style={{ color: "var(--color-text, #fff)" }}>
                      {selectedTarget.name}
                    </strong>{" "}
                    <span className="muted">({selectedTarget.url})</span>
                    {latestTargetScan ? (
                      <div style={{ fontSize: "0.85rem", marginTop: 4 }} className="muted">
                        Latest Assessment: Scan #{latestTargetScan.id} · {renderScanStatusBadge(latestTargetScan)} · Risk: {latestTargetScan.risk_score || 0}/100 · {latestTargetScan.findings_count || 0} findings
                      </div>
                    ) : (
                      <div style={{ fontSize: "0.85rem", marginTop: 4 }} className="muted">
                        No previous scan completed yet for this target.
                      </div>
                    )}
                  </div>
                  {latestTargetScan ? (
                    <Button
                      size="sm"
                      variant="primary"
                      onClick={() => downloadReportPdf(latestTargetScan.id, selectedTarget.name)}
                    >
                      📄 Download Report (PDF)
                    </Button>
                  ) : null}
                </div>
              ) : null}
              <div className="websec__actions">

                <Button
                  variant="primary"
                  disabled={!wizard.target_id}
                  onClick={() => setWizard({ ...wizard, step: 2 })}
                >
                  Next
                </Button>
              </div>
            </div>
          ) : null}

          {wizard.step === 2 ? (
            <div>
              <p>Select scan profile.</p>
              {["QUICK", "STANDARD", "DEEP", "PASSIVE", "API", "AUTHENTICATED", "LAB"].map((p) => (
                <label key={p} className="websec__radio">
                  <input
                    type="radio"
                    name="profile"
                    checked={wizard.profile === p}
                    onChange={() => setWizard({ ...wizard, profile: p })}
                  />
                  <span>
                    <strong>{p}</strong>
                    <span className="muted">
                      {p === "QUICK" && " — discovery + sitemap + crawl + API paths"}
                      {p === "STANDARD" && " — Quick + Nuclei"}
                      {p === "DEEP" && " — Standard + Nmap + ZAP (lab/safety gated)"}
                      {p === "PASSIVE" && " — TLS/headers/sitemap only (no crawl)"}
                      {p === "API" && " — API/OpenAPI + sitemap oriented"}
                      {p === "AUTHENTICATED" && " — crawl/API with auth profile intent"}
                      {p === "LAB" && " — aggressive lab profile"}
                    </span>
                  </span>
                </label>
              ))}
              <div className="websec__actions">
                <Button onClick={() => setWizard({ ...wizard, step: 1 })}>Back</Button>
                <Button variant="primary" onClick={() => setWizard({ ...wizard, step: 3 })}>
                  Next
                </Button>
              </div>
            </div>
          ) : null}

          {wizard.step === 3 ? (
            <div>
              <p>Safe options (no raw scanner flags).</p>
              <ul className="muted">
                <li>SSRF validation and DNS checks always enforced</li>
                <li>Bounded crawl depth / URL limits</li>
                <li>Missing engines are skipped without failing the scan</li>
              </ul>
              <div className="websec__actions">
                <Button onClick={() => setWizard({ ...wizard, step: 2 })}>Back</Button>
                <Button variant="primary" onClick={() => setWizard({ ...wizard, step: 4 })}>
                  Next
                </Button>
              </div>
            </div>
          ) : null}

          {wizard.step === 4 ? (
            <div>
              <p className="warn-text">
                Confirm you are authorized to assess this asset.
              </p>
              <div className="websec__confirm-box">
                <div>
                  <strong>Target:</strong> {selectedTarget?.name}
                </div>
                <div className="websec__mono">{selectedTarget?.url}</div>
                <div>
                  <strong>Profile:</strong> {wizard.profile}
                </div>
                <div>
                  <strong>Authorization:</strong> {selectedTarget?.authorization_status}
                </div>
              </div>
              <label className="websec__radio">
                <input
                  type="checkbox"
                  checked={wizard.confirm}
                  onChange={(e) =>
                    setWizard({ ...wizard, confirm: e.target.checked })
                  }
                />
                I confirm explicit authorization to scan this target.
              </label>
              <div className="websec__actions">
                <Button onClick={() => setWizard({ ...wizard, step: 3 })}>Back</Button>
                <Button
                  variant="primary"
                  disabled={!wizard.confirm}
                  onClick={() => setWizard({ ...wizard, step: 5 })}
                >
                  Next
                </Button>
              </div>
            </div>
          ) : null}

          {wizard.step === 5 ? (
            <div>
              <p>
                Ready to start {wizard.profile} scan against <strong>{selectedTarget?.name}</strong> ({selectedTarget?.url}). Progress updates live.
              </p>
              {latestTargetScan ? (
                <div style={{ marginBottom: 14 }}>
                  <span className="muted" style={{ fontSize: "0.9rem" }}>
                    Previous report on file: Scan #{latestTargetScan.id} ({latestTargetScan.findings_count || 0} findings) ·{" "}
                  </span>
                  <Button
                    size="sm"
                    onClick={() => downloadReportPdf(latestTargetScan.id, selectedTarget?.name)}
                  >
                    📄 Download Previous Report (PDF)
                  </Button>
                </div>
              ) : null}
              <div className="websec__actions">
                <Button onClick={() => setWizard({ ...wizard, step: 4 })}>Back</Button>
                <Button variant="primary" onClick={startScan}>
                  Start scan
                </Button>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}

      {activeScan ? (
        <div className="surface websec__panel">
          <div className="websec__row">
            <h2>Live scan #{activeScan.id}</h2>
            <Button
              size="sm"
              onClick={() => navigator.clipboard?.writeText(String(activeScan.id))}
            >
              Copy ID
            </Button>
          </div>
          <div className="websec__kpi-grid">
            <div className="websec__kpi">
              <div className="websec__kpi-label">Stage</div>
              <div>{activeScan.current_stage || activeScan.stage || "—"}</div>
            </div>
            <div className="websec__kpi">
              <div className="websec__kpi-label">Progress</div>
              <div>{activeScan.progress ?? 0}%</div>
            </div>
            <div className="websec__kpi">
              <div className="websec__kpi-label">Findings</div>
              <div>{activeScan.findings_count ?? 0}</div>
            </div>
            <div className="websec__kpi">
              <div className="websec__kpi-label">Status</div>
              {renderScanStatusBadge(activeScan)}
            </div>
          </div>
          <div className="websec__timeline">
            {STAGES.map((s) => (
              <span
                key={s}
                className={`websec__tl-item${
                  (activeScan.current_stage || "") === s ||
                  (activeScan.status === "COMPLETED" && s === "COMPLETED")
                    ? " is-active"
                    : ""
                }`}
              >
                {s}
              </span>
            ))}
          </div>
          <div className="websec__progress">
            <div
              className="websec__progress-bar"
              style={{ width: `${activeScan.progress || 0}%` }}
            />
          </div>
          {activeScan.error_message ? (
            <p className="muted">Notes: {activeScan.error_message}</p>
          ) : null}
          {activeScan.status === "RUNNING" || activeScan.status === "PENDING" ? (
            <Button variant="danger" size="sm" onClick={() => cancel(activeScan.id)}>
              Cancel scan
            </Button>
          ) : null}
          {activeScan.status === "COMPLETED" || activeScan.status === "PARTIAL" || (activeScan.findings_count || 0) > 0 ? (
            <div className="websec__actions">
              <Link to={`/webscan/map?scan=${activeScan.id}`}>Website Map</Link>
              <Link to={`/webscan/findings?scan=${activeScan.id}`}>View findings</Link>
              <Button
                size="sm"
                variant="primary"
                onClick={() =>
                  downloadReportPdf(
                    activeScan.id,
                    activeScan.target?.name || selectedTarget?.name || "Target"
                  )
                }
              >
                📄 Download Report (PDF)
              </Button>
              <Button
                size="sm"
                onClick={async () => {
                  const res = await webApi.getScanReport(activeScan.id, "json");
                  const blob = new Blob([JSON.stringify(res.data, null, 2)], {
                    type: "application/json",
                  });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `webscan_${activeScan.id}.json`;
                  a.click();
                }}
              >
                Export JSON
              </Button>
              <Button
                size="sm"
                onClick={() => {
                  const token = getStoredToken();
                  const bust = Date.now();
                  const baseUrl = API_BASE_URL || window.location.origin;
                  window.open(
                    `${baseUrl}/api/web-scans/${activeScan.id}/report?format=csv&token=${encodeURIComponent(token)}&v=${bust}`,
                    "_blank",
                    "noopener,noreferrer"
                  );
                }}
              >
                Export CSV
              </Button>
            </div>
          ) : null}

          {["FAILED", "CANCELLED", "PARTIAL"].includes(activeScan.status) && canRun ? (
            <Button
              size="sm"
              onClick={async () => {
                const res = await webApi.resumeScan(activeScan.id);
                setActiveScan(res.data);
              }}
            >
              Resume scan
            </Button>
          ) : null}
        </div>
      ) : null}

      <div className="surface websec__panel">
        <h2>Scan history</h2>
        <div className="websec__table-wrap">
          <table className="websec__table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Target</th>
                <th>Profile</th>
                <th>Status</th>
                <th>Progress</th>
                <th>Findings</th>
                <th>Risk</th>
                <th>Started</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id}>
                  <td>{s.id}</td>
                  <td>{s.target_id}</td>
                  <td>{s.scan_profile}</td>
                  <td>
                    {renderScanStatusBadge(s)}
                  </td>
                  <td>{s.progress ?? 0}%</td>
                  <td>{s.findings_count}</td>
                  <td>{s.risk_score}</td>
                  <td>{s.started_at ? new Date(s.started_at).toLocaleString() : "—"}</td>
                  <td className="websec__actions-cell">
                    <Button size="sm" onClick={() => setActiveScan(s)}>
                      Open
                    </Button>
                    <Button
                      size="sm"
                      onClick={() => navigate(`/webscan/map?scan=${s.id}`)}
                    >
                      Map
                    </Button>
                    <Button
                      size="sm"
                      variant="primary"
                      onClick={() =>
                        downloadReportPdf(
                          s.id,
                          targets.find((t) => String(t.id) === String(s.target_id))?.name
                        )
                      }
                    >
                      PDF
                    </Button>
                    {(s.status === "RUNNING" || s.status === "PENDING") && canRun ? (

                      <Button size="sm" variant="danger" onClick={() => cancel(s.id)}>
                        Cancel
                      </Button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {activeScan?.status === "COMPLETED" ? (
          <div style={{ marginTop: 16 }}>
            <h3>Compare with previous scan</h3>
            <div className="websec__form-grid">
              <input
                className="field__input"
                placeholder="Other scan ID"
                value={compareId}
                onChange={(e) => setCompareId(e.target.value)}
              />
              <Button onClick={() => runCompare(activeScan.id)}>Compare</Button>
            </div>
            {comparison ? (
              <div className="websec__kpi-grid" style={{ marginTop: 12 }}>
                <div className="websec__kpi">
                  <div className="websec__kpi-label">Previous</div>
                  <div>{comparison.previous_count}</div>
                </div>
                <div className="websec__kpi">
                  <div className="websec__kpi-label">Current</div>
                  <div>{comparison.current_count}</div>
                </div>
                <div className="websec__kpi">
                  <div className="websec__kpi-label">New</div>
                  <div>{comparison.new_count}</div>
                </div>
                <div className="websec__kpi">
                  <div className="websec__kpi-label">Resolved</div>
                  <div>{comparison.resolved_count}</div>
                </div>
                <div className="websec__kpi">
                  <div className="websec__kpi-label">Net</div>
                  <div>{comparison.net_change}</div>
                </div>
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

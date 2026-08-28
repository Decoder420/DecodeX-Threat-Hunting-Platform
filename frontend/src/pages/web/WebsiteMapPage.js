import React, { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { io } from "socket.io-client";
import { API_BASE_URL } from "../../api";
import webApi from "../../webApi";
import Badge from "../../components/ui/Badge";
import Button from "../../components/ui/Button";
import { getStoredToken } from "../../auth";
import WebsiteMap, { upsertTreeNode } from "./WebsiteMap";

export default function WebsiteMapPage() {
  const { targetId } = useParams();
  const [params, setParams] = useSearchParams();
  const scanParam = params.get("scan");
  const navigate = useNavigate();

  const [data, setData] = useState(null);
  const [tree, setTree] = useState(null);
  const [selected, setSelected] = useState(null);
  const [findings, setFindings] = useState([]);
  const [events, setEvents] = useState([]);
  const [error, setError] = useState("");
  const [scan, setScan] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const applyScanId = useCallback(
    (id) => {
      const next = new URLSearchParams(params);
      next.set("scan", String(id));
      setParams(next, { replace: true });
    },
    [params, setParams]
  );

  const loadScanBundle = useCallback(async (scanId) => {
    const [t, e, s] = await Promise.all([
      webApi.getScanTree(scanId),
      webApi.getScanEvents(scanId).catch(() => ({ data: { events: [] } })),
      webApi.getScan(scanId),
    ]);
    setTree(t.data);
    setEvents(e.data.events || []);
    setScan(s.data);
    setData({
      scan: s.data,
      target: s.data.target,
      scan_id: Number(scanId),
    });
    return s.data;
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      if (scanParam) {
        await loadScanBundle(scanParam);
      } else if (targetId) {
        const res = await webApi.getTargetAttackSurface(targetId);
        setData(res.data);
        setTree(res.data.tree);
        setScan(res.data.scan);
        if (res.data.scan_id) {
          applyScanId(res.data.scan_id);
          const ev = await webApi.getScanEvents(res.data.scan_id).catch(() => ({
            data: { events: [] },
          }));
          setEvents(ev.data.events || []);
        } else {
          setError(
            "No scans yet for this target. Start a scan from Scans, then open Website Map."
          );
        }
      } else {
        // Default: latest scan so /webscan/map always has something to show
        const list = await webApi.getScans({ limit: 20 });
        const scans = list.data.scans || [];
        setRecentScans(scans);
        const latest = scans[0];
        if (latest?.id) {
          applyScanId(latest.id);
          await loadScanBundle(latest.id);
        } else {
          setError("No scans found. Authorize a target and start a scan first.");
        }
      }
    } catch (err) {
      setError(
        err.response?.data?.error?.message ||
          "Failed to load website map. Is the backend running on port 5000?"
      );
    } finally {
      setLoading(false);
    }
  }, [targetId, scanParam, loadScanBundle, applyScanId]);

  useEffect(() => {
    load();
  }, [load]);

  // Poll tree while running (works even if Socket.IO drops)
  useEffect(() => {
    const sid = scan?.id || data?.scan_id || (scanParam ? Number(scanParam) : null);
    if (!sid) return undefined;
    const isTerminal = ["COMPLETED", "FAILED", "CANCELLED", "PARTIAL"].includes(scan?.status);
    if (isTerminal) return undefined;


    const tick = async () => {
      try {
        const [progress, treeRes, ev] = await Promise.all([
          webApi.getScanProgress(sid),
          webApi.getScanTree(sid),
          webApi.getScanEvents(sid).catch(() => ({ data: { events: [] } })),
        ]);
        setTree(treeRes.data);
        setEvents(ev.data.events || []);
        setScan((prev) =>
          prev
            ? {
                ...prev,
                ...progress.data,
                current_stage: progress.data.stage || prev.current_stage,
                progress: progress.data.progress,
                status: progress.data.status,
                findings_count: progress.data.findings_count,
                nodes_count: progress.data.discovered_urls ?? prev.nodes_count,
              }
            : {
                id: sid,
                ...progress.data,
                current_stage: progress.data.stage,
              }
        );
        if (["COMPLETED", "FAILED", "CANCELLED", "PARTIAL"].includes(progress.data.status)) {
          await loadScanBundle(sid);
        }
      } catch {
        /* ignore transient poll errors */
      }
    };

    tick();
    const id = setInterval(tick, 2000);
    return () => clearInterval(id);
  }, [scan?.id, scan?.status, data?.scan_id, scanParam, loadScanBundle]);

  // Live Socket.IO node inserts
  useEffect(() => {
    const sid = scan?.id || data?.scan_id || (scanParam ? Number(scanParam) : null);
    if (!sid) return undefined;
    if (!["RUNNING", "PENDING", "CANCELLING"].includes(scan?.status || "RUNNING")) {
      // Still connect briefly for late events when status unknown
    }

    // Connect via API_BASE_URL if set, or fall back to current origin (Nginx proxy)
    const socketURL = API_BASE_URL || window.location.origin;
    const socket = io(socketURL, {

      path: "/socket.io/",
      transports: ["websocket", "polling"],
      auth: getStoredToken() ? { token: getStoredToken() } : undefined,
    });

    const onNode = (payload) => {
      if (payload?.scan_id !== sid) return;
      if (payload.node) setTree((prev) => upsertTreeNode(prev, payload.node));
    };
    const onLog = (payload) => {
      if (payload?.scan_id !== sid) return;
      setEvents((prev) => [...prev, payload].slice(-400));
    };
    const onFinding = (payload) => {
      if (payload?.scan_id !== sid) return;
      setFindings((prev) => [payload, ...prev].slice(0, 50));
    };
    const onProgress = (payload) => {
      if (payload?.scan_id !== sid) return;
      setScan((prev) =>
        prev
          ? {
              ...prev,
              progress: payload.progress,
              current_stage: payload.stage,
              findings_count: payload.findings_count ?? prev.findings_count,
              nodes_count: payload.nodes_count ?? prev.nodes_count,
              status: ["COMPLETED", "FAILED", "CANCELLED", "PARTIAL"].includes(payload.stage)
                ? payload.stage
                : "RUNNING",
            }
          : prev
      );
    };

    socket.on("webscan_node_discovered", onNode);
    socket.on("web_scan_node_discovered", onNode);
    socket.on("webscan_node_updated", onNode);
    socket.on("webscan_log", onLog);
    socket.on("web_scan_log", onLog);
    socket.on("webscan_finding_discovered", onFinding);
    socket.on("web_scan_finding", onFinding);
    socket.on("webscan_progress", onProgress);
    socket.on("web_scan_progress", onProgress);
    socket.on("webscan_completed", () => loadScanBundle(sid));
    socket.on("web_scan_completed", () => loadScanBundle(sid));
    socket.on("webscan_failed", () => loadScanBundle(sid));

    return () => socket.disconnect();
  }, [scan?.id, scan?.status, data?.scan_id, scanParam, loadScanBundle]);

  const onSelectNode = async (node) => {
    setSelected(node);
    try {
      const res = await webApi.getFindings({
        scan_id: scan?.id || data?.scan_id || scanParam,
        q: node.url || node.label,
        limit: 50,
      });
      const matched = (res.data.findings || []).filter(
        (f) =>
          f.node_id === node.id ||
          (f.affected_url || f.url || "").includes(node.label)
      );
      setFindings(matched.length ? matched : res.data.findings || []);
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="websec__stack">
      <div className="websec__row">
        <div>
          <h2>Website Map</h2>
          <p className="muted">
            {data?.target?.name || scan?.target?.name || "Attack surface"} · scan #
            {scan?.id || data?.scan_id || scanParam || "—"}
            {scan?.status ? (
              <>
                {" "}
                <Badge>{scan.status}</Badge> {scan.progress ?? 0}% ·{" "}
                {scan.current_stage || scan.stage}
              </>
            ) : null}
          </p>
        </div>
        <div className="websec__actions">
          <Link to="/webscan/targets">Targets</Link>
          <Link to="/webscan/scans">Scans</Link>
          <Button size="sm" onClick={load}>
            Refresh
          </Button>
          {scan?.id ? (
            <Button
              size="sm"
              variant="primary"
              onClick={() => {
                const token = getStoredToken();
                const bust = Date.now();
                const baseUrl = API_BASE_URL || window.location.origin;
                window.open(
                  `${baseUrl}/api/web-scans/${scan.id}/report.pdf?token=${encodeURIComponent(token)}&v=${bust}`,
                  "_blank",
                  "noopener,noreferrer"
                );
              }}
            >
              📄 Download Report (PDF)
            </Button>
          ) : null}
        </div>

      </div>

      {recentScans.length > 1 ? (
        <div className="surface websec__panel">
          <label className="muted">Load scan</label>
          <select
            className="field__input"
            value={String(scan?.id || scanParam || "")}
            onChange={(e) => {
              const id = e.target.value;
              if (id) navigate(`/webscan/map?scan=${id}`);
            }}
          >
            {recentScans.map((s) => (
              <option key={s.id} value={s.id}>
                #{s.id} · target {s.target_id} · {s.status} · {s.scan_profile}
              </option>
            ))}
          </select>
        </div>
      ) : null}

      {loading ? <div className="surface websec__panel muted">Loading website map…</div> : null}
      {error ? <div className="surface websec__panel error-text">{error}</div> : null}

      <div className="page-grid-2">
        <div className="surface websec__panel">
          <WebsiteMap
            tree={tree}
            onSelectNode={onSelectNode}
            selectedId={selected?.id}
            live={Boolean(scan?.status) && !["COMPLETED", "FAILED", "CANCELLED", "PARTIAL"].includes(scan?.status)}
          />
        </div>
        <div className="surface websec__panel">
          <h3>Inspection</h3>
          {selected ? (
            <>
              <p>
                <strong>{selected.label}</strong>
              </p>
              <code className="websec__mono">{selected.url}</code>
              <div className="websec__kpi-grid" style={{ marginTop: 12 }}>
                <div className="websec__kpi">
                  <div className="websec__kpi-label">Severity</div>
                  <div>{selected.severity || "—"}</div>
                </div>
                <div className="websec__kpi">
                  <div className="websec__kpi-label">Direct findings</div>
                  <div>{selected.finding_count}</div>
                </div>
                <div className="websec__kpi">
                  <div className="websec__kpi-label">Descendants</div>
                  <div>{selected.descendant_finding_count}</div>
                </div>
              </div>
            </>
          ) : (
            <p className="muted">Select a node to inspect findings.</p>
          )}

          <h3 style={{ marginTop: 16 }}>Findings</h3>
          {(findings || []).slice(0, 12).map((f) => (
            <div key={f.id || f.title} className="list-row">
              <Badge
                tone={
                  f.severity === "CRITICAL" || f.severity === "HIGH" ? "danger" : "warn"
                }
              >
                {f.severity}
              </Badge>
              <Link to={`/webscan/findings?q=${encodeURIComponent(f.title || "")}`}>
                {f.title}
              </Link>
            </div>
          ))}
          {!findings?.length ? <div className="muted">No findings for selection.</div> : null}

          <h3 style={{ marginTop: 16 }}>Live activity</h3>
          <div className="wmap-log">
            {(events || []).slice(-40).map((e) => (
              <div key={e.id || `${e.timestamp}-${e.message}`} className="wmap-log-line">
                <span className="muted">
                  {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : ""}
                </span>{" "}
                <Badge>{e.event_type}</Badge> {e.message}
              </div>
            ))}
            {!events?.length ? <div className="muted">No events yet.</div> : null}
          </div>
        </div>
      </div>
    </div>
  );
}

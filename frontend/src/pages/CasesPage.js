import React, { useEffect, useState } from "react";
import api from "../api";
import Badge from "../components/ui/Badge";
import Button from "../components/ui/Button";
import { hasPermission } from "../auth";

export default function CasesPage() {
  const [cases, setCases] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newNote, setNewNote] = useState("");
  const [submittingNote, setSubmittingNote] = useState(false);
  const [newCaseForm, setNewCaseForm] = useState({
    title: "",
    description: "",
    severity: "HIGH",
    assigned_to: "admin",
  });

  const canWrite = hasPermission("cases.write");

  const loadData = async () => {
    setLoading(true);
    try {
      const [c, i] = await Promise.all([
        api.get("/cases"),
        api.get("/incidents"),
      ]);
      setCases(c.data.cases || []);
      setIncidents(i.data.incidents || []);
    } catch {
      setCases([]);
      setIncidents([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const openCaseDetails = async (id) => {
    try {
      const res = await api.get(`/cases/${id}`);
      setSelectedCase(res.data);
      setSelectedIncident(null);
    } catch {
      window.alert("Failed to load case details.");
    }
  };

  const openIncident = async (id) => {
    try {
      const res = await api.get(`/incidents/${id}`);
      setSelectedIncident(res.data);
      setSelectedCase(null);
    } catch {
      window.alert("Failed to load incident.");
    }
  };

  const updateCaseStatus = async (caseId, status) => {
    try {
      await api.patch(`/cases/${caseId}`, { status });
      setCases((prev) =>
        prev.map((c) => (c.id === caseId ? { ...c, status } : c))
      );
      if (selectedCase && selectedCase.id === caseId) {
        setSelectedCase((prev) => ({ ...prev, status }));
      }
    } catch {
      window.alert("Failed to update case status.");
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim() || !selectedCase) return;
    setSubmittingNote(true);
    try {
      const res = await api.post(`/cases/${selectedCase.id}/notes`, {
        body: newNote.trim(),
      });
      setSelectedCase((prev) => ({
        ...prev,
        notes: [
          ...(prev.notes || []),
          {
            id: res.data.id,
            author: res.data.author,
            body: res.data.body,
            created_at: new Date().toISOString(),
          },
        ],
      }));
      setNewNote("");
    } catch {
      window.alert("Failed to append note.");
    } finally {
      setSubmittingNote(false);
    }
  };

  const handleCreateCase = async (e) => {
    e.preventDefault();
    try {
      await api.post("/cases", newCaseForm);
      setShowCreateModal(false);
      setNewCaseForm({
        title: "",
        description: "",
        severity: "HIGH",
        assigned_to: "admin",
      });
      await loadData();
    } catch {
      window.alert("Failed to create case.");
    }
  };

  const filteredCases = cases.filter((c) => {
    const matchesSearch =
      !search ||
      (c.title || "").toLowerCase().includes(search.toLowerCase()) ||
      (c.case_number || "").toLowerCase().includes(search.toLowerCase());
    const matchesStatus =
      statusFilter === "ALL" || (c.status || "").toUpperCase() === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="page-shell">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
        <div>
          <h1>Incident Case Management & Correlation</h1>
          <p className="page-shell__copy">
            Triage operational security cases, record analyst findings, and explore multi-alert attack correlation timelines.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {canWrite ? (
            <Button variant="primary" size="sm" onClick={() => setShowCreateModal(true)}>
              + New Case
            </Button>
          ) : null}
          <Button size="sm" onClick={loadData}>
            ↻ Refresh
          </Button>
        </div>
      </div>

      {/* FILTER & SEARCH */}
      <div className="surface" style={{ padding: "10px 14px", marginBottom: 16, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <input
          className="field__input"
          style={{ flex: "1 1 200px" }}
          placeholder="Search cases by title, ID..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <span className="muted" style={{ fontSize: "0.85rem" }}>Status:</span>
          <select
            className="field__input"
            style={{ width: "auto", padding: "6px 10px" }}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="IN_PROGRESS">In Progress</option>
            <option value="CONTAINED">Contained</option>
            <option value="RESOLVED">Resolved</option>
            <option value="CLOSED">Closed</option>
          </select>
        </div>
      </div>

      <div className="page-grid-2" style={{ alignItems: "start" }}>
        {/* CASES COLUMN */}
        <div className="surface" style={{ padding: 16 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <h2 style={{ margin: 0 }}>Active Cases ({filteredCases.length})</h2>
          </div>
          {loading ? (
            <div className="muted">Loading cases…</div>
          ) : !filteredCases.length ? (
            <div className="muted">No cases matching current filter.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 520, overflowY: "auto" }}>
              {filteredCases.map((c) => (
                <div
                  key={c.id}
                  className="list-row list-row--btn"
                  style={{
                    cursor: "pointer",
                    background: selectedCase?.id === c.id ? "rgba(62, 224, 162, 0.08)" : undefined,
                    border: selectedCase?.id === c.id ? "1px solid var(--accent, #3ee0a2)" : undefined,
                  }}
                  onClick={() => openCaseDetails(c.id)}
                >
                  <div>
                    <strong>{c.case_number}</strong>
                    <div style={{ fontSize: "0.88rem", marginTop: 2 }}>{c.title}</div>
                    <span className="muted" style={{ fontSize: "0.75rem" }}>
                      Assigned: {c.assigned_to || "unassigned"}
                    </span>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
                    <Badge tone={c.severity}>{c.severity}</Badge>
                    <span className="muted" style={{ fontSize: "0.8rem" }}>{c.status}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* CORRELATED INCIDENTS COLUMN */}
        <div className="surface" style={{ padding: 16 }}>
          <h2 style={{ margin: "0 0 12px" }}>Auto-Correlated Incidents ({incidents.length})</h2>
          {!incidents.length ? (
            <div className="muted">No correlated multi-alert incidents detected yet.</div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 520, overflowY: "auto" }}>
              {incidents.map((inc) => (
                <button
                  key={inc.id}
                  className="list-row list-row--btn"
                  style={{
                    textAlign: "left",
                    background: selectedIncident?.id === inc.id ? "rgba(94, 200, 255, 0.08)" : undefined,
                    border: selectedIncident?.id === inc.id ? "1px solid var(--info, #5ec8ff)" : undefined,
                  }}
                  onClick={() => openIncident(inc.id)}
                >
                  <div>
                    <strong>{inc.case_number}</strong>
                    <div style={{ fontSize: "0.88rem" }}>{inc.title}</div>
                    <span className="muted" style={{ fontSize: "0.78rem" }}>
                      Scope: {inc.alert_count} correlated alerts
                    </span>
                  </div>
                  <Badge tone={inc.risk_score >= 75 ? "danger" : "warn"}>
                    Risk {inc.risk_score}
                  </Badge>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* SELECTED CASE WORKBENCH */}
      {selectedCase ? (
        <div className="surface" style={{ padding: 20, marginTop: 18, borderTop: "2px solid var(--accent, #3ee0a2)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
            <div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span className="muted" style={{ fontSize: "0.85rem" }}>CASE WORKBENCH</span>
                <Badge tone={selectedCase.severity}>{selectedCase.severity}</Badge>
                <Badge>{selectedCase.status}</Badge>
              </div>
              <h2 style={{ margin: "6px 0" }}>{selectedCase.case_number} — {selectedCase.title}</h2>
              <p style={{ margin: "0 0 12px", color: "var(--text-muted, #8fa3a0)" }}>
                {selectedCase.description || "No description provided."}
              </p>
            </div>
            <Button size="sm" onClick={() => setSelectedCase(null)}>
              ✕ Close
            </Button>
          </div>

          {/* STATUS WORKFLOW SELECTOR */}
          <div
            style={{
              padding: "10px 14px",
              background: "rgba(255, 255, 255, 0.03)",
              border: "1px solid var(--line, rgba(255,255,255,0.08))",
              borderRadius: 8,
              marginBottom: 16,
              display: "flex",
              gap: 8,
              alignItems: "center",
              flexWrap: "wrap",
            }}
          >
            <span className="muted" style={{ fontSize: "0.85rem", fontWeight: 600 }}>Triage Status:</span>
            {["OPEN", "IN_PROGRESS", "CONTAINED", "RESOLVED", "CLOSED"].map((st) => (
              <Button
                key={st}
                size="sm"
                variant={selectedCase.status === st ? "primary" : undefined}
                onClick={() => updateCaseStatus(selectedCase.id, st)}
              >
                {st.replace("_", " ")}
              </Button>
            ))}
          </div>

          <div className="page-grid-2" style={{ gap: 16 }}>
            {/* LINKED ALERTS */}
            <div>
              <h3>Linked Alert Detections ({(selectedCase.alerts || []).length})</h3>
              {!(selectedCase.alerts || []).length ? (
                <div className="muted">No alerts explicitly attached.</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 260, overflowY: "auto" }}>
                  {selectedCase.alerts.map((a) => (
                    <div key={a.id} className="list-row" style={{ padding: "8px 12px" }}>
                      <div>
                        <strong>#{a.id}</strong> {a.title || a.description}
                        <div className="muted" style={{ fontSize: "0.75rem" }}>Host: {a.host || "—"} · Risk {a.risk_score}</div>
                      </div>
                      <Badge tone={a.severity}>{a.severity}</Badge>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* ANALYST NOTES & TIMELINE */}
            <div>
              <h3>Analyst Investigation Log</h3>
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 8,
                  maxHeight: 220,
                  overflowY: "auto",
                  marginBottom: 10,
                }}
              >
                {!(selectedCase.notes || []).length ? (
                  <div className="muted" style={{ fontStyle: "italic" }}>No notes added yet.</div>
                ) : (
                  selectedCase.notes.map((n) => (
                    <div
                      key={n.id}
                      style={{
                        padding: "8px 12px",
                        background: "rgba(0, 0, 0, 0.25)",
                        borderLeft: "2px solid var(--accent, #3ee0a2)",
                        borderRadius: 4,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem" }} className="muted">
                        <strong>{n.author}</strong>
                        <span>{new Date(n.created_at).toLocaleString()}</span>
                      </div>
                      <div style={{ marginTop: 4, fontSize: "0.85rem" }}>{n.body}</div>
                    </div>
                  ))
                )}
              </div>

              {canWrite ? (
                <form onSubmit={handleAddNote} style={{ display: "flex", gap: 8 }}>
                  <input
                    className="field__input"
                    placeholder="Add an investigation note / IOC finding..."
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    style={{ flex: 1 }}
                  />
                  <Button size="sm" variant="primary" type="submit" disabled={submittingNote || !newNote.trim()}>
                    Add Note
                  </Button>
                </form>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}

      {/* SELECTED CORRELATED INCIDENT TIMELINE */}
      {selectedIncident ? (
        <div className="surface" style={{ padding: 20, marginTop: 18, borderTop: "2px solid var(--info, #5ec8ff)" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
            <div>
              <span className="muted" style={{ fontSize: "0.85rem" }}>ATTACK CAMPAIGN TIMELINE</span>
              <h2 style={{ margin: "4px 0" }}>{selectedIncident.case_number} — {selectedIncident.title}</h2>
              <p className="muted" style={{ margin: 0 }}>{selectedIncident.description}</p>
            </div>
            <Button size="sm" onClick={() => setSelectedIncident(null)}>
              ✕ Close
            </Button>
          </div>
          <div className="timeline" style={{ marginTop: 16 }}>
            {(selectedIncident.timeline || []).map((item, idx) => (
              <div key={item.alert_id || idx} className="timeline__item">
                <div className="timeline__time">{item.timestamp}</div>
                <div>
                  <strong>{item.title}</strong>
                  <div className="muted" style={{ fontSize: "0.8rem", margin: "2px 0 4px" }}>
                    Host: <code>{item.host}</code> · User: <code>{item.user}</code> · Technique: <code>{item.technique_id}</code>
                  </div>
                  {item.commandline ? (
                    <code style={{ fontSize: "0.78rem", background: "rgba(0,0,0,0.4)", padding: "2px 6px", borderRadius: 4 }}>
                      {item.commandline}
                    </code>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {/* CREATE CASE MODAL */}
      {showCreateModal ? (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.75)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 9999,
            padding: 16,
          }}
          onClick={() => setShowCreateModal(false)}
        >
          <div
            className="surface"
            style={{ width: "100%", maxWidth: 500, padding: 24, borderRadius: 10 }}
            onClick={(e) => e.stopPropagation()}
          >
            <h2 style={{ marginTop: 0 }}>Create Incident Case</h2>
            <form onSubmit={handleCreateCase} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div>
                <label className="field__label">Case Title</label>
                <input
                  className="field__input"
                  placeholder="e.g. Unauthorized Credential Dumping on Domain Controller"
                  value={newCaseForm.title}
                  onChange={(e) => setNewCaseForm({ ...newCaseForm, title: e.target.value })}
                  required
                />
              </div>
              <div>
                <label className="field__label">Severity</label>
                <select
                  className="field__input"
                  value={newCaseForm.severity}
                  onChange={(e) => setNewCaseForm({ ...newCaseForm, severity: e.target.value })}
                >
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
              <div>
                <label className="field__label">Description</label>
                <textarea
                  className="field__input"
                  style={{ minHeight: 80 }}
                  placeholder="Summarize initial findings, affected assets, and potential impact..."
                  value={newCaseForm.description}
                  onChange={(e) => setNewCaseForm({ ...newCaseForm, description: e.target.value })}
                />
              </div>
              <div>
                <label className="field__label">Assignee</label>
                <input
                  className="field__input"
                  value={newCaseForm.assigned_to}
                  onChange={(e) => setNewCaseForm({ ...newCaseForm, assigned_to: e.target.value })}
                />
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
                <Button type="button" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </Button>
                <Button variant="primary" type="submit">
                  Create Case
                </Button>
              </div>
            </form>
          </div>
        </div>
      ) : null}
    </div>
  );
}

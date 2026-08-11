import React, { useEffect, useState } from "react";
import api from "../api";
import Badge from "../components/ui/Badge";

export default function CasesPage() {
  const [cases, setCases] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const [c, i] = await Promise.all([
          api.get("/cases"),
          api.get("/incidents"),
        ]);
        setCases(c.data.cases || []);
        setIncidents(i.data.incidents || []);
      } catch {
        setCases([]);
      }
    })();
  }, []);

  const openIncident = async (id) => {
    const res = await api.get(`/incidents/${id}`);
    setSelected(res.data);
  };

  return (
    <div className="page-shell">
      <h1>Cases & Correlated Incidents</h1>
      <p className="page-shell__copy">
        Analyst case management plus auto-correlated incident timelines.
      </p>

      <div className="page-grid-2">
        <div className="surface" style={{ padding: 16 }}>
          <h2>Cases</h2>
          {(cases || []).map((c) => (
            <div key={c.id} className="list-row">
              <strong>{c.case_number}</strong>
              <span>{c.title}</span>
              <Badge tone={c.severity}>{c.severity}</Badge>
              <span>{c.status}</span>
            </div>
          ))}
          {!cases.length ? <div className="muted">No cases yet. Create one from an alert.</div> : null}
        </div>

        <div className="surface" style={{ padding: 16 }}>
          <h2>Incidents</h2>
          {(incidents || []).map((inc) => (
            <button
              key={inc.id}
              className="list-row list-row--btn"
              onClick={() => openIncident(inc.id)}
            >
              <strong>{inc.case_number}</strong>
              <span>{inc.title}</span>
              <span>Risk {inc.risk_score}</span>
              <span>{inc.alert_count} alerts</span>
            </button>
          ))}
          {!incidents.length ? <div className="muted">No correlated incidents yet.</div> : null}
        </div>
      </div>

      {selected ? (
        <div className="surface" style={{ padding: 16, marginTop: 16 }}>
          <h2>{selected.case_number} — Timeline</h2>
          <p>{selected.description}</p>
          <div className="timeline">
            {(selected.timeline || []).map((item) => (
              <div key={item.alert_id} className="timeline__item">
                <div className="timeline__time">{item.timestamp}</div>
                <div>
                  <strong>{item.title}</strong>
                  <div className="muted">
                    {item.host} · {item.user} · {item.process} · {item.technique_id}
                  </div>
                  <code>{item.commandline}</code>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

import React, { useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Link } from "react-router-dom";
import webApi from "../../webApi";
import Badge from "../../components/ui/Badge";
import Button from "../../components/ui/Button";

const SEV_COLORS = {
  CRITICAL: "#f87171",
  HIGH: "#fb923c",
  MEDIUM: "#fbbf24",
  LOW: "#60a5fa",
  INFO: "#94a3b8",
};

export default function WebOverviewPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await webApi.getOverview();
      setData(res.data);
    } catch (err) {
      setError(err.response?.data?.error?.message || "Failed to load overview.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const sevData = useMemo(() => {
    const sev = data?.findings_by_severity || {};
    return Object.keys(sev).map((k) => ({ name: k, value: sev[k] }));
  }, [data]);

  const catData = useMemo(() => {
    const cat = data?.findings_by_category || {};
    return Object.keys(cat)
      .filter(Boolean)
      .slice(0, 8)
      .map((k) => ({ name: k, count: cat[k] }));
  }, [data]);

  if (loading) {
    return <div className="surface websec__panel muted">Loading overview…</div>;
  }

  if (error) {
    return (
      <div className="surface websec__panel">
        <p className="error-text">{error}</p>
        <Button onClick={load}>Retry</Button>
      </div>
    );
  }

  const t = data?.totals || {};

  return (
    <div className="websec__stack">
      <div className="websec__kpi-grid">
        {[
          ["Targets", t.targets],
          ["Authorized", t.authorized_targets],
          ["Active scans", t.active_scans],
          ["Completed", t.completed_scans],
          ["Critical", t.critical_findings],
          ["High", t.high_findings],
          ["Avg risk", t.avg_risk_score],
        ].map(([label, value]) => (
          <div key={label} className="surface websec__kpi">
            <div className="websec__kpi-label">{label}</div>
            <div className="websec__kpi-value">{value ?? 0}</div>
          </div>
        ))}
      </div>

      <div className="page-grid-2">
        <div className="surface websec__panel">
          <h2>Findings by severity</h2>
          {sevData.length ? (
            <div style={{ height: 240 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={sevData} dataKey="value" nameKey="name" outerRadius={90} label>
                    {sevData.map((entry) => (
                      <Cell key={entry.name} fill={SEV_COLORS[entry.name] || "#64748b"} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="muted">No findings yet. Authorize a target and run a scan.</div>
          )}
        </div>
        <div className="surface websec__panel">
          <h2>Findings by category</h2>
          {catData.length ? (
            <div style={{ height: 240 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={catData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} />
                  <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#38bdf8" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="muted">Categories appear after the first scan.</div>
          )}
        </div>
      </div>

      <div className="surface websec__panel">
        <div className="websec__row">
          <h2>Engine readiness</h2>
          <Link className="btn btn--sm btn--ghost" to="/webscan/health">
            Scanner health
          </Link>
        </div>
        <div className="websec__engine-row">
          {Object.entries(data?.engines || {}).map(([name, info]) => (
            <div key={name} className="websec__engine-chip">
              <strong>{name}</strong>
              <Badge tone={info.status === "READY" ? "ok" : "warn"}>
                {info.status || "UNKNOWN"}
              </Badge>
            </div>
          ))}
        </div>
        <div className="websec__actions">
          <Link to="/webscan/targets">Manage targets</Link>
          <Link to="/webscan/scans">View scans</Link>
          <Link to="/webscan/findings">Browse findings</Link>
        </div>
      </div>
    </div>
  );
}

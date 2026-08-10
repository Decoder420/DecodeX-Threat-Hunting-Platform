import React from 'react';

export default function AttackMap({ alerts }) {
  // Helper to color the connection line based on severity
  const getSeverityColor = (severity) => {
    const s = (severity || "").toLowerCase();
    if (s === "critical") return "#ef4444"; // Red
    if (s === "high") return "#ea580c";     // Orange
    if (s === "medium") return "#eab308";   // Yellow
    return "#3b82f6";                       // Blue
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
      {alerts.slice(0, 5).map((alert, idx) => {
        const color = getSeverityColor(alert.severity);
        
        return (
          <div key={idx} style={{ 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'space-between',
            background: '#0f172a',
            padding: '10px 15px',
            borderRadius: '8px',
            borderLeft: `4px solid ${color}`
          }}>
            
            {/* Source Node (Attacker IP) */}
            <div style={{ textAlign: 'center', flex: 1 }}>
              <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase' }}>Source</div>
              <div style={{ fontFamily: 'monospace', fontWeight: 'bold', color: '#e2e8f0' }}>
                {alert.ip || "Unknown IP"}
              </div>
            </div>

            {/* The Attack Vector Line */}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flex: 1 }}>
              <div style={{ fontSize: '10px', color: color, fontWeight: 'bold', marginBottom: '2px' }}>
                {alert.severity ? alert.severity.toUpperCase() : "INFO"}
              </div>
              {/* SVG Arrow connecting the nodes */}
              <svg width="60" height="10" viewBox="0 0 60 10" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M0 5H55M55 5L50 1M55 5L50 9" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              <div style={{ fontSize: '10px', color: '#64748b', marginTop: '2px', maxWidth: '100px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {alert.rule_id || alert.rule || "Rule Match"}
              </div>
            </div>

            {/* Target Node (Your Host) */}
            <div style={{ textAlign: 'center', flex: 1 }}>
              <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase' }}>Target</div>
              <div style={{ fontFamily: 'monospace', fontWeight: 'bold', color: '#38bdf8' }}>
                {alert.host || "Local Network"}
              </div>
            </div>

          </div>
        );
      })}
      
      {alerts.length === 0 && (
        <div style={{ textAlign: 'center', color: '#64748b', padding: '20px' }}>
          No active attack flows detected.
        </div>
      )}
    </div>
  );
}
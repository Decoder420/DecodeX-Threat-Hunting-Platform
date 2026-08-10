export default function MitrePanel({ data }) {
  return (
    <div>
      {Object.entries(data || {}).map(([tactic, sev]) => (
        <div key={tactic} style={{ marginBottom: 10 }}>
          <strong>{tactic}</strong>
          <div style={{ marginTop: 5 }}>
            {Object.entries(sev).map(([level, count]) => {
              // 1. Force the level to lowercase for safe comparison
              const lowerLevel = level.toLowerCase();
              
              // 2. Determine the background color safely
              let bgColor = "#1e3a8a"; // Default Blue (Low/Info)
              if (lowerLevel === "critical") bgColor = "#991b1b"; // Dark Red
              else if (lowerLevel === "high") bgColor = "#7f1d1d"; // Red
              else if (lowerLevel === "medium") bgColor = "#78350f"; // Orange/Brown

              return (
                <span
                  key={level}
                  style={{
                    marginRight: 8,
                    padding: "4px 8px",
                    borderRadius: 6,
                    background: bgColor,
                    color: "#ffffff",
                    fontWeight: "bold",
                    textTransform: "capitalize" // Ensures it renders cleanly on the UI
                  }}
                >
                  {level}: {count}
                </span>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
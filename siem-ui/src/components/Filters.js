export default function Filters({ range, setRange, search, setSearch }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div>
        {["1h", "24h", "7d"].map((r) => (
          <button
            key={r}
            onClick={() => setRange(r)}
            style={{
              marginRight: 10,
              background: range === r ? "#38bdf8" : "#1e293b",
              color: "white",
              border: "none",
              padding: "6px 12px"
            }}
          >
            {r}
          </button>
        ))}
      </div>

      <input
        placeholder="Search alerts..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        style={{ marginTop: 10, padding: 8, width: "100%" }}
      />
    </div>
  );
}
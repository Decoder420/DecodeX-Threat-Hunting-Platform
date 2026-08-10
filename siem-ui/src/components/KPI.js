export default function KPI({ title, value }) {
  return (
    <div style={{
      flex: 1,
      background: "#10243a",
      padding: 15,
      borderRadius: 10
    }}>
      <div>{title}</div>
      <h2>{value}</h2>
    </div>
  );
}
export default function AlertTable({ alerts, onAlertClick }) {
  return (
    <table className="panel">
      <thead>
        <tr>
          <th>Rule</th>
          <th>Host</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        {alerts.map((a) => (
          <tr key={a.id} onClick={() => onAlertClick(a)} style={{ cursor: 'pointer' }}>
            <td><strong>{a.rule}</strong></td>
            <td>{a.host}</td>
            <td>
              <span className={`badge badge-${(a.severity && a.severity.toLowerCase())}`}>
                {a.severity}
              </span>
            </td>
            <td>{a.status}</td>
            <td>
              <button className="investigate-btn">Investigate</button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
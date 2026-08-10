import React from 'react';

export default function Navbar({ onNavigate, onLogout }) {
  return (
    <nav style={styles.nav}>
      <div style={styles.left}>
        <h2 style={styles.logo}>Threat Hunting SIEM</h2>
      </div>
      
      <div style={styles.right}>
        <button onClick={() => onNavigate("dashboard")} style={styles.button}>Dashboard</button>
        <button onClick={() => onNavigate("admin")} style={styles.button}>Admin Panel</button>
        <button onClick={onLogout} style={{ ...styles.button, color: '#ef4444', fontWeight: 'bold' }}>Logout</button>
      </div>
    </nav>
  );
}

const styles = {
  nav: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem 2rem', background: '#0f172a', borderBottom: '1px solid #1e293b', marginBottom: '20px' },
  left: { display: 'flex', alignItems: 'center' },
  right: { display: 'flex', gap: '20px', alignItems: 'center' },
  logo: { margin: 0, color: '#38bdf8', fontSize: '1.2rem' },
  button: { background: 'transparent', border: 'none', color: '#e2e8f0', cursor: 'pointer', fontSize: '14px' }
};
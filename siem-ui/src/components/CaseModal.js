import React, { useState } from 'react';
import API from '../api';

export default function CaseModal({ alert, onClose, onUpdate }) {
  const [formData, setFormData] = useState({
    status: 'Open',
    assigned_to: '',
    analyst_notes: ''
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    // Call the endpoint we will create in Flask
    await API.post(`/alerts/${alert.id}/case`, new URLSearchParams(formData));
    onUpdate(); // Refresh the parent list
    onClose();
  };

  return (
    <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.8)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <form onSubmit={handleSubmit} className="panel" style={{ width: '400px' }}>
        <h3>Manage Case: Alert #{alert.id}</h3>
        <select onChange={(e) => setFormData({...formData, status: e.target.value})} className="controls">
          {["Open", "In Progress", "Resolved", "False Positive"].map(s => <option value={s}>{s}</option>)}
        </select>
        <input placeholder="Assigned Analyst" onChange={(e) => setFormData({...formData, assigned_to: e.target.value})} className="controls" />
        <textarea placeholder="Notes" onChange={(e) => setFormData({...formData, analyst_notes: e.target.value})} className="controls" style={{ width: '100%' }} />
        <div style={{ marginTop: 10 }}>
          <button type="submit">Update Case</button>
          <button onClick={onClose}>Cancel</button>
        </div>
      </form>
    </div>
  );
}
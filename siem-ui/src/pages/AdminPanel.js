import React, { useState } from 'react';
import API from '../api';

export default function AdminPanel() {
    const [sigmaFile, setSigmaFile] = useState(null);
    const [suppression, setSuppression] = useState({ name: '', rule_id: '', field_name: '', field_value: '', reason: '' });

    // Sigma Import
    const handleSigmaUpload = async (e) => {
        e.preventDefault();
        const formData = new FormData();
        formData.append("sigma_file", sigmaFile);
        try {
            const res = await API.post('/sigma', formData, {
                headers: { 'Content-Type': 'multipart/form-data' }
            });
            alert(`Success! Imported ${res.data.imported} rules.`);
        } catch (err) { alert("Upload failed."); }
    };

    // Suppression Rule Creation
    const handleSuppressionSubmit = async (e) => {
        e.preventDefault();
        try {
            await API.post('/suppression', suppression);
            alert("Suppression rule active.");
            setSuppression({ name: '', rule_id: '', field_name: '', field_value: '', reason: '' });
        } catch (err) { alert("Failed."); }
    };

    // IOC Sync
    const handleIocSync = async () => {
        try {
            await API.post('/ioc/sync');
            alert("IOC feeds synced successfully!");
        } catch (err) { alert("Sync failed."); }
    };

    return (
        <div className="container">
            <h2>SOC Administration</h2>

            {/* Grid for Sigma and IOC Sync */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                
                {/* SIGMA IMPORT */}
                <div className="panel">
                    <h3>📥 Sigma Import</h3>
                    <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '10px' }}>
                        Upload YAML-based Sigma rules to expand detection capabilities.
                    </p>
                    <form onSubmit={handleSigmaUpload} style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                        <input 
                            type="file" 
                            accept=".yml,.yaml" 
                            onChange={(e) => setSigmaFile(e.target.files[0])} 
                            style={{ background: '#1e293b', padding: '8px', borderRadius: '4px', border: '1px solid #334155' }}
                        />
                        <button 
                            type="submit" 
                            style={{ padding: '8px 16px', background: '#38bdf8', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: 'bold' }}
                        >
                            Upload
                        </button>
                    </form>
                </div>

                {/* IOC Sync */}
                <div className="panel">
                    <h3>🛡️ IOC Sync</h3>
                    <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '10px' }}>
                        Manually trigger a sync with threat intel feeds.
                    </p>
                    <button onClick={handleIocSync} style={{ padding: '8px 16px', background: '#38bdf8', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                        Sync Threat Intel
                    </button>
                </div>
            </div>

            {/* Suppression */}
            <div className="panel">
                <h3>🔇 Create Suppression Rule</h3>
                <form onSubmit={handleSuppressionSubmit} style={{ display: 'flex', gap: '10px' }}>
                    <input placeholder="Name" value={suppression.name} onChange={(e) => setSuppression({...suppression, name: e.target.value})} className="controls" />
                    <input placeholder="Rule ID" value={suppression.rule_id} onChange={(e) => setSuppression({...suppression, rule_id: e.target.value})} className="controls" />
                    <button type="submit" style={{ padding: '8px 16px', background: '#38bdf8', border: 'none', borderRadius: '4px' }}>Save Rule</button>
                </form>
            </div>
        </div>
    );
}
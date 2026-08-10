import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';
import axios from 'axios';

const API = axios.create({ baseURL: 'http://127.0.0.1:5001/api' });

// Add the token to every request automatically
API.interceptors.request.use((req) => {
    req.headers.Authorization = `dummy-soc-analyst-token`;
    return req;
});

export const getDashboard = (range) => API.get(`/dashboard?range=${range}`);
export const getAlertContext = (id) => API.get(`/alert_context/${id}`);
export const getAdminData = () => API.get('/admin/data');
export const listYaraRules = () => API.get('/admin/rules');
export const getRuleContent = (file) => API.get(`/admin/rules/content?file=${file}`);

// THE DEPLOY FUNCTION
export const saveYaraRule = (file, content) =>
    API.post('/admin/rules/save', { file, content });

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render( <
    React.StrictMode >
    <
    App / >
    <
    /React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
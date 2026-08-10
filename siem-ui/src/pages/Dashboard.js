import React, {
    useCallback,
    useEffect,
    useMemo,
    useState,
} from "react";

import {
    BarChart,
    Bar,
    CartesianGrid,
    Cell,
    Legend,
    LineChart,
    Line,
    PieChart,
    Pie,
    PolarAngleAxis,
    PolarGrid,
    PolarRadiusAxis,
    Radar,
    RadarChart,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from "recharts";

import { io } from "socket.io-client";
import Editor from "react-simple-code-editor";

import {
    getDashboard,
    getAlertContext,
    getAdminData,
    toggleFeed,
    listYaraRules,
    getRuleContent,
    saveYaraRule,
} from "../api";

import Navbar from "../components/Navbar";

import {
    highlight,
    languages,
} from "prismjs/components/prism-core";

import "prismjs/components/prism-clike";
import "prismjs/themes/prism-tomorrow.css";

import axios from "axios";

/* ============================================================
   BACKEND
   ============================================================ */

const BACKEND_URL = "https://f462-2401-4900-8844-5426-997a-c83e-.ngrok-free.app";

/* ============================================================
   CONSTANTS
   ============================================================ */

const TIME_RANGES = [
    "1h",
    "12h",
    "24h",
    "3d",
    "7d",
    "15d",
    "1M",
    "3M",
    "6M",
    "1Y",
];

const CHART_COLORS = [
    "#38bdf8",
    "#22c55e",
    "#f59e0b",
    "#ef4444",
    "#a855f7",
    "#14b8a6",
];

const getAuthHeaders = () => ({
    Authorization: `Bearer ${
        localStorage.getItem("token") || ""
    }`,
});

/* ============================================================
   COMPONENT
   ============================================================ */

export default function Dashboard({ onLogout }) {
    const [data, setData] = useState(null);
    const [adminData, setAdminData] = useState(null);

    const [currentView, setCurrentView] =
    useState("dashboard");

    const [range, setRange] =
    useState("24h");

    const [searchQuery, setSearchQuery] =
    useState("");

    const [pendingAlerts, setPendingAlerts] =
    useState([]);

    const [currentPage, setCurrentPage] =
    useState(1);

    const [rowsPerPage, setRowsPerPage] =
    useState(10);

    const [slideContext, setSlideContext] =
    useState(null);

    const [analystNotes, setAnalystNotes] =
    useState("");

    const [activeHostIsolated, setActiveHostIsolated] =
    useState(false);

    const [rulesList, setRulesList] =
    useState([]);

    const [selectedRule, setSelectedRule] =
    useState("");

    const [ruleContent, setRuleContent] =
    useState("");

    const [newSuppression, setNewSuppression] =
    useState("");

    const [socketStatus, setSocketStatus] =
    useState("connecting");

    /* ========================================================
       DASHBOARD DATA
       ======================================================== */

    const refreshDashboard = useCallback(async() => {
        try {
            const response =
                await getDashboard(range);

            const payload =
                (response && response.data) || {};

            setData(payload);
            setCurrentPage(1);
        } catch (error) {
            console.error(
                "Dashboard Sync Error:",
                error
            );
        }
    }, [range]);

    /* ========================================================
       ADMIN DATA
       ======================================================== */

    const refreshAdmin = useCallback(async() => {
        try {
            const adminResponse =
                await getAdminData();

            const rulesResponse =
                await listYaraRules();

            setAdminData((adminResponse && adminResponse.data) || {});

            setRulesList((rulesResponse && rulesResponse.data && rulesResponse.data.rules) || []);

        } catch (error) {
            console.error(
                "Admin Sync Error:",
                error
            );
        }
    }, []);

    /* ========================================================
       LOAD DATA
       ======================================================== */

    useEffect(() => {
        if (currentView === "dashboard") {
            refreshDashboard();
        } else {
            refreshAdmin();
        }
    }, [
        currentView,
        refreshDashboard,
        refreshAdmin,
    ]);

    /* ========================================================
       REALTIME SOCKET.IO
       ======================================================== */

    useEffect(() => {
        const socket = io(
            BACKEND_URL, {
                transports: [
                    "websocket",
                    "polling",
                ],
                reconnection: true,
                reconnectionAttempts: Infinity,
                reconnectionDelay: 1000,
            }
        );

        socket.on("connect", () => {
            console.log(
                "Socket.IO connected:",
                socket.id
            );

            setSocketStatus("online");
        });

        socket.on(
            "disconnect",
            () => {
                console.log(
                    "Socket.IO disconnected"
                );

                setSocketStatus("offline");
            }
        );

        socket.on(
            "connect_error",
            (error) => {
                console.error(
                    "Socket.IO connection error:",
                    error
                );

                setSocketStatus("error");
            }
        );

        socket.on(
            "new_alert",
            (newAlert) => {
                console.log(
                    "Realtime alert:",
                    newAlert
                );

                setPendingAlerts(
                    (previous) => [
                        newAlert,
                        ...previous,
                    ]
                );
            }
        );

        return () => {
            socket.disconnect();
        };
    }, []);

    /* ========================================================
       MERGE REALTIME ALERTS
       ======================================================== */

    const mergePendingAlerts = () => {
        if (
            pendingAlerts.length === 0
        ) {
            return;
        }

        setData((previous) => {
            if (!previous) {
                return previous;
            }

            const existingAlerts =
                previous.alerts || [];

            return {
                ...previous,

                metadata: {
                    ...(previous.metadata || {}),
                    total_alerts: (previous.metadata && previous.metadata.total_alerts || 0) + pendingAlerts.length,
                },

                alerts: [
                    ...pendingAlerts,
                    ...existingAlerts,
                ],
            };
        });

        setPendingAlerts([]);
        setCurrentPage(1);
    };

    /* ========================================================
       SEARCH
       ======================================================== */

    const filteredAlerts = useMemo(() => {
        const alerts =
            data && data.alerts || [];

        const query =
            searchQuery
            .trim()
            .toLowerCase();

        if (!query) {
            return alerts;
        }

        return alerts.filter(
            (alert) => {
                const searchable = [
                        alert && alert.name,
                        alert && alert.host,
                        alert && alert.tactic,
                        alert && alert.severity,
                        alert && alert.status,
                        alert && alert.source,
                        alert && alert.assigned,
                    ]
                    .filter(Boolean)
                    .join(" ")
                    .toLowerCase();

                return searchable.includes(
                    query
                );
            }
        );
    }, [
        data && data.alerts,
        searchQuery,
    ]);

    /* ========================================================
       PAGINATION
       ======================================================== */

    const totalPages = Math.max(
        1,
        Math.ceil(
            filteredAlerts.length /
            rowsPerPage
        )
    );

    const safeCurrentPage =
        Math.min(
            currentPage,
            totalPages
        );

    const currentAlerts =
        filteredAlerts.slice(
            (safeCurrentPage - 1) *
            rowsPerPage,
            safeCurrentPage *
            rowsPerPage
        );

    /* ========================================================
       CHART DATA
       ======================================================== */

    const tacticChartData = useMemo(() => {
        return (
            data && data.charts && data.charts.tactics || []
        ).map((item) => ({
            name: (item && item.name) ||
                "Unknown",
            value: Number((item && item.value)) || 0,
        }));
    }, [data]);

    const hostChartData = useMemo(() => {
        return (
            data && data.charts && data.charts.hosts || []
        ).map((item) => ({
            name: (item && item.name) ||
                "Unknown",
            count: Number((item && item.count)) || 0,
        }));
    }, [data]);

    const severityRadarData =
        useMemo(() => {
            const alerts =
                data && data.alerts || [];

            const counts = {
                Critical: 0,
                High: 0,
                Medium: 0,
                Low: 0,
            };

            alerts.forEach(
                (alert) => {
                    const severity =
                        String(
                            alert && alert.severity ||
                            "Low"
                        ).toLowerCase();

                    if (
                        severity ===
                        "critical"
                    ) {
                        counts.Critical++;
                    } else if (
                        severity === "high"
                    ) {
                        counts.High++;
                    } else if (
                        severity ===
                        "medium"
                    ) {
                        counts.Medium++;
                    } else {
                        counts.Low++;
                    }
                }
            );

            return [{
                    severity: "Critical",
                    value: counts.Critical,
                },
                {
                    severity: "High",
                    value: counts.High,
                },
                {
                    severity: "Medium",
                    value: counts.Medium,
                },
                {
                    severity: "Low",
                    value: counts.Low,
                },
            ];
        }, [data]);

    /* ========================================================
       INVESTIGATION
       ======================================================== */

    const handleInvestigate =
        async(id, host) => {
            try {
                const response =
                    await getAlertContext(
                        id
                    );

                setSlideContext({
                    ...(response && response.data) || {},
                    host,
                    originalId: id,
                });

                setAnalystNotes("");
                setActiveHostIsolated(
                    false
                );
            } catch (error) {
                console.error(
                    "Alert investigation error:",
                    error
                );

                window.alert(
                    "Unable to load alert investigation."
                );
            }
        };

    /* ========================================================
       SOAR
       ======================================================== */

    const executeSOAR =
        async(action) => {
            if (!slideContext) {
                return;
            }

            try {
                await axios.post(
                    `${BACKEND_URL}/api/soar/action`, {
                        action,
                        target: slideContext.host,
                    }, {
                        headers: getAuthHeaders(),
                    }
                );

                if (
                    action ===
                    "Isolate Host"
                ) {
                    setActiveHostIsolated(
                        true
                    );
                }

                window.alert(
                    `SOAR Action: [${action}] executed successfully.`
                );
            } catch (error) {
                console.error(
                    "SOAR Action error:",
                    error
                );

                window.alert(
                    "SOAR Action failed."
                );
            }
        };

    /* ========================================================
       FEEDS
       ======================================================== */

    const handleToggleFeed =
        async(id) => {
            try {
                await toggleFeed(id);
                await refreshAdmin();
            } catch (error) {
                console.error(
                    "Feed toggle error:",
                    error
                );

                window.alert(
                    "Failed to toggle feed."
                );
            }
        };

    /* ========================================================
       YARA
       ======================================================== */

    const loadRule =
        async(file) => {
            setSelectedRule(file);

            try {
                const response =
                    await getRuleContent(
                        file
                    );

                setRuleContent(
                    (response && response.data && response.data.content) || ""
                );
            } catch (error) {
                console.error(
                    "YARA rule load error:",
                    error
                );

                setRuleContent("");
            }
        };

    const handleSaveRule =
        async() => {
            if (!selectedRule) {
                window.alert(
                    "Please select a YARA rule first."
                );

                return;
            }

            try {
                await saveYaraRule(
                    selectedRule,
                    ruleContent
                );

                window.alert(
                    "YARA rule deployed successfully."
                );

                await refreshAdmin();
            } catch (error) {
                console.error(
                    "YARA rule save error:",
                    error
                );

                window.alert(
                    "Failed to deploy YARA rule."
                );
            }
        };

    /* ========================================================
       SYNC FEEDS
       ======================================================== */

    const handleSyncFeeds =
        async() => {
            try {
                const response =
                    await axios.post(
                        `${BACKEND_URL}/api/admin/feeds/sync`, {}, {
                            headers: getAuthHeaders(),
                        }
                    );

                await refreshAdmin();

                const summary =
                    (response && response.data && response.data.summary) || {};

                window.alert(
                    `Sync complete: ${
                        summary.feeds_checked ||
                        0
                    } feeds checked, ${
                        summary.ioc_added ||
                        0
                    } IOCs added.`
                );
            } catch (error) {
                console.error(
                    "Feed sync error:",
                    error
                );

                window.alert(
                    "Feed sync failed."
                );
            }
        };

    /* ========================================================
       SUPPRESSION
       ======================================================== */

    const handleAddSuppression =
        async() => {
            const indicator =
                newSuppression.trim();

            if (!indicator) {
                return;
            }

            try {
                await axios.post(
                    `${BACKEND_URL}/api/admin/suppressions/add`, {
                        indicator,
                    }, {
                        headers: getAuthHeaders(),
                    }
                );

                setNewSuppression("");

                await refreshAdmin();

                window.alert(
                    "Suppression rule added."
                );
            } catch (error) {
                console.error(
                    "Suppression error:",
                    error
                );

                window.alert(
                    "Failed to add suppression."
                );
            }
        };

    /* ========================================================
       PDF
       ======================================================== */

    const downloadPDF =
        (id) => {
            const token =
                localStorage.getItem(
                    "token"
                );

            const url =
                `${BACKEND_URL}/api/report/${id}?token=${encodeURIComponent(
                    token || ""
                )}`;

            window.open(
                url,
                "_blank",
                "noopener,noreferrer"
            );
        };

    /* ========================================================
       LOADING
       ======================================================== */

    if (!data) {
        return ( <
            div style = {
                loadingStyle
            } >
            <
            div style = {
                {
                    fontSize: "28px",
                    marginBottom: "15px",
                }
            } > 🛰️
            <
            /div>

            Initializing Enterprise SOC Environment...

            <
            div style = {
                {
                    marginTop: "15px",
                    color: "#64748b",
                    fontSize: "12px",
                }
            } >
            Backend: { " " } { BACKEND_URL } <
            /div> < /
            div >
        );
    }

    /* ========================================================
       RENDER
       ======================================================== */

    return ( <
        div style = {
            {
                minHeight: "100vh",
                background: "#0b1120",
                color: "#f8fafc",
                paddingBottom: "60px",
            }
        } >
        <
        Navbar onNavigate = {
            setCurrentView
        }
        onLogout = {
            onLogout
        }
        />

        <
        main style = {
            {
                padding: "20px 40px",
            }
        } > {
            currentView ===
            "dashboard" ? ( <
                >
                { /* SEARCH */ }

                <
                div style = {
                    searchBarStyle
                } >
                <
                input type = "text"
                value = {
                    searchQuery
                }
                onChange = {
                    (
                        event
                    ) => {
                        setSearchQuery(
                            event
                            .target
                            .value
                        );

                        setCurrentPage(
                            1
                        );
                    }
                }
                placeholder = 'index=main sourcetype=endpoint | search host="WIN-SRV-01"'
                style = {
                    searchInputStyle
                }
                />

                <
                select value = {
                    range
                }
                onChange = {
                    (
                        event
                    ) =>
                    setRange(
                        event
                        .target
                        .value
                    )
                }
                style = {
                    rangeStyle
                } > {
                    TIME_RANGES.map(
                        (item) => ( <
                            option key = {
                                item
                            }
                            value = {
                                item
                            } >
                            Last { " " } { item } <
                            /option>
                        )
                    )
                } <
                /select> < /
                div >

                { /* HEADER */ }

                <
                div style = {
                    headerStyle
                } >
                <
                div >
                <
                span style = {
                    liveBadgeStyle
                } >
                LIVE SOC CONSOLE <
                /span>

                <
                h1 >
                Threat Hunting Dashboard <
                /h1>

                <
                p style = {
                    {
                        color: "#64748b",
                    }
                } >
                Real - time alert monitoring,
                threat analytics,
                IOC feeds and incident response. <
                /p> < /
                div >

                <
                div style = {
                    {
                        textAlign: "right",
                        color: "#94a3b8",
                        fontSize: "13px",
                    }
                } >
                <
                div >
                Socket: { " " } <
                strong style = {
                    {
                        color: socketStatus ===
                            "online" ?
                            "#22c55e" : "#f59e0b",
                    }
                } > { socketStatus.toUpperCase() } <
                /strong> < /
                div >

                <
                div >
                Events: { " " } {
                    data && data.metadata && data.metadata.total_events ||
                        0
                } <
                /div>

                <
                div >
                Alerts: { " " } {
                    (data && data.metadata && data.metadata.total_alerts) ??
                    0
                } <
                /div>

                <
                div >
                Last ingest: { " " } {
                    data && data.metadata && data.metadata.last_ingest ||
                        "N/A"
                } <
                /div> < /
                div > <
                /div>

                { /* KPI CARDS */ }

                <div style={kpiGrid}>
                    <KpiCard
                        title="TOTAL ALERTS"
                        value={
                            (data && data.kpis && data.kpis.total_alerts) ??
                            (data && data.metadata && data.metadata.total_alerts) ??
                            0
                        }
                        icon="🚨"
                    />
                    <KpiCard
                        title="HIGH / CRITICAL"
                        value={(data && data.kpis && data.kpis.high_or_above) || 0}
                        icon="🔥"
                    />
                    <KpiCard
                        title="EVENTS"
                        value={(data && data.metadata && data.metadata.total_events) || 0}
                        icon="📡"
                    />
                    <KpiCard
                        title="LIVE SOCKET"
                        value={socketStatus === 'online' ? 'ONLINE' : 'OFFLINE'}
                        icon="🛰️"
                    />
                </div>

                { /* CHARTS */ }

                <
                div style = {
                    chartGrid
                } > { /* TIMELINE */ }

                <
                Panel title = "Alert Activity"
                subtitle = "Current selected time range" >
                <
                div style = {
                    {
                        height: "280px",
                    }
                } >
                <
                ResponsiveContainer width = "100%"
                height = "100%" >
                <
                LineChart data = {
                    buildTimeline(
                        data && data.alerts || []
                    )
                } >
                <
                CartesianGrid stroke = "#1e293b" /
                >

                <
                XAxis dataKey = "time"
                stroke = "#64748b" /
                >

                <
                YAxis allowDecimals = {
                    false
                }
                stroke = "#64748b" /
                >

                <
                Tooltip contentStyle = {
                    {
                        background: "#020617",
                        border: "1px solid #334155",
                    }
                }
                />

                <
                Line type = "monotone"
                dataKey = "alerts"
                stroke = "#38bdf8"
                strokeWidth = {
                    3
                }
                dot = {
                    false
                }
                />
                </LineChart>
                </ResponsiveContainer>
                </div>
                </Panel>

                { /* THREAT RADAR */ }

                <
                Panel title = "Realtime Threat Radar"
                subtitle = "Severity distribution" >
                <
                div style = {
                    {
                        height: "280px",
                        position: "relative",
                    }
                } >
                <
                ResponsiveContainer width = "100%"
                height = "100%" >
                <
                RadarChart data = {
                    severityRadarData
                } >
                <
                PolarGrid stroke = "#334155" /
                >

                <
                PolarAngleAxis dataKey = "severity"
                tick = {
                    {
                        fill: "#cbd5e1",
                        fontSize: 12,
                    }
                }
                />

                <
                PolarRadiusAxis tick = {
                    {
                        fill: "#64748b",
                        fontSize: 10,
                    }
                }
                />

                <
                Radar name = "Threats"
                dataKey = "value"
                stroke = "#38bdf8"
                fill = "#38bdf8"
                fillOpacity = {
                    0.3
                }
                />

                <
                Tooltip contentStyle = {
                    {
                        background: "#020617",
                        border: "1px solid #334155",
                    }
                }
                /> < /
                RadarChart > <
                /ResponsiveContainer>

                <
                div style = {
                    radarCenter
                } >
                <
                span > {
                    (
                        data && data.alerts || []
                    ).length
                } <
                /span> <
                small >
                THREATS <
                /small> < /
                div > <
                /div> < /
                Panel >

                { /* HOSTS */ }

                <
                Panel title = "Top Targeted Hosts"
                subtitle = "Hosts generating the most alerts" >
                <
                div style = {
                    {
                        height: "280px",
                    }
                } >
                <
                ResponsiveContainer width = "100%"
                height = "100%" >
                <
                BarChart data = {
                    hostChartData
                }
                layout = "vertical"
                margin = {
                    {
                        left: 20,
                        right: 20,
                    }
                } >
                <
                CartesianGrid stroke = "#1e293b"
                horizontal = {
                    false
                }
                />

                <
                XAxis type = "number"
                allowDecimals = {
                    false
                }
                stroke = "#64748b" /
                >

                <
                YAxis type = "category"
                dataKey = "name"
                width = {
                    100
                }
                stroke = "#64748b" /
                >

                <
                Tooltip contentStyle = {
                    {
                        background: "#020617",
                        border: "1px solid #334155",
                    }
                }
                />

                <
                Bar dataKey = "count"
                fill = "#8b5cf6"
                radius = {
                    [
                        0,
                        5,
                        5,
                        0,
                    ]
                }
                /> < /
                BarChart > <
                /ResponsiveContainer> < /
                div > <
                /Panel>

                { /* TACTICS */ }

                <
                Panel title = "MITRE Tactics"
                subtitle = "Alert distribution by tactic" >
                <
                div style = {
                    {
                        height: "280px",
                    }
                } >
                <
                ResponsiveContainer width = "100%"
                height = "100%" >
                <
                PieChart >
                <
                Pie data = {
                    tacticChartData
                }
                dataKey = "value"
                nameKey = "name"
                cx = "50%"
                cy = "50%"
                outerRadius = {
                    95
                }
                innerRadius = {
                    50
                }
                label > {
                    tacticChartData.map(
                        (
                            entry,
                            index
                        ) => ( <
                            Cell key = { `cell-${index}` }
                            fill = {
                                CHART_COLORS[
                                    index %
                                    CHART_COLORS.length
                                ]
                            }
                            />
                        )
                    )
                } <
                /Pie>

                <
                Tooltip contentStyle = {
                    {
                        background: "#020617",
                        border: "1px solid #334155",
                    }
                }
                />

                <
                Legend / >
                <
                /PieChart> < /
                ResponsiveContainer > <
                /div> < /
                Panel > <
                /div>

                { /* LIVE ALERT TOAST */ }

                {
                    pendingAlerts.length >
                        0 && ( <
                            div style = {
                                realtimeAlertBar
                            } >
                            <
                            span > 🔴{ " " } <
                            strong > {
                                pendingAlerts.length
                            } <
                            /strong>{" "}
                            new realtime alert {
                                pendingAlerts.length >
                                    1 ?
                                    "s" :
                                    ""
                            } { " " }
                            received <
                            /span>

                            <
                            button onClick = {
                                mergePendingAlerts
                            }
                            style = {
                                refreshButton
                            } >
                            LOAD NEW ALERTS <
                            /button> < /
                            div >
                        )
                }

                { /* ALERTS */ }

                <
                Panel title = "Active Alerts"
                subtitle = { `${filteredAlerts.length} alerts` } >
                <
                div style = {
                    {
                        maxHeight: "620px",
                        overflowY: "auto",
                    }
                } > {
                    currentAlerts.length ===
                    0 ? ( <
                        div style = {
                            emptyStyle
                        } >
                        No alerts match your criteria. <
                        /div>
                    ) : (
                        currentAlerts.map(
                            (
                                alert,
                                index
                            ) => ( <
                                AlertCard key = {
                                    alert && alert.id ||
                                    `${(alert && alert.name)}-${(alert && alert.host)}-${index}`
                                }
                                alert = {
                                    alert
                                }
                                onInvestigate = {
                                    handleInvestigate
                                }
                                />
                            )
                        )
                    )
                } <
                /div>

                { /* PAGINATION */ }

                <
                div style = {
                    paginationFooter
                } >
                <
                select value = {
                    rowsPerPage
                }
                onChange = {
                    (
                        event
                    ) => {
                        setRowsPerPage(
                            Number(
                                event
                                .target
                                .value
                            )
                        );

                        setCurrentPage(
                            1
                        );
                    }
                }
                style = {
                    pageSelect
                } >
                <
                option value = { 5 } >
                5 rows <
                /option>

                <
                option value = { 10 } >
                10 rows <
                /option>

                <
                option value = { 25 } >
                25 rows <
                /option>

                <
                option value = { 50 } >
                50 rows <
                /option> < /
                select >

                <
                span >
                Page { " " } {
                    safeCurrentPage
                } { " " }
                of { " " } {
                    totalPages
                } <
                /span>

                <
                div style = {
                    {
                        display: "flex",
                        gap: "8px",
                    }
                } >
                <
                button disabled = {
                    safeCurrentPage <=
                    1
                }
                onClick = {
                    () =>
                    setCurrentPage(
                        (
                            page
                        ) =>
                        Math.max(
                            1,
                            page -
                            1
                        )
                    )
                }
                style = {
                    pageButton
                } > ←
                <
                /button>

                <
                button disabled = {
                    safeCurrentPage >=
                    totalPages
                }
                onClick = {
                    () =>
                    setCurrentPage(
                        (
                            page
                        ) =>
                        Math.min(
                            totalPages,
                            page +
                            1
                        )
                    )
                }
                style = {
                    pageButton
                } > →
                <
                /button> < /
                div > <
                /div> < /
                Panel >

                { /* IOC FEEDS */ }

                <
                Panel title = "IOC Feeds"
                subtitle = "Threat intelligence sources" >
                <
                button onClick = {
                    handleSyncFeeds
                }
                style = {
                    primaryButton
                } > 🔄Sync Live Threat Intel Feeds <
                /button>

                <
                div style = {
                    {
                        overflowX: "auto",
                    }
                } >
                <
                table style = {
                    tableStyle
                } >
                <
                thead >
                <
                tr >
                <
                th >
                NAME <
                /th> <
                th >
                TYPE <
                /th> <
                th >
                ENABLED <
                /th> < /
                tr > <
                /thead>

                <
                tbody > {
                    (
                        data && data.feeds || []
                    ).map(
                        (
                            feed,
                            index
                        ) => ( <
                            tr key = {
                                feed && feed.name ||
                                index
                            } >
                            <
                            td > {
                                feed && feed.name
                            } <
                            /td>

                            <
                            td > {
                                feed && feed.type
                            } <
                            /td>

                            <
                            td > {
                                String(
                                    (feed && feed.enabled) ??
                                    false
                                )
                            } <
                            /td> < /
                            tr >
                        )
                    )
                } </tbody>
                </table>
                </div>
                </Panel>
                </>
            ) : ( <
                AdminView adminData = {
                    adminData
                }
                rulesList = {
                    rulesList
                }
                selectedRule = {
                    selectedRule
                }
                ruleContent = {
                    ruleContent
                }
                setRuleContent = {
                    setRuleContent
                }
                loadRule = {
                    loadRule
                }
                handleSaveRule = {
                    handleSaveRule
                }
                handleToggleFeed = {
                    handleToggleFeed
                }
                newSuppression = {
                    newSuppression
                }
                setNewSuppression = {
                    setNewSuppression
                }
                handleAddSuppression = {
                    handleAddSuppression
                }
                />
            )
        } </main>

        { /* INCIDENT PANEL */ }

        {
            slideContext && ( <>
                <div onClick = {
                    () =>
                    setSlideContext(
                        null
                    )
                }
                style = {
                    overlayStyle
                }
                />

                <IncidentPanel slideContext = {
                    slideContext
                }
                analystNotes = {
                    analystNotes
                }
                setAnalystNotes = {
                    setAnalystNotes
                }
                activeHostIsolated = {
                    activeHostIsolated
                }
                executeSOAR = {
                    executeSOAR
                }
                downloadPDF = {
                    downloadPDF
                }
                onClose = {
                    () =>
                    setSlideContext(
                        null
                    )
                }
                />
                </>
            )
        }
        </div>
    );
}

/* ============================================================
   KPI CARD
   ============================================================ */

function KpiCard({
    title,
    value,
    icon,
}) {
    return ( <
        div style = {
            {
                ...panelContainer,
                minHeight:
                    "100px",
            }
        } >
        <
        div style = {
            {
                fontSize: "24px",
            }
        } > { icon } <
        /div>

        <
        div style = {
            {
                color: "#64748b",
                fontSize: "11px",
                marginTop: "8px",
            }
        } > { title } <
        /div>

        <
        div style = {
            {
                fontSize: "26px",
                fontWeight: "bold",
                marginTop: "4px",
            }
        } > { value } <
        /div> < /
        div >
    );
}

/* ============================================================
   PANEL
   ============================================================ */

function Panel({
    title,
    subtitle,
    children,
}) {
    return ( <
        section style = {
            panelContainer
        } >
        <
        div style = {
            {
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "18px",
            }
        } >
        <
        div >
        <
        h3 style = {
            {
                margin: 0,
            }
        } > { title } <
        /h3>

        {
            subtitle && ( <
                div style = {
                    {
                        color: "#64748b",
                        fontSize: "11px",
                        marginTop: "4px",
                    }
                } > { subtitle } <
                /div>
            )
        } <
        /div> < /
        div >

        { children } <
        /section>
    );
}

/* ============================================================
   ALERT CARD
   ============================================================ */

function AlertCard({
    alert,
    onInvestigate,
}) {
    return ( <
        div style = {
            alertCardStyle
        } >
        <
        div style = {
            {
                display: "flex",
                justifyContent: "space-between",
                gap: "15px",
            }
        } >
        <
        div >
        <
        h4 style = {
            {
                margin: "0 0 8px",
            }
        } > {
            alert && alert.name ||
            "Unnamed Alert"
        } <
        /h4>

        <
        div style = {
            {
                color: "#94a3b8",
                fontSize: "12px",
            }
        } >
        Tactic: { " " } {
            alert && alert.tactic ||
                "N/A"
        } <
        br / >
        Host: { " " } {
            alert && alert.host ||
                "Unknown"
        } <
        br / >
        Source: { " " } {
            alert && alert.source ||
                "Unknown"
        } <
        br / >
        Assigned: { " " } {
            alert && alert.assigned ||
                "Unassigned"
        } <
        /div> < /
        div >

        <
        div style = {
            {
                whiteSpace: "nowrap",
            }
        } >
        <
        span style = {
            severityBadge(
                alert && alert.severity
            )
        } > {
            String(
                alert && alert.severity ||
                "UNKNOWN"
            ).toUpperCase()
        } <
        /span>

        <
        span style = {
            statusBadge
        } > {
            String(
                alert && alert.status ||
                "OPEN"
            ).toUpperCase()
        } <
        /span> < /
        div > <
        /div>

        <
        div style = {
            {
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginTop: "15px",
            }
        } >
        <
        small style = {
            {
                color: "#64748b",
            }
        } > {
            alert && alert.timestamp ?
            new Date(
                alert.timestamp
            ).toLocaleString() : "Unknown time"
        } <
        /small>

        <
        button onClick = {
            () =>
            onInvestigate(
                alert && alert.id,
                alert && alert.host
            )
        }
        style = {
            investigateButton
        } >
        Open Investigation→ <
        /button> < /
        div > <
        /div>
    );
}

/* ============================================================
   ADMIN
   ============================================================ */

function AdminView({
    adminData,
    rulesList,
    selectedRule,
    ruleContent,
    setRuleContent,
    loadRule,
    handleSaveRule,
    handleToggleFeed,
    newSuppression,
    setNewSuppression,
    handleAddSuppression,
}) {
    return ( <
        div >
        <
        h1 >
        Admin Control Center <
        /h1>

        <
        div style = {
            {
                display: "grid",
                gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
                gap: "20px",
            }
        } >
        <
        Panel title = "Threat Intel Feeds" > {
            (
                adminData && adminData.feeds || []
            ).map(
                (
                    feed,
                    index
                ) => ( <
                    div key = {
                        feed && feed.id ||
                        index
                    }
                    style = {
                        adminRow
                    } >
                    <
                    span > {
                        feed && feed.name
                    } <
                    /span>

                    <
                    button onClick = {
                        () =>
                        handleToggleFeed(
                            feed && feed.id
                        )
                    }
                    style = {
                        {
                            ...toggleButton,
                            background:
                                feed && feed.enabled ?
                                "#065f46" :
                                "#334155",
                        }
                    } > {
                        feed && feed.enabled ?
                        "Enabled" : "Disabled"
                    } <
                    /button> < /
                    div >
                )
            )
        } <
        /Panel>

        <
        Panel title = "Active Analysts" > {
            (
                adminData && adminData.users || []
            ).map(
                (
                    user,
                    index
                ) => ( <
                    div key = {
                        user && user.id ||
                        index
                    }
                    style = {
                        adminRow
                    } >
                    <
                    span > {
                        user && user.username
                    } <
                    /span>

                    <
                    span style = {
                        roleBadge
                    } > {
                        user && user.role
                    } <
                    /span> < /
                    div >
                )
            )
        } <
        /Panel>

        <
        Panel title = "Suppression Rules" >
        <
        div style = {
            {
                display: "flex",
                gap: "8px",
            }
        } >
        <
        input value = {
            newSuppression
        }
        onChange = {
            (
                event
            ) =>
            setNewSuppression(
                event
                .target
                .value
            )
        }
        placeholder = "IP or rule name"
        style = {
            adminInput
        }
        />

        <
        button onClick = {
            handleAddSuppression
        }
        style = {
            primaryButton
        } >
        Add <
        /button> < /
        div >

        <
        div style = {
            {
                marginTop: "15px",
                maxHeight: "160px",
                overflowY: "auto",
            }
        } > {
            (
                (adminData && adminData.suppressions) || []
            ).map(
                (
                    item,
                    index
                ) => ( <
                    div key = {
                        (item && item.id) ||
                        index
                    }
                    style = {
                        adminRow
                    } > {
                        (item && item.indicator)
                    } <
                    /div>
                )
            )
        } <
        /div> < /
        Panel >

        <
        div style = {
            {
                ...panelContainer,
                gridColumn:
                    "1 / -1",
            }
        } >
        <
        h3 >
        Live YARA Signature Editor <
        /h3>

        <
        div style = {
            {
                display: "grid",
                gridTemplateColumns: "240px 1fr",
                gap: "20px",
                marginTop: "20px",
            }
        } >
        <
        div > {
            rulesList.length ===
            0 ? ( <
                div style = {
                    emptyStyle
                } >
                No YARA rules found. <
                /div>
            ) : (
                rulesList.map(
                    (
                        rule
                    ) => ( <
                        button key = {
                            rule
                        }
                        onClick = {
                            () =>
                            loadRule(
                                rule
                            )
                        }
                        style = {
                            {
                                display: "block",
                                width: "100%",
                                textAlign: "left",
                                background: selectedRule ===
                                    rule ?
                                    "#2563eb" : "transparent",
                                color: "white",
                                border: "1px solid #334155",
                                padding: "10px",
                                marginBottom: "6px",
                                borderRadius: "5px",
                                cursor: "pointer",
                            }
                        } > {
                            rule
                        } <
                        /button>
                    )
                )
            )
        } <
        /div>

        <
        div >
        <
        Editor value = {
            ruleContent
        }
        onValueChange = {
            setRuleContent
        }
        highlight = {
            (
                code
            ) =>
            highlight(
                code,
                languages.clike
            )
        }
        padding = {
            20
        }
        style = {
            {
                fontFamily: "monospace",
                fontSize: 14,
                background: "#020617",
                minHeight: "400px",
                color: "#10b981",
                border: "1px solid #334155",
                borderRadius: "6px",
            }
        }
        placeholder = "Select a YARA rule..." /
        >

        <
        button onClick = {
            handleSaveRule
        }
        style = {
            {
                ...primaryButton,
                width:
                    "100%",
                    marginTop:
                    "10px",
            }
        } >
        Deploy to Scanner <
        /button> < /
        div > <
        /div> < /
        div > <
        /div> < /
        div >
    );
}

/* ============================================================
   INCIDENT PANEL
   ============================================================ */

function IncidentPanel({
    slideContext,
    analystNotes,
    setAnalystNotes,
    activeHostIsolated,
    executeSOAR,
    downloadPDF,
    onClose,
}) {
    return ( <
        aside style = {
            incidentPanelStyle
        } >
        <
        div style = {
            {
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
            }
        } >
        <
        div >
        <
        h2 style = {
            {
                color: "#38bdf8",
                margin: "0 0 8px",
            }
        } >
        Incident Control Room <
        /h2>

        <
        small style = {
            {
                color: "#94a3b8",
            }
        } >
        Target: { " " } {
            slideContext.host
        } <
        br / >
        Alert ID: { " " } {
            slideContext.originalId
        } <
        /small> < /
        div >

        <
        button onClick = {
            onClose
        }
        style = {
            closeButton
        } > ×
        <
        /button> < /
        div >

        <
        div style = {
            {
                marginTop: "25px",
            }
        } >
        <
        h3 >
        Active Response(SOAR) <
        /h3>

        <
        div style = {
            {
                display: "flex",
                gap: "10px",
                flexWrap: "wrap",
            }
        } >
        <
        button disabled = {
            activeHostIsolated
        }
        onClick = {
            () =>
            executeSOAR(
                "Isolate Host"
            )
        }
        style = {
            {
                ...soarButton,
                background:
                    activeHostIsolated ?
                    "#7f1d1d" :
                    "#b91c1c",
            }
        } > {
            activeHostIsolated ?
            "Host Isolated" : "Isolate Host"
        } <
        /button>

        <
        button onClick = {
            () =>
            executeSOAR(
                "Block IP"
            )
        }
        style = {
            {
                ...soarButton,
                background:
                    "#ea580c",
            }
        } >
        Block IP <
        /button> < /
        div > <
        /div>

        <
        div style = {
            {
                marginTop: "25px",
                flex: 1,
                overflowY: "auto",
            }
        } >
        <
        div style = {
            {
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
            }
        } >
        <
        h3 >
        Chain of Attack <
        /h3>

        <
        button onClick = {
            () =>
            downloadPDF(
                slideContext.originalId
            )
        }
        style = {
            exportButton
        } > 📄Export PDF <
        /button> < /
        div >

        {
            (
                slideContext.timeline || []
            ).length === 0 ? ( <
                div style = {
                    emptyStyle
                } >
                No timeline events available. <
                /div>
            ) : (
                slideContext.timeline.map(
                    (
                        event,
                        index
                    ) => ( <
                        div key = {
                            (event && event.id) ||
                            index
                        }
                        style = {
                            {
                                background: "#0f172a",
                                borderLeft: (event && event.is_incident) ?
                                    "4px solid #ef4444" : "4px solid #3b82f6",
                                padding: "15px",
                                marginBottom: "10px",
                                borderRadius: "0 5px 5px 0",
                            }
                        } >
                        <
                        small style = {
                            {
                                color: "#64748b",
                            }
                        } > {
                            (event && event.ts) ?
                            new Date(
                                event.ts
                            ).toLocaleString() : "Unknown"
                        } <
                        /small>

                        <
                        div style = {
                            {
                                fontWeight: "bold",
                                marginTop: "6px",
                            }
                        } > {
                            (event && event.proc) ||
                            "Unknown process"
                        } <
                        /div>

                        <
                        code style = {
                            {
                                display: "block",
                                marginTop: "8px",
                                color: "#10b981",
                                background: "#000",
                                padding: "10px",
                                borderRadius: "4px",
                                whiteSpace: "pre-wrap",
                                wordBreak: "break-word",
                            }
                        } > {
                            (event && event.cmd) ||
                            "Binary execution detected"
                        } <
                        /code> < /
                        div >
                    )
                )
            )
        }

        <
        div style = {
            {
                marginTop: "20px",
            }
        } >
        <
        label style = {
            formLabel
        } >
        Analyst Notes <
        /label>

        <
        textarea value = {
            analystNotes
        }
        onChange = {
            (
                event
            ) =>
            setAnalystNotes(
                event
                .target
                .value
            )
        }
        placeholder = "Enter investigation notes..."
        style = {
            notesStyle
        }
        /> < /
        div > <
        /div> < /
        aside >
    );
}

/* ============================================================
   TIMELINE BUILDER
   ============================================================ */

function buildTimeline(
    alerts
) {
    const buckets = {};

    alerts.forEach(
        (alert) => {
            if (!alert && alert.timestamp) {
                return;
            }

            const date =
                new Date(
                    alert.timestamp
                );

            if (
                Number.isNaN(
                    date.getTime()
                )
            ) {
                return;
            }

            const key =
                `${String(
                    date.getHours()
                ).padStart(
                    2,
                    "0"
                )}:00`;

            buckets[key] =
                (buckets[key] || 0) +
                1;
        }
    );

    return Object.entries(
            buckets
        )
        .sort(
            ([a], [b]) =>
            a.localeCompare(b)
        )
        .map(
            ([time, count]) => ({
                time,
                alerts: count,
            })
        );
}

/* ============================================================
   STYLES
   ============================================================ */

const loadingStyle = {
    minHeight: "100vh",
    display: "flex",
    flexDirection: "column",
    justifyContent: "center",
    alignItems: "center",
    background: "#0b1120",
    color: "white",
    fontSize: "18px",
};

const panelContainer = {
    background: "#111827",
    border: "1px solid #1e293b",
    borderRadius: "10px",
    padding: "20px",
};

const searchBarStyle = {
    display: "flex",
    gap: "15px",
    marginBottom: "25px",
    background: "#0f172a",
    padding: "15px",
    borderRadius: "8px",
    border: "1px solid #1e293b",
};

const searchInputStyle = {
    flex: 1,
    background: "transparent",
    border: "none",
    outline: "none",
    color: "#10b981",
    fontFamily: "monospace",
    fontSize: "14px",
};

const rangeStyle = {
    background: "#1e293b",
    color: "#e2e8f0",
    border: "1px solid #334155",
    padding: "8px 12px",
    borderRadius: "5px",
};

const headerStyle = {
    display: "flex",
    justifyContent: "space-between",
    marginBottom: "25px",
};

const liveBadgeStyle = {
    color: "#38bdf8",
    border: "1px solid #38bdf8",
    padding: "4px 9px",
    borderRadius: "15px",
    fontSize: "11px",
};

const kpiGrid = {
    display: "grid",
    gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
    gap: "15px",
    marginBottom: "25px",
};

const chartGrid = {
    display: "grid",
    gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
    gap: "20px",
    marginBottom: "25px",
};

const alertCardStyle = {
    background: "#0f172a",
    border: "1px solid #1e293b",
    padding: "18px",
    borderRadius: "7px",
    marginBottom: "10px",
};

const severityBadge =
    (severity) => {
        const value =
            String(
                severity ||
                ""
            ).toLowerCase();

        let background =
            "#1e293b";

        let color =
            "#94a3b8";

        if (
            value ===
            "critical"
        ) {
            background =
                "#450a0a";
            color =
                "#f87171";
        } else if (
            value ===
            "high"
        ) {
            background =
                "#78350f";
            color =
                "#fbbf24";
        } else if (
            value ===
            "medium"
        ) {
            background =
                "#713f12";
            color =
                "#fde047";
        }

        return {
            fontSize: "10px",
            padding: "4px 8px",
            borderRadius: "12px",
            background,
            color,
            marginRight: "7px",
            fontWeight: "bold",
        };
    };

const statusBadge = {
    fontSize: "10px",
    padding: "4px 8px",
    borderRadius: "12px",
    background: "#064e3b",
    color: "#34d399",
};

const investigateButton = {
    background: "transparent",
    color: "#38bdf8",
    border: "none",
    cursor: "pointer",
    fontSize: "12px",
};

const paginationFooter = {
    marginTop: "15px",
    paddingTop: "15px",
    borderTop: "1px solid #1e293b",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    color: "#94a3b8",
    fontSize: "12px",
};

const pageSelect = {
    background: "#0f172a",
    color: "white",
    border: "1px solid #334155",
    padding: "5px",
};

const pageButton = {
    background: "#1e293b",
    color: "white",
    border: "1px solid #334155",
    borderRadius: "4px",
    padding: "5px 10px",
    cursor: "pointer",
};

const primaryButton = {
    background: "#2563eb",
    color: "white",
    border: "none",
    padding: "10px 14px",
    borderRadius: "5px",
    cursor: "pointer",
    fontWeight: "bold",
};

const refreshButton = {
    ...primaryButton,
    background: "#dc2626",
};

const realtimeAlertBar = {
    background: "#450a0a",
    border: "1px solid #ef4444",
    color: "#fecaca",
    padding: "12px 16px",
    borderRadius: "7px",
    marginBottom: "20px",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
};

const tableStyle = {
    width: "100%",
    marginTop: "20px",
    borderCollapse: "collapse",
    fontSize: "12px",
};

const emptyStyle = {
    color: "#64748b",
    textAlign: "center",
    padding: "40px",
};

const radarCenter = {
    position: "absolute",
    top: "50%",
    left: "50%",
    transform: "translate(-50%, -50%)",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    pointerEvents: "none",
};

const overlayStyle = {
    position: "fixed",
    inset: 0,
    background: "rgba(0,0,0,0.55)",
    zIndex: 998,
};

const incidentPanelStyle = {
    position: "fixed",
    top: 0,
    right: 0,
    width: "620px",
    maxWidth: "100%",
    height: "100vh",
    background: "#020617",
    borderLeft: "1px solid #334155",
    boxShadow: "-10px 0 40px rgba(0,0,0,0.7)",
    zIndex: 999,
    padding: "25px",
    boxSizing: "border-box",
    display: "flex",
    flexDirection: "column",
};

const closeButton = {
    background: "transparent",
    border: "none",
    color: "#94a3b8",
    fontSize: "28px",
    cursor: "pointer",
};

const soarButton = {
    color: "white",
    border: "none",
    padding: "10px 15px",
    borderRadius: "5px",
    cursor: "pointer",
    fontWeight: "bold",
};

const exportButton = {
    background: "#10b981",
    color: "white",
    border: "none",
    padding: "7px 12px",
    borderRadius: "5px",
    cursor: "pointer",
};

const notesStyle = {
    width: "100%",
    height: "100px",
    boxSizing: "border-box",
    background: "#0f172a",
    border: "1px solid #334155",
    color: "white",
    padding: "10px",
    borderRadius: "5px",
    resize: "vertical",
};

const adminRow = {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "10px 0",
    borderBottom: "1px solid #1e293b",
    color: "#cbd5e1",
    fontSize: "13px",
};

const toggleButton = {
    color: "white",
    border: "none",
    padding: "5px 10px",
    borderRadius: "4px",
    cursor: "pointer",
};

const roleBadge = {
    background: "#0ea5e9",
    color: "white",
    padding: "3px 7px",
    borderRadius: "10px",
    fontSize: "10px",
};

const adminInput = {
    flex: 1,
    minWidth: 0,
    background: "#0f172a",
    color: "white",
    border: "1px solid #334155",
    borderRadius: "5px",
    padding: "9px",
};

const formLabel = {
    display: "block",
    color: "#94a3b8",
    fontSize: "12px",
    marginBottom: "6px",
};
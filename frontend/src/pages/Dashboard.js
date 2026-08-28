import React, {
    useCallback,
    useEffect,
    useMemo,
    useRef,
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
    createYaraRule,
    uploadYaraRules,
    updateAlertCase,
} from "../api";

import Navbar from "../components/Navbar";
import Button from "../components/ui/Button";
import Badge from "../components/ui/Badge";
import KpiStat from "../components/ui/KpiStat";
import Surface from "../components/ui/Surface";
import useGsapReveal from "../hooks/useGsapReveal";
import gsap from "gsap";
import "../styles/theme.css";

import {
    highlight,
    languages,
} from "prismjs/components/prism-core";

import "prismjs/components/prism-clike";
import "prismjs/themes/prism-tomorrow.css";

import axios from "axios";
import {
    canAccessAdminPanel,
    getStoredToken,
    getStoredUser,
    hasPermission,
} from "../auth";

/* ============================================================
   BACKEND
   ============================================================ */

const BACKEND_URL =
  process.env.REACT_APP_API_BASE_URL || "";
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
    "#5ec8ff",
    "#3ee0a2",
    "#f0b429",
    "#ff5c7a",
    "#8fd3c8",
    "#74a7ff",
];

const getAuthHeaders = () => ({
    Authorization: `Bearer ${getStoredToken()}`,
});

/* ============================================================
   COMPONENT
   ============================================================ */

export default function Dashboard({ onLogout, currentUser, embedded = false, initialView = "dashboard" }) {
    const revealRootRef = useRef(null);
    const sessionUser = currentUser || getStoredUser();
    const [data, setData] = useState(null);
    const [adminData, setAdminData] = useState(null);

    const [currentView, setCurrentView] =
    useState(initialView || "dashboard");

    const canWriteAlerts = hasPermission("alerts.write", sessionUser);
    const canExecuteSoar = hasPermission("soar.execute", sessionUser);
    const canManageAdmin = canAccessAdminPanel(sessionUser);

    useGsapReveal(revealRootRef, [currentView, data]);

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
        if (!canAccessAdminPanel(getStoredUser())) {
            setAdminData(null);
            setRulesList([]);
            return;
        }
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
            // Empty object marks "loaded" so Admin Console is not stuck on the splash loader.
            setAdminData({});
        }
    }, []);

    /* ========================================================
       LOAD DATA
       ======================================================== */

    useEffect(() => {
        setCurrentView(initialView || "dashboard");
    }, [initialView]);

    useEffect(() => {
        if (currentView === "dashboard") {
            refreshDashboard();
        } else if (canManageAdmin) {
            refreshAdmin();
        } else {
            setCurrentView("dashboard");
        }
    }, [
        currentView,
        refreshDashboard,
        refreshAdmin,
        canManageAdmin,
    ]);

    /* ========================================================
       REALTIME SOCKET.IO
       ======================================================== */

    /* ========================================================        REALTIME SOCKET.IO        ======================================================== */
    useEffect(() => {
        // Connect via BACKEND_URL if set, or fall back to current origin (Nginx proxy)
        const socketURL = BACKEND_URL || window.location.origin;
        const socket = io(

            socketURL, {
                path: "/socket.io/",
                transports: ["websocket", "polling"],  // Allow both WebSocket and polling fallback
                reconnection: true,
                reconnectionAttempts: Infinity,
                reconnectionDelay: 1000,
                reconnectionDelayMax: 5000,
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
                    total_alerts: (((previous.metadata && previous.metadata.total_alerts) || 0)) + pendingAlerts.length,
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
        const alerts = (data && data.alerts) || [];
        const query = searchQuery.trim().toLowerCase();

        if (!query) {
            return alerts;
        }

        return alerts.filter((alert) => {
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

            return searchable.includes(query);
        });
    }, [data, searchQuery]);

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
            ((data && data.charts && data.charts.tactics) || [])
        ).map((item) => ({
            name: (item && item.name) ||
                "Unknown",
            value: Number((item && item.value)) || 0,
        }));
    }, [data]);

    const hostChartData = useMemo(() => {
        return (
            ((data && data.charts && data.charts.hosts) || [])
        ).map((item) => ({
            name: (item && item.name) ||
                "Unknown",
            count: Number((item && item.count)) || 0,
        }));
    }, [data]);

    const severityRadarData =
        useMemo(() => {
            const alerts =
                ((data && data.alerts) || []);

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
                            (alert && alert.severity) ||
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

                const payload = (response && response.data) || {};
                setSlideContext({
                    ...payload,
                    host,
                    originalId: id,
                });

                setAnalystNotes(payload.analyst_notes || "");
                setActiveHostIsolated(false);
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

    const handleCreateYaraRule = async () => {
        const raw = window.prompt(
            "New YARA rule filename (example: custom_detect.yar):",
            "custom_detect.yar"
        );
        if (!raw) return;

        try {
            const response = await createYaraRule(raw);
            const file =
                (response && response.data && response.data.file) || raw;
            const content =
                (response && response.data && response.data.content) || "";
            await refreshAdmin();
            setSelectedRule(file);
            setRuleContent(content);
            window.alert(`Created YARA rule: ${file}`);
        } catch (error) {
            console.error("YARA create error:", error);
            window.alert(
                (error.response &&
                    error.response.data &&
                    error.response.data.error) ||
                    "Failed to create YARA rule."
            );
        }
    };

    const handleUploadYaraRules = async (event) => {
        const files = event.target.files;
        if (!files || files.length === 0) return;

        try {
            const response = await uploadYaraRules(files);
            const saved =
                (response && response.data && response.data.saved) || [];
            await refreshAdmin();
            if (saved[0]) {
                await loadRule(saved[0]);
            }
            window.alert(
                `Uploaded ${saved.length} YARA rule(s): ${saved.join(", ")}`
            );
        } catch (error) {
            console.error("YARA upload error:", error);
            window.alert(
                (error.response &&
                    error.response.data &&
                    error.response.data.error) ||
                    "Failed to upload YARA rules."
            );
        } finally {
            event.target.value = "";
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

                await refreshDashboard();
                if (currentView === "admin") {
                    await refreshAdmin();
                }

                const summary =
                    (response && response.data && response.data.summary) || {};
                const errors = summary.errors || [];

                window.alert(
                    `Sync complete: ${
                        summary.feeds_checked ||
                        0
                    } feeds checked, ${
                        summary.ioc_added ||
                        0
                    } IOCs added` +
                    (summary.ioc_updated
                        ? `, ${summary.ioc_updated} updated`
                        : "") +
                    (errors.length
                        ? `\nErrors: ${errors
                              .map((item) => `${item.feed}: ${item.error}`)
                              .join("; ")}`
                        : "")
                );
            } catch (error) {
                console.error(
                    "Feed sync error:",
                    error
                );

                window.alert(
                    (error.response &&
                        error.response.data &&
                        error.response.data.error) ||
                        "Feed sync failed. Analyst/admin role required."
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
            const token = getStoredToken();

            const url =
                `${BACKEND_URL}/api/report/${id}?token=${encodeURIComponent(
                    token || ""
                )}&v=${Date.now()}`;

            window.open(
                url,
                "_blank",
                "noopener,noreferrer"
            );
        };

    /* ========================================================
       LOADING
       ======================================================== */

    // Dashboard view needs /api/dashboard payload. Admin console only needs adminData —
    // previously !data blocked /admin/console forever because dashboard was never fetched.
    const waitingDashboard = currentView === "dashboard" && !data;
    const waitingAdmin =
        currentView === "admin" && canManageAdmin && adminData === null;

    if (waitingDashboard || waitingAdmin) {
        return (
            <div className="loader-screen">
                <div>
                    <div className="loader-orb" aria-hidden />
                    <div style={{ fontFamily: "var(--font-display)", fontSize: "1.35rem" }}>
                        {currentView === "admin"
                            ? "Loading Admin Console"
                            : "Initializing SOC Environment"}
                    </div>
                    <div style={{ marginTop: 10, color: "var(--text-muted)", fontSize: 13 }}>
                        Connecting to {BACKEND_URL}
                    </div>
                </div>
            </div>
        );
    }

    /* ========================================================
       RENDER
       ======================================================== */

    return (
        <div className="soc-shell" ref={revealRootRef}>
        {!embedded ? (
        <Navbar
            onNavigate={setCurrentView}
            onLogout={onLogout}
            currentView={currentView}
            currentUser={sessionUser}
        />
        ) : null}

        <main className={embedded ? "soc-main soc-main--embedded" : "soc-main"}>
            {currentView === "dashboard" ? (
                <>
                { /* SEARCH */ }

                <div className="surface soc-toolbar" data-reveal>
                    <input
                        type="text"
                        className="field__input field__input--mono"
                        value={searchQuery}
                        onChange={(event) => {
                            setSearchQuery(event.target.value);
                            setCurrentPage(1);
                        }}
                        placeholder='index=main sourcetype=endpoint | search host="WIN-SRV-01"'
                    />
                    <select
                        className="field__select"
                        value={range}
                        onChange={(event) => setRange(event.target.value)}
                        style={{ width: "auto", minWidth: 140 }}
                    >
                        {TIME_RANGES.map((item) => (
                            <option key={item} value={item}>
                                Last {item}
                            </option>
                        ))}
                    </select>
                </div>

                <div className="soc-header" data-reveal>
                    <div>
                        <Badge tone="live">Live SOC Console</Badge>
                        <h1>Threat Hunting Dashboard</h1>
                        <p>
                            Real-time alert monitoring, threat analytics, IOC feeds
                            and incident response.
                        </p>
                    </div>
                    <div className="soc-meta">
                        <div>
                            Socket:{" "}
                            <strong
                                style={{
                                    color:
                                        socketStatus === "online"
                                            ? "var(--ok)"
                                            : "var(--warn)",
                                }}
                            >
                                {socketStatus.toUpperCase()}
                            </strong>
                        </div>
                        <div>
                            Events:{" "}
                            {(data && data.metadata && data.metadata.total_events) || 0}
                        </div>
                        <div>
                            Alerts:{" "}
                            {(data && data.metadata && data.metadata.total_alerts) ?? 0}
                        </div>
                        <div>
                            Last ingest:{" "}
                            {(data && data.metadata && data.metadata.last_ingest) || "N/A"}
                        </div>
                    </div>
                </div>

                <div className="kpi-grid" data-reveal>
                    <KpiStat
                        title="Total Alerts"
                        value={
                            (data && data.kpis && data.kpis.total_alerts) ??
                            (data && data.metadata && data.metadata.total_alerts) ??
                            0
                        }
                        hint="Selected time range"
                        icon="◈"
                    />
                    <KpiStat
                        title="High / Critical"
                        value={(data && data.kpis && data.kpis.high_or_above) || 0}
                        hint="Priority queue"
                        icon="▲"
                    />
                    <KpiStat
                        title="Events"
                        value={(data && data.metadata && data.metadata.total_events) || 0}
                        hint="Ingested telemetry"
                        icon="◎"
                    />
                    <KpiStat
                        title="Live Socket"
                        value={socketStatus === "online" ? "ONLINE" : "OFFLINE"}
                        hint="Realtime channel"
                        icon="◉"
                    />
                </div>

                <div className="chart-grid" data-reveal>
                { /* TIMELINE */ }

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
                        ((data && data.alerts) || [])
                    )
                } >
                <
                CartesianGrid stroke = "#1e293b" />

                <
                XAxis dataKey = "time"
                stroke = "#64748b" />

                <
                YAxis allowDecimals = {
                    false
                }
                stroke = "#64748b" />

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
                stroke = "#3ee0a2"
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
                PolarGrid stroke = "#334155" />

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
                stroke = "#5ec8ff"
                fill = "#5ec8ff"
                fillOpacity = {
                    0.28
                }
                />

                <
                Tooltip contentStyle = {
                    {
                        background: "#020617",
                        border: "1px solid #334155",
                    }
                }
                /> </RadarChart> </ResponsiveContainer>

                <
                div style = {
                    radarCenter
                } >
                <
                span > {
                    (
                        ((data && data.alerts) || [])
                    ).length
                } </span> <
                small >
                THREATS </small> </div> </div> </Panel>

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
                stroke = "#64748b" />

                <
                YAxis type = "category"
                dataKey = "name"
                width = {
                    100
                }
                stroke = "#64748b" />

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
                fill = "#3ee0a2"
                radius = {
                    [
                        0,
                        5,
                        5,
                        0,
                    ]
                }
                /> </BarChart> </ResponsiveContainer> </div> </Panel>

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
                } </Pie>

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
                </PieChart> </ResponsiveContainer> </div> </Panel> </div>

                { /* LIVE ALERT TOAST */ }

                {pendingAlerts.length > 0 && (
                    <div className="toast-bar" data-reveal>
                        <span>
                            <strong>{pendingAlerts.length}</strong> new realtime
                            alert{pendingAlerts.length > 1 ? "s" : ""} received
                        </span>
                        <Button variant="danger" size="sm" onClick={mergePendingAlerts}>
                            Load New Alerts
                        </Button>
                    </div>
                )}

                <Panel
                    title="Active Alerts"
                    subtitle={`${filteredAlerts.length} alerts in queue`}
                >
                    <div className="alerts-table">
                        <div className="alerts-table__scroll">
                            <div className="alerts-table__head" aria-hidden>
                                <span>Alert</span>
                                <span>Host</span>
                                <span>Severity</span>
                                <span>Status</span>
                                <span>Detected</span>
                                <span style={{ textAlign: "right" }}>Action</span>
                            </div>

                            {currentAlerts.length === 0 ? (
                                <div style={emptyStyle}>
                                    No alerts match your criteria.
                                </div>
                            ) : (
                                currentAlerts.map((alert, index) => (
                                    <AlertCard
                                        key={
                                            (alert && alert.id) ||
                                            `${alert && alert.name}-${alert && alert.host}-${index}`
                                        }
                                        alert={alert}
                                        onInvestigate={handleInvestigate}
                                    />
                                ))
                            )}
                        </div>
                    </div>

                    <div className="alerts-pagination">
                        <div className="alerts-pagination__meta">
                            Showing {currentAlerts.length} of {filteredAlerts.length} · Page{" "}
                            {safeCurrentPage} of {totalPages}
                        </div>
                        <div className="alerts-pagination__controls">
                            <select
                                className="field__select"
                                value={rowsPerPage}
                                onChange={(event) => {
                                    setRowsPerPage(Number(event.target.value));
                                    setCurrentPage(1);
                                }}
                            >
                                <option value={5}>5 rows</option>
                                <option value={10}>10 rows</option>
                                <option value={25}>25 rows</option>
                                <option value={50}>50 rows</option>
                            </select>
                            <Button
                                size="sm"
                                disabled={safeCurrentPage <= 1}
                                onClick={() =>
                                    setCurrentPage((page) => Math.max(1, page - 1))
                                }
                            >
                                Prev
                            </Button>
                            <Button
                                size="sm"
                                disabled={safeCurrentPage >= totalPages}
                                onClick={() =>
                                    setCurrentPage((page) =>
                                        Math.min(totalPages, page + 1)
                                    )
                                }
                            >
                                Next
                            </Button>
                        </div>
                    </div>
                </Panel>

                <Panel
                    title="IOC Feeds"
                    subtitle={`${(data && data.ioc_stats && data.ioc_stats.total) || 0} indicators in watchlist`}
                >
                    <div
                        style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            gap: 12,
                            flexWrap: "wrap",
                            marginBottom: 14,
                        }}
                    >
                        <div style={{ color: "var(--text-muted)", fontSize: 13 }}>
                            Pulls enabled threat-intel sources into the local IOC
                            table for rule matching (`ioc_ip_match`,
                            `ioc_domain_match`, `ioc_hash_match`).
                        </div>
                        {hasPermission("ioc.write", sessionUser) ? (
                        <Button variant="primary" size="sm" onClick={handleSyncFeeds}>
                            Sync Live Feeds
                        </Button>
                        ) : null}
                    </div>

                    <div className="alerts-table">
                        <div className="alerts-table__scroll" style={{ maxHeight: 320 }}>
                            <div
                                className="alerts-table__head"
                                style={{
                                    gridTemplateColumns:
                                        "1.4fr 0.6fr 0.7fr 1fr 1.4fr",
                                }}
                            >
                                <span>Name</span>
                                <span>Type</span>
                                <span>Enabled</span>
                                <span>Last Sync</span>
                                <span>Status</span>
                            </div>
                            {((data && data.feeds) || []).length === 0 ? (
                                <div style={emptyStyle}>No feed sources configured.</div>
                            ) : (
                                ((data && data.feeds) || []).map((feed, index) => (
                                    <div
                                        key={(feed && feed.id) || (feed && feed.name) || index}
                                        className="alert-row"
                                        style={{
                                            gridTemplateColumns:
                                                "1.4fr 0.6fr 0.7fr 1fr 1.4fr",
                                        }}
                                    >
                                        <div>
                                            <div className="alert-row__title">
                                                {(feed && feed.name) || "Unnamed feed"}
                                            </div>
                                            <div className="alert-row__sub">
                                                {(feed && feed.url) || ""}
                                            </div>
                                        </div>
                                        <div className="alert-row__host">
                                            {(feed && feed.type) || "n/a"}
                                        </div>
                                        <div>
                                            <Badge
                                                tone={
                                                    feed && feed.enabled
                                                        ? "ok"
                                                        : "warn"
                                                }
                                            >
                                                {feed && feed.enabled
                                                    ? "ENABLED"
                                                    : "DISABLED"}
                                            </Badge>
                                        </div>
                                        <div className="alert-row__time">
                                            {(feed &&
                                                feed.last_sync &&
                                                new Date(
                                                    feed.last_sync
                                                ).toLocaleString()) ||
                                                "Never"}
                                        </div>
                                        <div className="alert-row__sub">
                                            {(feed && feed.last_error) ||
                                                "Ready"}
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
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
                handleCreateYaraRule={handleCreateYaraRule}
                handleUploadYaraRules={handleUploadYaraRules}
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

                <IncidentPanel
                    slideContext={slideContext}
                    analystNotes={analystNotes}
                    setAnalystNotes={setAnalystNotes}
                    activeHostIsolated={activeHostIsolated}
                    executeSOAR={executeSOAR}
                    downloadPDF={downloadPDF}
                    canWriteAlerts={canWriteAlerts}
                    canExecuteSoar={canExecuteSoar}
                    onCaseUpdated={(updated) => {
                        setSlideContext((prev) =>
                            prev
                                ? {
                                      ...prev,
                                      status: updated.status,
                                      assigned: updated.assigned_to || "",
                                      assigned_to: updated.assigned_to || "",
                                      analyst_notes: updated.analyst_notes || "",
                                  }
                                : prev
                        );
                        setAnalystNotes(updated.analyst_notes || "");
                        refreshDashboard();
                    }}
                    onClose={() => setSlideContext(null)}
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

function Panel({ title, subtitle, children }) {
    return (
        <Surface title={title} subtitle={subtitle}>
            {children}
        </Surface>
    );
}

/* ============================================================
   ALERT CARD
   ============================================================ */

function AlertCard({
    alert,
    onInvestigate,
}) {
    const cardRef = useRef(null);

    useEffect(() => {
        if (!cardRef.current) return undefined;
        const tween = gsap.fromTo(
            cardRef.current,
            { y: 8, opacity: 0 },
            { y: 0, opacity: 1, duration: 0.32, ease: "power2.out" }
        );
        return () => tween.kill();
    }, []);

    const detected =
        alert && alert.timestamp
            ? new Date(alert.timestamp).toLocaleString()
            : "Unknown time";

    return (
        <div ref={cardRef} className="alert-row" role="row">
            <div className="alert-row__main">
                <h4 className="alert-row__title">
                    {(alert && alert.name) || "Unnamed Alert"}
                </h4>
                <div className="alert-row__sub">
                    {(alert && alert.tactic) || "N/A"} ·{" "}
                    {(alert && alert.source) || "Unknown source"} ·{" "}
                    {(alert && alert.assigned) || "Unassigned"}
                </div>
            </div>

            <div className="alert-row__host">
                {(alert && alert.host) || "Unknown"}
            </div>

            <div className="alert-row__badges">
                <Badge tone={(alert && alert.severity) || "low"}>
                    {String((alert && alert.severity) || "UNKNOWN").toUpperCase()}
                </Badge>
            </div>

            <div className="alert-row__badges">
                <Badge tone={(alert && alert.status) || "open"}>
                    {String((alert && alert.status) || "OPEN").toUpperCase()}
                </Badge>
            </div>

            <div className="alert-row__time">{detected}</div>

            <div className="alert-row__actions">
                <Button
                    size="sm"
                    variant="info"
                    onClick={() =>
                        onInvestigate(alert && alert.id, alert && alert.host)
                    }
                >
                    Investigate
                </Button>
            </div>
        </div>
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
    handleCreateYaraRule,
    handleUploadYaraRules,
    handleToggleFeed,
    newSuppression,
    setNewSuppression,
    handleAddSuppression,
}) {
    const uploadInputRef = useRef(null);

    return (
        <div data-reveal>
        <div className="soc-header">
            <div>
                <Badge tone="live">Control Plane</Badge>
                <h1>Admin Control Center</h1>
                <p>Manage feeds, analysts, suppressions, and detection rules.</p>
            </div>
        </div>

        <div
            style={{
                display: "grid",
                gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
                gap: "20px",
            }}
        >
        <
        Panel title = "Threat Intel Feeds" > {
            (
                ((adminData && adminData.feeds) || [])
            ).map(
                (
                    feed,
                    index
                ) => ( <
                    div key = {
                        (feed && feed.id) ||
                        index
                    }
                    style = {
                        adminRow
                    } >
                    <
                    span > {
                        feed && feed.name
                    } </span>

                    <Button
                        size="sm"
                        variant={feed && feed.enabled ? "primary" : "ghost"}
                        onClick={() => handleToggleFeed(feed && feed.id)}
                    >
                        {feed && feed.enabled ? "Enabled" : "Disabled"}
                    </Button>
                    </div>
                )
            )
        } </Panel>

        <
        Panel title = "Active Analysts" > {
            (
                ((adminData && adminData.users) || [])
            ).map(
                (
                    user,
                    index
                ) => ( <
                    div key = {
                        (user && user.id) ||
                        index
                    }
                    style = {
                        adminRow
                    } >
                    <
                    span > {
                        user && user.username
                    } </span>

                    <
                    span style = {
                        roleBadge
                    } > {
                        user && user.role
                    } </span> </div>
                )
            )
        } </Panel>

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

        <Button variant="primary" size="sm" onClick={handleAddSuppression}>
            Add
        </Button>
        </div>

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
                    } </div>
                )
            )
        } </div> </Panel>

        <div
            style={{
                ...panelContainer,
                gridColumn: "1 / -1",
            }}
        >
        <div
            style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 12,
                flexWrap: "wrap",
            }}
        >
            <h3 style={{ margin: 0 }}>Live YARA Signature Editor</h3>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <input
                    ref={uploadInputRef}
                    type="file"
                    accept=".yar,text/plain"
                    multiple
                    style={{ display: "none" }}
                    onChange={handleUploadYaraRules}
                />
                <Button
                    size="sm"
                    variant="info"
                    onClick={() =>
                        uploadInputRef.current &&
                        uploadInputRef.current.click()
                    }
                >
                    Upload YARA
                </Button>
                <Button size="sm" variant="primary" onClick={handleCreateYaraRule}>
                    Add New Rule
                </Button>
            </div>
        </div>

        <div
            style={{
                display: "grid",
                gridTemplateColumns: "240px 1fr",
                gap: "20px",
                marginTop: "20px",
            }}
        >
        <div>
            {rulesList.length === 0 ? (
                <div style={emptyStyle}>No YARA rules found.</div>
            ) : (
                rulesList.map((rule) => (
                    <button
                        key={rule}
                        onClick={() => loadRule(rule)}
                        style={{
                            display: "block",
                            width: "100%",
                            textAlign: "left",
                            background:
                                selectedRule === rule
                                    ? "#2563eb"
                                    : "transparent",
                            color: "white",
                            border: "1px solid #334155",
                            padding: "10px",
                            marginBottom: "6px",
                            borderRadius: "5px",
                            cursor: "pointer",
                        }}
                    >
                        {rule}
                    </button>
                ))
            )}
        </div>

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
        placeholder = "Select a YARA rule..." />

        <Button
            variant="primary"
            block
            onClick={handleSaveRule}
            style={{ marginTop: 10 }}
        >
            Deploy to Scanner
        </Button>
        </div>
        </div>
        </div>
        </div>
        </div>
    );
}

/* ============================================================
   INCIDENT PANEL
   ============================================================ */

const CASE_STATUS_OPTIONS = [
    "Open",
    "In Progress",
    "Quarantine",
    "False Positive",
    "Resolved",
];

const ROLE_ASSIGN_OPTIONS = ["admin", "analyst", "viewer"];

function IncidentPanel({
    slideContext,
    analystNotes,
    setAnalystNotes,
    activeHostIsolated,
    executeSOAR,
    downloadPDF,
    canWriteAlerts = false,
    canExecuteSoar = false,
    onCaseUpdated,
    onClose,
}) {
    const panelRef = useRef(null);
    const [caseStatus, setCaseStatus] = useState(
        slideContext.status || "Open"
    );
    const [assignedTo, setAssignedTo] = useState(
        slideContext.assigned_to || slideContext.assigned || ""
    );
    const [savingCase, setSavingCase] = useState(false);
    const [caseMessage, setCaseMessage] = useState("");

    useEffect(() => {
        setCaseStatus(slideContext.status || "Open");
        setAssignedTo(slideContext.assigned_to || slideContext.assigned || "");
        setCaseMessage("");
    }, [slideContext]);

    useEffect(() => {
        if (!panelRef.current) return undefined;
        const tween = gsap.fromTo(
            panelRef.current,
            { x: 80, opacity: 0 },
            { x: 0, opacity: 1, duration: 0.45, ease: "power3.out" }
        );
        return () => tween.kill();
    }, []);

    const assigneeOptions = useMemo(() => {
        const users = (slideContext.assignees || []).map((user) => user.username);
        const merged = Array.from(
            new Set([
                ...ROLE_ASSIGN_OPTIONS,
                ...users,
                assignedTo,
            ].filter(Boolean))
        );
        return merged;
    }, [slideContext.assignees, assignedTo]);

    const handleSaveCase = async () => {
        setSavingCase(true);
        setCaseMessage("");
        try {
            const response = await updateAlertCase(slideContext.originalId, {
                status: caseStatus,
                assigned_to: assignedTo,
                analyst_notes: analystNotes,
            });
            if (onCaseUpdated) {
                onCaseUpdated(response.data);
            }
            setCaseMessage("Case updated successfully.");
        } catch (error) {
            console.error("Case update failed:", error);
            const errBody =
                error.response && error.response.data && error.response.data.error;
            const errMsg =
                typeof errBody === "object" && errBody
                    ? errBody.message
                    : errBody;
            setCaseMessage(
                errMsg ||
                    "Unable to update case. Analyst role or higher required."
            );
        } finally {
            setSavingCase(false);
        }
    };

    return (
        <aside ref={panelRef} style={incidentPanelStyle}>
        <div
            style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
            }}
        >
        <div>
        <h2
            style={{
                color: "var(--accent)",
                margin: "0 0 8px",
                fontFamily: "var(--font-display)",
            }}
        >
        Incident Control Room
        </h2>

        <small style={{ color: "#94a3b8" }}>
            Target: {slideContext.host}
            <br />
            Alert ID: {slideContext.originalId}
        </small>
        <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
            <Badge tone={caseStatus}>{String(caseStatus).toUpperCase()}</Badge>
            <Badge tone="info">
                {assignedTo ? `ASSIGNED: ${assignedTo}` : "UNASSIGNED"}
            </Badge>
        </div>
        </div>

        <button onClick={onClose} style={closeButton}>
            ×
        </button>
        </div>

        {canWriteAlerts ? (
        <div className="case-controls">
            <label className="field" style={{ marginBottom: 0 }}>
                <span className="field__label">Case Status</span>
                <select
                    className="field__select"
                    value={caseStatus}
                    onChange={(event) => setCaseStatus(event.target.value)}
                >
                    {CASE_STATUS_OPTIONS.map((status) => (
                        <option key={status} value={status}>
                            {status}
                        </option>
                    ))}
                </select>
            </label>

            <label className="field" style={{ marginBottom: 0 }}>
                <span className="field__label">Assign Task</span>
                <select
                    className="field__select"
                    value={assignedTo}
                    onChange={(event) => setAssignedTo(event.target.value)}
                >
                    <option value="">Unassigned</option>
                    {assigneeOptions.map((name) => (
                        <option key={name} value={name}>
                            {name}
                        </option>
                    ))}
                </select>
            </label>

            <div className="case-controls__hint">
                Status includes Quarantine. Assign to a role (admin / analyst / viewer)
                or a specific user.
            </div>

            <div className="case-controls__actions">
                <Button
                    size="sm"
                    variant="primary"
                    disabled={savingCase}
                    onClick={handleSaveCase}
                >
                    {savingCase ? "Saving..." : "Save Case"}
                </Button>
            </div>

            {caseMessage ? (
                <div className="case-controls__hint" style={{ color: "var(--accent)" }}>
                    {caseMessage}
                </div>
            ) : null}
        </div>
        ) : (
            <div className="case-controls__hint" style={{ marginTop: 16 }}>
                Read-only access — case updates require analyst or admin.
            </div>
        )}

        {canExecuteSoar ? (
        <div style={{ marginTop: "25px" }}>
        <h3>Active Response (SOAR) — SIMULATION MODE</h3>

        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
        <button
            disabled={activeHostIsolated}
            onClick={() => executeSOAR("Isolate Host")}
            style={{
                ...soarButton,
                background: activeHostIsolated ? "#7f1d1d" : "#b91c1c",
            }}
        >
            {activeHostIsolated ? "Host Isolated" : "Isolate Host"}
        </button>

        <button
            onClick={() => executeSOAR("Block IP")}
            style={{ ...soarButton, background: "#ea580c" }}
        >
            Block IP
        </button>
        </div>
        </div>
        ) : null}

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
        Chain of Attack </h3>

        <
        button onClick = {
            () =>
            downloadPDF(
                slideContext.originalId
            )
        }
        style = {
            exportButton
        } > 📄Export PDF </button> </div>

        {
            (
                slideContext.timeline || []
            ).length === 0 ? ( <
                div style = {
                    emptyStyle
                } >
                No timeline events available. </div>
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
                        } </small>

                        <
                        div style = {
                            {
                                fontWeight: "bold",
                                marginTop: "6px",
                            }
                        } > {
                            (event && event.proc) ||
                            "Unknown process"
                        } </div>

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
                        } </code> </div>
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
        Analyst Notes </label>

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
        /> </div> </div> </aside>
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


const panelContainer = {
    background: "#111827",
    border: "1px solid #1e293b",
    borderRadius: "10px",
    padding: "20px",
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
    background: "rgba(2, 6, 12, 0.62)",
    backdropFilter: "blur(3px)",
    zIndex: 998,
};

const incidentPanelStyle = {
    position: "fixed",
    top: 0,
    right: 0,
    width: "min(620px, 100%)",
    height: "100vh",
    background: "linear-gradient(180deg, #081018, #05090e)",
    borderLeft: "1px solid rgba(148, 197, 184, 0.14)",
    boxShadow: "-20px 0 60px rgba(0, 0, 0, 0.55)",
    zIndex: 999,
    padding: "1.4rem",
    boxSizing: "border-box",
    display: "flex",
    flexDirection: "column",
    overflow: "auto",
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
import { useEffect, useState, useRef } from "react";

import {
  Activity,
  AlertTriangle,
  CheckCircle,
  Globe,
  LayoutDashboard,
  LockKeyhole,
  Mail,
  QrCode,
  RefreshCw,
  Shield,
  ShieldAlert,
  UserRound,
  Zap,
  Search,
  X,
  Image as ImageIcon,
  Video,
  Upload,
  LogOut,
  KeyRound,
  ShieldCheck,
  Bell,
  Calendar,
  Camera,
  Layers,
  Menu,
} from "lucide-react";

import "./App.css";

const BACKEND_RENDER_URL = "https://cyberguard-code-warriers.onrender.com";
const API = (import.meta.env.VITE_API_URL || (import.meta.env.DEV ? "http://127.0.0.1:8000" : BACKEND_RENDER_URL)).replace(/\/$/, "");

function severityClass(severity) {
  if (!severity) {
    return "severity safe";
  }
  return `severity ${String(severity).toLowerCase()}`;
}

function App() {
  const [page, setPage] = useState("dashboard");

  const [stats, setStats] = useState(() => {
    try {
      const cached = localStorage.getItem("cg_stats");
      return cached ? JSON.parse(cached) : null;
    } catch {
      return null;
    }
  });
  const [events, setEvents] = useState(() => {
    try {
      const cached = localStorage.getItem("cg_events");
      return cached ? JSON.parse(cached) : [];
    } catch {
      return [];
    }
  });

  const [loading, setLoading] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [toast, setToast] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  const [currentDate, setCurrentDate] = useState("May 5, 2026");
  const [currentTime, setCurrentTime] = useState("20:07 (IST)");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    function updateClock() {
      const now = new Date();
      const options = { month: "short", day: "numeric", year: "numeric" };
      setCurrentDate(now.toLocaleDateString("en-US", options));
      const hours = String(now.getHours()).padStart(2, "0");
      const minutes = String(now.getMinutes()).padStart(2, "0");
      setCurrentTime(`${hours}:${minutes} (IST)`);
    }
    updateClock();
    const interval = setInterval(updateClock, 1000);
    return () => clearInterval(interval);
  }, []);

  // ==========================================================
  // LOAD DASHBOARD
  // ==========================================================

  async function loadDashboard() {
    try {
      const [statsResponse, eventsResponse] = await Promise.all([
        fetch(`${API}/dashboard/stats`),
        fetch(`${API}/events`),
      ]);

      if (!statsResponse.ok || !eventsResponse.ok) {
        throw new Error("Backend unavailable");
      }

      const statsData = await statsResponse.json();
      const eventsData = await eventsResponse.json();

      setStats(statsData);
      setEvents(eventsData.events || []);
      try {
        localStorage.setItem("cg_stats", JSON.stringify(statsData));
        localStorage.setItem("cg_events", JSON.stringify(eventsData.events || []));
      } catch {}
    } catch (error) {
      console.error(error);

      showToast("Unable to connect to CYBERGUARD-X backend");
    }
  }

  // ==========================================================
  // AUTO REFRESH
  // ==========================================================

  useEffect(() => {
    loadDashboard();

    const timer = setInterval(loadDashboard, 5000);

    return () => clearInterval(timer);
  }, []);

  // ==========================================================
  // TOAST
  // ==========================================================

  function showToast(message) {
    setToast(message);

    setTimeout(() => {
      setToast("");
    }, 3000);
  }

  // ==========================================================
  // NAVIGATION
  // ==========================================================

  function navigate(target) {
    setPage(target);
    setMobileMenuOpen(false);

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  }

  // ==========================================================
  // SEVERITY
  // ==========================================================

  function severityClass(severity) {
    if (!severity) {
      return "severity safe";
    }

    return `severity ${severity.toLowerCase()}`;
  }

  // ==========================================================
  // ICON
  // ==========================================================

  function threatIcon(type) {
    switch (type) {
      case "PHISHING":
        return <Mail size={18} />;

      case "MALICIOUS_URL":
        return <Globe size={18} />;

      case "ACCOUNT_TAKEOVER":
        return <LockKeyhole size={18} />;

      case "DIGITAL_IMPERSONATION":
        return <UserRound size={18} />;

      case "QR_PHISHING":
      case "SUSPICIOUS_QR":
      case "QR_ANALYSIS":
      case "QR_CONTENT":
        return <QrCode size={18} />;

      default:
        return <AlertTriangle size={18} />;
    }
  }

  // ==========================================================
  // MODULE COUNTS
  // ==========================================================

  const moduleCounts = {
    phishing: events.filter((e) => e.threat_type === "PHISHING").length,

    maliciousUrl: events.filter(
      (e) =>
        e.threat_type === "MALICIOUS_URL" || e.threat_type === "URL_THREAT",
    ).length,

    accountTakeover: events.filter((e) => e.threat_type === "ACCOUNT_TAKEOVER")
      .length,

    impersonation: events.filter(
      (e) => e.threat_type === "DIGITAL_IMPERSONATION",
    ).length,

    qr: events.filter((e) =>
      ["QR_PHISHING", "SUSPICIOUS_QR", "QR_ANALYSIS", "QR_CONTENT"].includes(
        e.threat_type,
      ),
    ).length,

    media: events.filter((e) =>
      ["DEEPFAKE_IMAGE", "DEEPFAKE_VIDEO", "MEDIA_ANALYSIS"].includes(
        e.threat_type,
      ),
    ).length,
  };

  // ==========================================================
  // DASHBOARD
  // ==========================================================

  function Dashboard() {
    const criticalAlertsCount = events.filter(
      (e) => e.severity === "CRITICAL" || e.severity === "HIGH",
    ).length;

    const displayedEvents = events
      .filter((e) => {
        if (!searchQuery.trim()) return true;
        const q = searchQuery.toLowerCase();
        return (
          String(e.id).includes(q) ||
          (e.source && e.source.toLowerCase().includes(q)) ||
          (e.threat_type && e.threat_type.toLowerCase().includes(q)) ||
          (e.severity && e.severity.toLowerCase().includes(q)) ||
          (e.summary && e.summary.toLowerCase().includes(q))
        );
      })
      .slice()
      .reverse();

    return (
      <div className="dashboard-wrapper">
        {/* ================================================= */}
        {/* TOP GLOBAL BAR (Search, Live Monitoring, Bell, Avatar) */}
        {/* ================================================= */}
        <div className="top-global-bar">
          <div className="top-search-box">
            <Search size={16} />
            <input
              type="text"
              placeholder="Search incidents, threats, sources..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery("")}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "#94a3b8",
                  cursor: "pointer",
                  fontSize: "14px",
                  lineHeight: "1",
                  padding: "0 6px",
                }}
                title="Clear search"
              >
                ✕
              </button>
            )}
          </div>

          <div className="top-bar-actions">
            <div className="live-status-pill">
              <span className="pulse-dot"></span>
              Live Monitoring
            </div>

            <button
              className="top-icon-btn notification-btn"
              title={`${criticalAlertsCount} Active Telemetry Alerts`}
              onClick={() =>
                showToast(
                  `${criticalAlertsCount} Critical/High security threat(s) active in telemetry`,
                )
              }
            >
              <Bell size={18} />
              <span className="notif-badge">{criticalAlertsCount}</span>
            </button>

            <div
              className="top-user-avatar"
              title="SOC Operator Terminal"
            >
              MR
            </div>
          </div>
        </div>

        {/* ================================================= */}
        {/* DASHBOARD HERO HEADER */}
        {/* ================================================= */}
        <header className="hero-header">
          <div className="hero-titles">
            <p className="hero-eyebrow">SECURITY OPERATIONS CENTER</p>
            <h2 className="hero-title">Threat Intelligence Dashboard</h2>
            <p className="hero-tagline">Detect &bull; Analyze &bull; Neutralize</p>
          </div>

          <div className="datetime-card">
            <Calendar size={18} className="datetime-icon" />
            <div className="datetime-text">
              <strong>{currentDate}</strong>
              <span>{currentTime}</span>
            </div>
          </div>
        </header>

        {/* ================================================= */}
        {/* 4 STAT CARDS */}
        {/* ================================================= */}
        <section className="stats-grid">
          <StatCard
            icon={<Activity size={22} />}
            title="Total Events"
            value={stats?.total_events ?? (events.length > 0 ? events.length : 0)}
            trend="↑ 12%"
            trendType="up"
            description="All monitored events"
            type="blue"
          />

          <StatCard
            icon={<Shield size={22} />}
            title="Total Threats"
            value={stats?.total_threats ?? (events.length > 0 ? events.filter(e => e.severity !== "SAFE").length : 0)}
            trend="↑ 7%"
            trendType="down"
            description="Detected security threats"
            type="purple"
          />

          <StatCard
            icon={<AlertTriangle size={22} />}
            title="Critical"
            value={
              stats?.severity?.critical ??
              events.filter((e) => e.severity === "CRITICAL").length
            }
            trend="↑ 33%"
            trendType="down"
            description="Immediate attention required"
            type="critical"
          />

          <StatCard
            icon={<ShieldAlert size={22} />}
            title="High Risk"
            value={
              stats?.severity?.high ??
              events.filter((e) => e.severity === "HIGH").length
            }
            trend="↑ 20%"
            trendType="amber"
            description="High priority threats"
            type="orange"
          />
        </section>

        {/* ================================================= */}
        {/* THREAT ANALYSIS CENTER BANNER */}
        {/* ================================================= */}
        <section className="tac-banner-card">
          <div className="tac-left">
            <div>
              <h3 className="tac-title">Threat Analysis Center</h3>
              <p className="tac-desc">Analyze a security event directly from CYBERGUARD-X</p>
            </div>
            <div className="tac-wave">
              <svg viewBox="0 0 140 28" className="neon-spark-svg">
                <path
                  d="M0,18 Q18,4 35,16 T70,10 T105,22 T140,8"
                  fill="none"
                  stroke="#a855f7"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                />
              </svg>
            </div>
          </div>

          <div className="tac-actions">
            <button className="tac-btn-primary" onClick={() => navigate("phishing")}>
              <Mail size={16} />
              Analyze Phishing
            </button>

            <button className="tac-btn-secondary" onClick={() => navigate("url")}>
              <Globe size={15} />
              Analyze URL
            </button>

            <button className="tac-btn-secondary" onClick={() => navigate("login")}>
              <LockKeyhole size={15} />
              Analyze Login
            </button>

            <button className="tac-btn-secondary" onClick={() => navigate("impersonation")}>
              <UserRound size={15} />
              Analyze Identity
            </button>
          </div>
        </section>

        {/* ================================================= */}
        {/* TWO BOTTOM PANELS */}
        {/* ================================================= */}
        <section className="content-grid">
          {/* Threat Distribution */}
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Threat Distribution</h3>
                <span>Current severity breakdown</span>
              </div>

              <Shield size={20} className="panel-header-icon" />
            </div>

            <SeverityRow
              name="Critical"
              count={stats?.severity?.critical ?? events.filter((e) => e.severity === "CRITICAL").length}
              type="critical"
            />

            <SeverityRow
              name="High"
              count={stats?.severity?.high ?? events.filter((e) => e.severity === "HIGH").length}
              type="high"
            />

            <SeverityRow
              name="Medium"
              count={stats?.severity?.medium ?? events.filter((e) => e.severity === "MEDIUM").length}
              type="medium"
            />

            <SeverityRow
              name="Low"
              count={stats?.severity?.low ?? events.filter((e) => e.severity === "LOW").length}
              type="low"
            />
          </div>

          {/* Detection Modules */}
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Detection Modules</h3>
                <span>Active CYBERGUARD-X engines</span>
              </div>
            </div>

            <ModuleRow
              icon={<Mail size={18} />}
              name="Phishing Detection"
              count={moduleCounts.phishing || 5}
              iconType="cyan"
              onClick={() => navigate("phishing")}
            />

            <ModuleRow
              icon={<Globe size={18} />}
              name="Malicious URL"
              count={moduleCounts.maliciousUrl || 1}
              iconType="dark"
              onClick={() => navigate("url")}
            />

            <ModuleRow
              icon={<UserRound size={18} />}
              name="Account Takeover"
              count={moduleCounts.accountTakeover || 3}
              iconType="cyan"
              onClick={() => navigate("login")}
            />
          </div>
        </section>

        {/* ================================================= */}
        {/* LIVE EVENTS */}
        {/* ================================================= */}

        <section className="panel events-panel">
          <div className="panel-header">
            <div>
              <h3>Live Threat Feed</h3>

              <span>Latest security events</span>
            </div>

            <div className="feed-live">
              <span></span>
              LIVE
            </div>
          </div>

          {events.length === 0 ? (
            <div className="empty">No security events detected.</div>
          ) : (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>EVENT</th>
                    <th>SOURCE</th>
                    <th>THREAT</th>
                    <th>RISK</th>
                    <th>SEVERITY</th>
                    <th>STATUS</th>
                    <th></th>
                  </tr>
                </thead>

                <tbody>
                  {displayedEvents.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: "center", padding: "28px", color: "#8b8fb2" }}>
                        {searchQuery ? `No incidents match "${searchQuery}"` : "No security events recorded yet."}
                      </td>
                    </tr>
                  ) : (
                    displayedEvents.map((event) => (
                      <tr key={event.id}>
                        <td>#{event.id}</td>

                        <td>{event.source}</td>

                        <td>
                          <div className="threat-name">
                            {threatIcon(event.threat_type)}

                            {event.threat_type}
                          </div>
                        </td>

                        <td>
                          <div className="risk">
                            <strong>{event.risk_score}</strong>

                            <div className="risk-bar">
                              <div
                                style={{
                                  width: `${Math.min(event.risk_score, 100)}%`,
                                }}
                              />
                            </div>
                          </div>
                        </td>

                        <td>
                          <span className={severityClass(event.severity)}>
                            {event.severity}
                          </span>
                        </td>

                        <td>
                          <span className="status">{event.status}</span>
                        </td>

                        <td>
                          <button
                            className="view-btn"
                            onClick={() => setSelectedEvent(event)}
                          >
                            View
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* ================================================= */}
        {/* DEMO CENTER */}
        {/* ================================================= */}

        <section className="demo-banner">
          <div>
            <Zap size={25} />

            <div>
              <strong>CYBERGUARD-X LIVE DEMO</strong>

              <span>Run safe simulated threat scenarios for presentation.</span>
            </div>
          </div>

          <button onClick={() => navigate("simulator")}>
            Open Demo Simulator
          </button>
        </section>
      </div>
    );
  }

  // ==========================================================
  // MAIN PAGE
  // ==========================================================

  return (
    <div className="app">
      {/* ==================================================== */}
      {/* MOBILE TOPBAR (<= 992px) */}
      {/* ==================================================== */}
      <div className="mobile-header">
        <button
          type="button"
          className="mobile-hamburger-btn"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          aria-label="Toggle navigation menu"
        >
          {mobileMenuOpen ? <X size={22} /> : <Menu size={22} />}
        </button>

        <div className="mobile-brand" onClick={() => navigate("dashboard")}>
          <div className="mobile-brand-icon">
            <Shield size={20} />
          </div>
          <div>
            <h2>CYBERGUARD-X</h2>
            <span>SOC DEFENCE</span>
          </div>
        </div>

        <div className="mobile-header-status">
          <span className="pulse-dot"></span>
          <span>LIVE</span>
        </div>
      </div>

      {/* Backdrop overlay for mobile drawer */}
      {mobileMenuOpen && (
        <div
          className="mobile-backdrop"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* ==================================================== */}
      {/* SIDEBAR */}
      {/* ==================================================== */}

      <aside className={`sidebar ${mobileMenuOpen ? "sidebar-mobile-open" : ""}`}>
        <div className="brand">
          <div className="brand-icon">
            <Shield size={28} />
          </div>

          <div>
            <h1>CYBERGUARD-X</h1>

            <span>AI CYBER DEFENCE</span>
          </div>
        </div>

        <nav>
          <NavItem
            icon={<LayoutDashboard />}
            label="Security Overview"
            active={page === "dashboard"}
            onClick={() => navigate("dashboard")}
          />

          <NavItem
            icon={<Mail />}
            label="Phishing Detection"
            active={page === "phishing"}
            onClick={() => navigate("phishing")}
          />

          <NavItem
            icon={<Globe />}
            label="URL Intelligence"
            active={page === "url"}
            onClick={() => navigate("url")}
          />

          <NavItem
            icon={<QrCode />}
            label="QR Detection"
            active={page === "qr"}
            onClick={() => navigate("qr")}
          />

          <NavItem
            icon={<ImageIcon />}
            label="Media Detection"
            active={page === "media"}
            onClick={() => navigate("media")}
          />

          <NavItem
            icon={<LockKeyhole />}
            label="Account Security"
            active={page === "login"}
            onClick={() => navigate("login")}
          />

          <NavItem
            icon={<UserRound />}
            label="Identity Protection"
            active={page === "impersonation"}
            onClick={() => navigate("impersonation")}
          />

          <NavItem
            icon={<ShieldAlert />}
            label="Incidents"
            active={page === "incidents"}
            onClick={() => navigate("incidents")}
          />

          <NavItem
            icon={<Zap />}
            label="Demo Simulator"
            active={page === "simulator"}
            onClick={() => navigate("simulator")}
          />

        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-dot"></span>

            <div>
              <strong>SYSTEM ONLINE</strong>

              <span>AI threat engine active</span>
            </div>
          </div>
        </div>
      </aside>

      {/* ==================================================== */}
      {/* MAIN */}
      {/* ==================================================== */}

      <main className="main">
        {page === "dashboard" && <Dashboard />}

        {page === "phishing" && (
          <PhishingPage
            onComplete={loadDashboard}
            onBack={() => navigate("dashboard")}
            showToast={showToast}
          />
        )}

        {page === "url" && (
          <UrlPage
            onComplete={loadDashboard}
            onBack={() => navigate("dashboard")}
            showToast={showToast}
          />
        )}

        {page === "login" && (
          <LoginPage
            onComplete={loadDashboard}
            onBack={() => navigate("dashboard")}
            showToast={showToast}
          />
        )}

        {page === "impersonation" && (
          <ImpersonationPage
            onComplete={loadDashboard}
            onBack={() => navigate("dashboard")}
            showToast={showToast}
          />
        )}

        {page === "incidents" && (
          <IncidentsPage
            events={events}
            onSelect={setSelectedEvent}
            onBack={() => navigate("dashboard")}
          />
        )}

        {page === "simulator" && (
          <SimulatorPage
            onComplete={loadDashboard}
            onBack={() => navigate("dashboard")}
            onViewIncidents={() => navigate("incidents")}
            showToast={showToast}
          />
        )}

        {page === "qr" && (
          <QRPage
            onComplete={loadDashboard}
            onBack={() => navigate("dashboard")}
            showToast={showToast}
          />
        )}

        {page === "media" && (
          <MediaPage
            onComplete={loadDashboard}
            onBack={() => navigate("dashboard")}
            showToast={showToast}
          />
        )}

      </main>

      {/* ==================================================== */}
      {/* INCIDENT MODAL */}
      {/* ==================================================== */}

      {selectedEvent && (
        <IncidentModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}

      {/* ==================================================== */}
      {/* TOAST */}
      {/* ==================================================== */}

      {toast && (
        <div className="toast">
          <AlertTriangle size={17} />

          {toast}
        </div>
      )}
    </div>
  );
}

// ============================================================
// STAT CARD
// ============================================================

function StatCard({ icon, title, value, description, trend, trendType, type }) {
  return (
    <div className={`stat-card stat-${type}`}>
      <div className={`stat-icon ${type}`}>{icon}</div>

      <div className="stat-content">
        <span className="stat-title">{title}</span>

        <div className="stat-value-row">
          <strong className="stat-number">{value}</strong>
          {trend && (
            <span className={`stat-trend-pill trend-${trendType || "up"}`}>
              {trend}
            </span>
          )}
        </div>

        <small className="stat-desc">{description}</small>
      </div>
    </div>
  );
}

// ============================================================
// NAV ITEM
// ============================================================

function NavItem({ icon, label, active, onClick }) {
  return (
    <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick}>
      {icon}

      <span>{label}</span>
    </button>
  );
}

// ============================================================
// SEVERITY ROW
// ============================================================

function SeverityRow({ name, count, type }) {
  const width = Math.min(count * 15, 100);

  return (
    <div className="severity-block">
      <div className="severity-row">
        <span>
          <i className={`dot ${type}-dot`} />

          {name}
        </span>

        <strong>{count}</strong>
      </div>

      <div className="bar">
        <div
          className={`bar-fill bar-${type}`}
          style={{
            width: `${Math.max(width, 8)}%`,
          }}
        />
      </div>
    </div>
  );
}

// ============================================================
// MODULE ROW
// ============================================================

function ModuleRow({ icon, name, count, iconType = "cyan", onClick }) {
  return (
    <button className="module-item" onClick={onClick}>
      <div className={`module-icon-box ${iconType}`}>{icon}</div>

      <div className="module-details">
        <strong>{name}</strong>
        <span className="module-status-tag">Active</span>
      </div>

      <b className="module-counter">{count}</b>
    </button>
  );
}

// ============================================================
// GENERIC ANALYSIS PAGE
// ============================================================

function AnalysisShell({
  title,
  subtitle,
  icon,
  category = "AI THREAT TELEMETRY",
  children,
  result,
  onBack,
}) {
  return (
    <div className="analysis-page">
      <div className="analysis-top-nav">
        <button className="cyber-back-btn" onClick={onBack}>
          <span>←</span>
          <span>Back to Dashboard</span>
        </button>

        <div className="telemetry-status-pill">
          <span className="pulse-dot"></span>
          <span>Engine Active &bull; SOC Ready</span>
        </div>
      </div>

      <div className="analysis-header-card">
        <div className="analysis-icon-glow">{icon}</div>

        <div className="analysis-header-text">
          <div className="analysis-eyebrow-row">
            <span className="analysis-badge">{category}</span>
            <span className="analysis-version">v2.4 NEURAL ENGINE</span>
          </div>

          <h2 className="analysis-main-title">{title}</h2>

          <p className="analysis-main-subtitle">{subtitle}</p>
        </div>
      </div>

      <div className="analysis-grid">
        <div className="panel cyber-form-panel">{children}</div>

        {result && <ResultPanel result={result} />}
      </div>
    </div>
  );
}

// ============================================================
// PHISHING
// ============================================================

function PhishingPage({ onComplete, onBack, showToast }) {
  const [form, setForm] = useState({
    sender: "",
    subject: "",
    message: "",
    url: "",
  });

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  function update(key, value) {
    setForm({
      ...form,
      [key]: value,
    });
  }

  function handleDemoEmail(preset) {
    setForm(preset);
    runAnalysisWithData(preset);
  }

  async function runAnalysisWithData(dataToScan) {
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch(`${API}/analyze/phishing`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(dataToScan),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Analysis failed");
      }

      setResult(data);
      onComplete();
      setTimeout(() => {
        const el = document.getElementById("analysis-result-section");
        if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }, 80);
    } catch (error) {
      showToast(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function analyze(event) {
    event.preventDefault();
    await runAnalysisWithData(form);
  }

  return (
    <AnalysisShell
      title="Email Phishing & Social Engineering Engine"
      subtitle="Deep telemetry scan for psychological coercion, spoofed sender domains, credential harvesting forms, and zero-day threat links."
      icon={<Mail size={28} />}
      category="SOCIAL ENGINEERING & PHISHING DETECTION"
      result={result}
      onBack={onBack}
    >
      <div className="demo-presets-row">
        <span className="demo-presets-label">⚡ 1-Click Test Scenarios:</span>
        <div className="demo-presets-chips">
          <button
            type="button"
            className="demo-preset-chip chip-critical"
            onClick={() =>
              handleDemoEmail({
                sender: "security-alert@paypal-account-verify.com",
                subject: "URGENT: Your Account Has Been Locked!",
                message:
                  "Immediate action required. Your account will be permanently deactivated in 24 hours. Verify your credentials and billing info immediately.",
                url: "http://verify-identity-login.paypal-alert.com/restore",
              })
            }
          >
            🚨 Urgent Account Lock (Phishing)
          </button>

          <button
            type="button"
            className="demo-preset-chip chip-high"
            onClick={() =>
              handleDemoEmail({
                sender: "payroll@internal-updates-hr.org",
                subject: "Updated Direct Deposit & Bonus Form",
                message:
                  "Please review the attached updated payment breakdown before Friday close of business.",
                url: "https://forms-payment.hr-portal.org/login",
              })
            }
          >
            ⚠️ HR Payroll Spoof
          </button>

          <button
            type="button"
            className="demo-preset-chip chip-safe"
            onClick={() =>
              handleDemoEmail({
                sender: "notifications@github.com",
                subject: "Weekly digest for your security alerts",
                message:
                  "Here is your weekly summary of dependency alerts and security advisories for your repositories.",
                url: "https://github.com/security",
              })
            }
          >
            🛡️ Legitimate Notification
          </button>
        </div>
      </div>

      <form onSubmit={analyze}>
        <Field
          label="Sender Address"
          value={form.sender}
          onChange={(v) => update("sender", v)}
          placeholder="e.g. security-alert@verify-portal.com"
        />

        <Field
          label="Email Subject"
          value={form.subject}
          onChange={(v) => update("subject", v)}
          placeholder="e.g. URGENT: Verify your account immediately"
        />

        <TextArea
          label="Message Body Content"
          value={form.message}
          onChange={(v) => update("message", v)}
          placeholder="Paste the suspicious message content or email body here..."
        />

        <Field
          label="Embedded Suspicious URL (Optional)"
          value={form.url}
          onChange={(v) => update("url", v)}
          placeholder="https://secure-account.example.com/login"
        />

        <button className="analyze-btn cyber-scan-btn" type="submit" disabled={loading}>
          {loading ? (
            <>
              <RefreshCw size={18} className="spin-icon" />
              ANALYZING PHISHING TELEMETRY...
            </>
          ) : (
            <>
              <Search size={18} />
              DISSECT & SCAN EMAIL
            </>
          )}
        </button>
      </form>
    </AnalysisShell>
  );
}

// ============================================================
// URL
// ============================================================

function UrlPage({ onComplete, onBack, showToast }) {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const demoUrls = [
    {
      label: "🚨 Typosquatting (Paypa1)",
      url: "https://paypa1-security-verify.com/login",
      type: "critical",
    },
    {
      label: "❌ Ghost / Dead Domain",
      url: "https://fake-login-sec99.com/auth",
      type: "critical",
    },
    {
      label: "⚠️ Malicious Raw IP Host",
      url: "http://185.220.101.5:8080/download/invoice_pdf.exe",
      type: "high",
    },
    {
      label: "🛡️ Legitimate Corporate Portal",
      url: "https://www.microsoft.com/en-us/security",
      type: "safe",
    },
  ];

  async function analyzeUrlString(targetUrl) {
    const scanUrl = targetUrl || url;
    if (!scanUrl || !scanUrl.trim()) {
      showToast("Please enter a valid URL to analyze.");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const response = await fetch(`${API}/analyze/url`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: scanUrl.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "URL analysis failed");
      }

      setResult(data);
      onComplete();
      setTimeout(() => {
        const el = document.getElementById("analysis-result-section");
        if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }, 80);
    } catch (error) {
      showToast(error.message);
    } finally {
      setLoading(false);
    }
  }

  function handleDemoClick(demoUrl) {
    setUrl(demoUrl);
    analyzeUrlString(demoUrl);
  }

  async function handleFormSubmit(event) {
    event.preventDefault();
    await analyzeUrlString(url);
  }

  return (
    <AnalysisShell
      title="URL Threat Intelligence & Domain Forensics"
      subtitle="Inspect suspicious web addresses, zero-day phishing infrastructure, cloaked redirect chains, and deceptive domain registrations with real-time heuristic scoring."
      icon={<Globe size={28} />}
      category="WEB REPUTATION & URL FORENSICS"
      result={result}
      onBack={onBack}
    >
      <form onSubmit={handleFormSubmit}>
        <div className="cyber-input-group">
          <label className="cyber-input-label">Target URL / Domain Endpoint</label>
          <div className="url-search-bar">
            <span className="url-protocol-tag">TARGET</span>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="e.g. https://secure-account.verify-bank.com/login"
              className="url-main-input"
              required
            />
            {url && (
              <button
                type="button"
                className="url-clear-btn"
                onClick={() => setUrl("")}
                title="Clear input"
              >
                ✕
              </button>
            )}
          </div>
        </div>

        {/* 1-Click Quick Demo Presets */}
        <div className="demo-presets-row">
          <span className="demo-presets-label">⚡ 1-Click Test Scenarios:</span>
          <div className="demo-presets-chips">
            {demoUrls.map((demo, idx) => (
              <button
                key={idx}
                type="button"
                className={`demo-preset-chip chip-${demo.type}`}
                onClick={() => handleDemoClick(demo.url)}
              >
                {demo.label}
              </button>
            ))}
          </div>
        </div>

        {/* Forensic Capabilities Badges */}
        <div className="forensic-capabilities-grid">
          <div className="cap-badge">
            <Shield size={14} className="cap-icon purple" />
            <span>Typosquatting & Punycode</span>
          </div>
          <div className="cap-badge">
            <Activity size={14} className="cap-icon cyan" />
            <span>Multi-Hop Redirect Chain</span>
          </div>
          <div className="cap-badge">
            <LockKeyhole size={14} className="cap-icon amber" />
            <span>TLD & Certificate Trust</span>
          </div>
          <div className="cap-badge">
            <Zap size={14} className="cap-icon red" />
            <span>Neural Threat Scoring</span>
          </div>
        </div>

        <button className="analyze-btn cyber-scan-btn" type="submit" disabled={loading}>
          {loading ? (
            <>
              <RefreshCw size={18} className="spin-icon" />
              SCANNING & DECODING URL TELEMETRY...
            </>
          ) : (
            <>
              <Search size={18} />
              DISSECT & ANALYZE URL
            </>
          )}
        </button>
      </form>
    </AnalysisShell>
  );
}

// ============================================================
// LOGIN
// ============================================================

function LoginPage({ onComplete, onBack, showToast }) {
  const [form, setForm] = useState({
    user_id: 1,
    ip_address: "",
    location: "",
    device: "",
    login_status: "SUCCESS",
    failed_attempts: 0,
    is_new_device: false,
    is_unusual_location: false,
  });

  const [result, setResult] = useState(null);

  const demoLogins = [
    {
      label: "🚨 Brute Force Credential Attack",
      type: "critical",
      data: {
        user_id: 1,
        ip_address: "185.220.101.5",
        location: "Moscow, Russia",
        device: "Kali Linux Automation Tool",
        login_status: "SUCCESS",
        failed_attempts: 12,
        is_new_device: true,
        is_unusual_location: true,
      },
    },
    {
      label: "⚠️ Unrecognized Overseas Device",
      type: "high",
      data: {
        user_id: 1,
        ip_address: "198.51.100.24",
        location: "Amsterdam, Netherlands",
        device: "Unknown MacOS Safari 17.2",
        login_status: "SUCCESS",
        failed_attempts: 3,
        is_new_device: true,
        is_unusual_location: true,
      },
    },
    {
      label: "🛡️ Authorized Corporate Station",
      type: "safe",
      data: {
        user_id: 1,
        ip_address: "10.0.4.15",
        location: "New York HQ Office",
        device: "CyberGuard Workstation (Win 11)",
        login_status: "SUCCESS",
        failed_attempts: 0,
        is_new_device: false,
        is_unusual_location: false,
      },
    },
  ];

  function update(key, value) {
    setForm({
      ...form,
      [key]: value,
    });
  }

  async function analyze(event, overrideData) {
    if (event) event.preventDefault();
    const payload = overrideData || form;

    try {
      const response = await fetch(`${API}/analyze/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ...payload,
          user_id: Number(payload.user_id),
          failed_attempts: Number(payload.failed_attempts),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Login analysis failed");
      }

      setResult(data);
      onComplete();

      setTimeout(() => {
        const el = document.getElementById("analysis-result-section");
        if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }, 80);
    } catch (error) {
      showToast(error.message);
    }
  }

  function handleDemoClick(demo) {
    setForm(demo.data);
    analyze(null, demo.data);
  }

  return (
    <AnalysisShell
      title="Account Takeover & Anomaly Detection"
      subtitle="Multi-vector behavioral heuristics for abnormal geolocations, unrecognized client devices, and brute-force credential stuffing."
      icon={<LockKeyhole size={28} />}
      category="ACCESS CONTROL & ANOMALY DEFENSE"
      result={result}
      onBack={onBack}
    >
      {/* 1-Click Test Scenarios */}
      <div className="demo-presets-row">
        <span className="demo-presets-label">⚡ 1-Click Test Scenarios:</span>
        <div className="demo-presets-chips">
          {demoLogins.map((demo, idx) => (
            <button
              key={idx}
              type="button"
              className={`demo-preset-chip chip-${demo.type}`}
              onClick={() => handleDemoClick(demo)}
            >
              {demo.label}
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={analyze}>
        <div className="form-two">
          <Field
            label="IP Address"
            value={form.ip_address}
            onChange={(v) => update("ip_address", v)}
            placeholder="203.0.113.45"
          />
        </div>

        <Field
          label="Location"
          value={form.location}
          onChange={(v) => update("location", v)}
          placeholder="Unknown Location"
        />

        <Field
          label="Device"
          value={form.device}
          onChange={(v) => update("device", v)}
          placeholder="Unknown Windows Device"
        />

        <div className="form-two">
          <Field
            label="Failed Attempts"
            type="number"
            value={form.failed_attempts}
            onChange={(v) => update("failed_attempts", v)}
          />

          <SelectField
            label="Login Status"
            value={form.login_status}
            onChange={(v) => update("login_status", v)}
            options={["SUCCESS", "FAILED"]}
          />
        </div>

        <label className="check">
          <input
            type="checkbox"
            checked={form.is_new_device}
            onChange={(e) => update("is_new_device", e.target.checked)}
          />
          Is this a new or unknown device?
        </label>

        <label className="check">
          <input
            type="checkbox"
            checked={form.is_unusual_location}
            onChange={(e) => update("is_unusual_location", e.target.checked)}
          />
          Is this a new or unusual location?
        </label>

        <button className="analyze-btn" type="submit">
          <Search size={18} />
          CHECK THIS LOGIN
        </button>
      </form>
    </AnalysisShell>
  );
}

// ============================================================
// IMPERSONATION
// ============================================================

function ImpersonationPage({ onComplete, onBack, showToast }) {
  const [form, setForm] = useState({
    sender_name: "",
    sender_email: "",
    claimed_identity: "",
    message: "",
    official_domain: "",
  });

  const [result, setResult] = useState(null);

  const demoImpersonations = [
    {
      label: "🚨 CEO Urgent Wire Transfer Spoof",
      type: "critical",
      data: {
        sender_name: "Satya Nadella (CEO)",
        sender_email: "satya.nadella-executive@gmail.com",
        claimed_identity: "Microsoft Corporation",
        official_domain: "microsoft.com",
        message:
          "Immediate wire authorization required for confidential acquisition. Do not contact finance department via telephone until closure.",
      },
    },
    {
      label: "⚠️ IT Helpdesk Password Reset Spoof",
      type: "high",
      data: {
        sender_name: "Global IT Support Desk",
        sender_email: "helpdesk@account-it-security.net",
        claimed_identity: "Google Workspace Admin",
        official_domain: "google.com",
        message:
          "Your multi-factor authentication expires in 1 hour. Verify credentials immediately to prevent service interruption.",
      },
    },
    {
      label: "🛡️ Verified Official Academic Announcement",
      type: "safe",
      data: {
        sender_name: "University Registrar",
        sender_email: "registrar@stanford.edu",
        claimed_identity: "Stanford University",
        official_domain: "stanford.edu",
        message:
          "Spring semester course enrollment is now open. Please review the updated schedule on the official student portal.",
      },
    },
  ];

  function update(key, value) {
    setForm({
      ...form,
      [key]: value,
    });
  }

  async function analyze(event, overrideData) {
    if (event) event.preventDefault();
    const payload = overrideData || form;

    try {
      const response = await fetch(`${API}/analyze/impersonation`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Identity analysis failed");
      }

      setResult(data);
      onComplete();

      setTimeout(() => {
        const el = document.getElementById("analysis-result-section");
        if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }, 80);
    } catch (error) {
      showToast(error.message);
    }
  }

  function handleDemoClick(demo) {
    setForm(demo.data);
    analyze(null, demo.data);
  }

  return (
    <AnalysisShell
      title="Digital Identity & Brand Impersonation Forensics"
      subtitle="Automated detection of executive impersonation, synthetic identity spoofing, and unauthorized brand deception."
      icon={<UserRound size={28} />}
      category="IDENTITY & REPUTATION DEFENSE"
      result={result}
      onBack={onBack}
    >
      {/* 1-Click Test Scenarios */}
      <div className="demo-presets-row">
        <span className="demo-presets-label">⚡ 1-Click Test Scenarios:</span>
        <div className="demo-presets-chips">
          {demoImpersonations.map((demo, idx) => (
            <button
              key={idx}
              type="button"
              className={`demo-preset-chip chip-${demo.type}`}
              onClick={() => handleDemoClick(demo)}
            >
              {demo.label}
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={analyze}>
        <Field
          label="Sender Name"
          value={form.sender_name}
          onChange={(v) => update("sender_name", v)}
          placeholder="Name of the person or organization"
        />

        <Field
          label="Sender Email"
          value={form.sender_email}
          onChange={(v) => update("sender_email", v)}
          placeholder="email@gmail.com"
        />

        <Field
          label="Claimed Identity"
          value={form.claimed_identity}
          onChange={(v) => update("claimed_identity", v)}
          placeholder="Name of the person or organization"
        />

        <Field
          label="Official Domain"
          value={form.official_domain}
          onChange={(v) => update("official_domain", v)}
          placeholder="university.edu"
        />

        <TextArea
          label="Message"
          value={form.message}
          onChange={(v) => update("message", v)}
          placeholder="Paste or type the suspicious message here..."
        />

        <button className="analyze-btn" type="submit">
          <Search size={18} />
          CHECK IDENTITY
        </button>
      </form>
    </AnalysisShell>
  );
}

// ============================================================
// QR CODE DETECTION
// ============================================================

function QRPage({ onComplete, onBack, showToast }) {
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState("");
  const [result, setResult] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const demoQRs = [
    {
      label: "🚨 Phishing Quishing QR",
      path: "/samples/qr_phishing.png",
      filename: "phishing_qr_payload.png",
      type: "critical",
    },
    {
      label: "⚠️ Malware Dropper QR",
      path: "/samples/qr_malware.png",
      filename: "malware_qr_binary.png",
      type: "high",
    },
    {
      label: "🛡️ Legitimate Corporate QR",
      path: "/samples/qr_safe.png",
      filename: "official_safe_qr.png",
      type: "safe",
    },
  ];

  function processFile(selectedFile) {
    if (!selectedFile) return;

    const allowedTypes = [
      "image/png",
      "image/jpeg",
      "image/jpg",
      "image/webp",
    ];

    if (!allowedTypes.includes(selectedFile.type)) {
      showToast("Please select a PNG, JPG, JPEG or WEBP image.");
      return;
    }

    setFile(selectedFile);
    setResult(null);
    setPreview(URL.createObjectURL(selectedFile));
  }

  function handleFileChange(event) {
    const selectedFile = event.target.files?.[0];
    processFile(selectedFile);
  }

  function handleDrop(e) {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  }

  async function runQRAnalysis(fileToAnalyze) {
    const target = fileToAnalyze || file;
    if (!target) {
      showToast("Please upload or select a QR code image first.");
      return;
    }

    setAnalyzing(true);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", target);

      const response = await fetch(`${API}/analyze/qr`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "QR code analysis failed");
      }

      setResult(data);
      onComplete();

      setTimeout(() => {
        const el = document.getElementById("analysis-result-section");
        if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }, 80);
    } catch (error) {
      console.error(error);
      showToast(error.message);
    } finally {
      setAnalyzing(false);
    }
  }

  async function handleDemoClick(demo) {
    try {
      setAnalyzing(true);
      const res = await fetch(demo.path);
      const blob = await res.blob();
      const sampleFile = new File([blob], demo.filename, { type: "image/png" });
      setFile(sampleFile);
      setPreview(URL.createObjectURL(blob));
      await runQRAnalysis(sampleFile);
    } catch (err) {
      showToast("Failed to load sample QR: " + err.message);
      setAnalyzing(false);
    }
  }

  function removeFile() {
    setFile(null);
    setPreview("");
    setResult(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  return (
    <AnalysisShell
      title="QR Code Exploit & Quishing Forensics"
      subtitle="Deep decode & telemetry scanning for obfuscated URLs, malicious payload intents, and redirect traps embedded in physical-to-digital QR matrices."
      icon={<QrCode size={28} />}
      category="PHYSICAL-TO-DIGITAL & QUISHING ANALYSIS"
      result={result}
      onBack={onBack}
    >
      {/* 1-Click Test Scenarios */}
      <div className="demo-presets-row">
        <span className="demo-presets-label">⚡ 1-Click Test Scenarios:</span>
        <div className="demo-presets-chips">
          {demoQRs.map((demo, idx) => (
            <button
              key={idx}
              type="button"
              className={`demo-preset-chip chip-${demo.type}`}
              onClick={() => handleDemoClick(demo)}
              disabled={analyzing}
            >
              {demo.label}
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={(e) => { e.preventDefault(); runQRAnalysis(); }}>
        <input
          type="file"
          ref={fileInputRef}
          accept="image/png,image/jpeg,image/jpg,image/webp"
          onChange={handleFileChange}
          style={{ display: "none" }}
        />

        {!file ? (
          <div
            className={`cyber-dropzone ${isDragOver ? "drag-active" : ""}`}
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleDrop}
          >
            <div className="dropzone-icon-glow">
              <QrCode size={32} />
            </div>
            <h3 className="dropzone-title">Drag & Drop QR Image File</h3>
            <p className="dropzone-sub">
              Upload physical sticker photos, digital invoice QRs, or payment matrices
            </p>
            <span className="dropzone-browse-pill">
              <Upload size={14} />
              Browse Image Files
            </span>
            <span className="dropzone-hint">Supported: PNG, JPG, JPEG, WEBP (Max 10MB)</span>
          </div>
        ) : (
          <div className="file-preview-card">
            <div className="preview-thumb-box">
              <img src={preview} alt="QR Code Preview" />
            </div>
            <div className="preview-file-info">
              <span className="preview-file-name">{file.name}</span>
              <span className="preview-file-meta">
                {(file.size / 1024).toFixed(1)} KB &bull; Image Matrix Ready
              </span>
            </div>
            <button
              type="button"
              className="preview-remove-btn"
              onClick={removeFile}
            >
              Change QR
            </button>
          </div>
        )}

        {/* Forensic Capabilities Checklist */}
        <div className="forensic-capabilities-grid">
          <div className="cap-badge">
            <QrCode size={14} className="cap-icon purple" />
            <span>Matrix Reed-Solomon Decode</span>
          </div>
          <div className="cap-badge">
            <Activity size={14} className="cap-icon cyan" />
            <span>Destination URL Heuristics</span>
          </div>
          <div className="cap-badge">
            <Shield size={14} className="cap-icon amber" />
            <span>Typosquatting & Spoofing</span>
          </div>
          <div className="cap-badge">
            <Zap size={14} className="cap-icon red" />
            <span>Quishing Payload Analysis</span>
          </div>
        </div>

        <button
          className="analyze-btn cyber-scan-btn"
          type="submit"
          disabled={analyzing || !file}
        >
          {analyzing ? (
            <>
              <RefreshCw size={18} className="spin-icon" />
              DECODING & ANALYZING QR TELEMETRY...
            </>
          ) : (
            <>
              <QrCode size={18} />
              DISSECT & SCAN QR CODE
            </>
          )}
        </button>
      </form>
    </AnalysisShell>
  );
}

// ============================================================
// IMAGE & VIDEO / DEEPFAKE DETECTION
// ============================================================

function MediaPage({ onComplete, onBack, showToast }) {
  const [mode, setMode] = useState("image");
  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const demoImages = [
    {
      label: "🎭 Synthetic AI Deepfake",
      path: "/samples/media_deepfake_sample.png",
      filename: "ai_deepfake_profile.png",
      type: "critical",
    },
    {
      label: "📄 Altered ID Document",
      path: "/samples/sample_manipulated_id.png",
      filename: "sample_manipulated_id.png",
      type: "high",
    },
    {
      label: "🛡️ Authentic Original Media",
      path: "/samples/media_safe_sample.png",
      filename: "authentic_source_image.png",
      type: "safe",
    },
  ];

  const demoVideos = [
    {
      label: "🎭 AI Deepfake Video",
      path: "/samples/sample_deepfake_video.mp4",
      filename: "sample_deepfake_video.mp4",
      type: "critical",
    },
    {
      label: "⚠️ Spliced Video Clip",
      path: "/samples/sample_spliced_video.mp4",
      filename: "sample_spliced_video.mp4",
      type: "high",
    },
    {
      label: "🛡️ Authentic HD Video",
      path: "/samples/sample_authentic_video.mp4",
      filename: "sample_authentic_video.mp4",
      type: "safe",
    },
  ];

  const demoMedia = mode === "image" ? demoImages : demoVideos;

  function processFile(selected) {
    if (!selected) return;

    const allowedImageTypes = [
      "image/png",
      "image/jpeg",
      "image/jpg",
      "image/webp",
    ];

    const allowedVideoTypes = [
      "video/mp4",
      "video/webm",
      "video/quicktime",
      "video/x-msvideo",
    ];

    const allowedTypes =
      mode === "image" ? allowedImageTypes : allowedVideoTypes;

    if (!allowedTypes.includes(selected.type)) {
      showToast(
        mode === "image"
          ? "Please select a PNG, JPG, JPEG or WEBP image."
          : "Please select an MP4, WEBM, MOV or AVI video.",
      );
      return;
    }

    setFile(selected);
    setResult(null);
    setPreview(URL.createObjectURL(selected));
  }

  function handleFile(event) {
    const selected = event.target.files?.[0];
    processFile(selected);
  }

  function handleDrop(e) {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  }

  function removeMedia() {
    setFile(null);
    setPreview("");
    setResult(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }

  function changeMode(newMode) {
    setMode(newMode);
    removeMedia();
  }

  async function analyzeMedia(targetFile) {
    const activeFile = targetFile || file;
    if (!activeFile) {
      showToast(
        mode === "image"
          ? "Please upload or select an image first."
          : "Please upload or select a video first.",
      );
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", activeFile);

      const endpoint =
        mode === "image"
          ? "/analyze/image"
          : "/analyze/video";

      const response = await fetch(`${API}${endpoint}`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Media analysis failed",
        );
      }

      setResult(data);
      onComplete();

      setTimeout(() => {
        const el = document.getElementById("analysis-result-section");
        if (el) el.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }, 80);
    } catch (error) {
      console.error(error);
      showToast(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleDemoClick(demo) {
    try {
      setLoading(true);
      const res = await fetch(demo.path);
      const blob = await res.blob();
      const mime = mode === "video" ? "video/mp4" : "image/png";
      const sampleFile = new File([blob], demo.filename, { type: mime });
      setFile(sampleFile);
      setPreview(URL.createObjectURL(blob));
      await analyzeMedia(sampleFile);
    } catch (err) {
      showToast("Failed to load sample media: " + err.message);
      setLoading(false);
    }
  }

  return (
    <AnalysisShell
      title="Media Manipulation & Deepfake Forensics"
      subtitle="Computer vision & frequency-domain analysis for synthetic media, facial artifacts, and video manipulation signatures."
      icon={
        mode === "image"
          ? <ImageIcon size={28} />
          : <Video size={28} />
      }
      category="SYNTHETIC MEDIA & DEEPFAKE FORENSICS"
      result={result}
      onBack={onBack}
    >
      {/* Media Mode Segmented Switcher */}
      <div className="media-mode-switch-wrapper">
        <div className="media-mode-switch">
          <button
            type="button"
            className={mode === "image" ? "active" : ""}
            onClick={() => changeMode("image")}
          >
            <ImageIcon size={16} />
            <span>IMAGE FORENSICS</span>
          </button>

          <button
            type="button"
            className={mode === "video" ? "active" : ""}
            onClick={() => changeMode("video")}
          >
            <Video size={16} />
            <span>VIDEO FORENSICS</span>
          </button>
        </div>
      </div>

      {/* 1-Click Test Scenarios */}
      <div className="demo-presets-row">
        <span className="demo-presets-label">⚡ 1-Click Test Scenarios:</span>
        <div className="demo-presets-chips">
          {demoMedia.map((demo, idx) => (
            <button
              key={idx}
              type="button"
              className={`demo-preset-chip chip-${demo.type}`}
              onClick={() => handleDemoClick(demo)}
              disabled={loading}
            >
              {demo.label}
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={(e) => { e.preventDefault(); analyzeMedia(); }}>
        <input
          type="file"
          ref={fileInputRef}
          accept={
            mode === "image"
              ? "image/png,image/jpeg,image/jpg,image/webp"
              : "video/mp4,video/webm,video/quicktime,video/x-msvideo"
          }
          onChange={handleFile}
          style={{ display: "none" }}
        />

        {!file ? (
          <div
            className={`cyber-dropzone ${isDragOver ? "drag-active" : ""}`}
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleDrop}
          >
            <div className="dropzone-icon-glow">
              {mode === "image" ? <ImageIcon size={32} /> : <Video size={32} />}
            </div>
            <h3 className="dropzone-title">
              Drag & Drop {mode === "image" ? "Image" : "Video"} for Forensics
            </h3>
            <p className="dropzone-sub">
              {mode === "image"
                ? "Dissect GAN/Diffusion artifacts, facial landmark jitter, and pixel-level inconsistencies"
                : "Analyze temporal frame consistency, lip-sync anomalies, and synthetic transitions"}
            </p>
            <span className="dropzone-browse-pill">
              <Upload size={14} />
              Browse {mode === "image" ? "Images" : "Videos"}
            </span>
            <span className="dropzone-hint">
              {mode === "image"
                ? "Supported: PNG, JPG, JPEG, WEBP (Max 25MB)"
                : "Supported: MP4, WEBM, MOV, AVI (Max 50MB)"}
            </span>
          </div>
        ) : (
          <div className="file-preview-card">
            <div className="preview-thumb-box">
              {mode === "image" ? (
                <img src={preview} alt="Selected media preview" />
              ) : (
                <video src={preview} controls />
              )}
            </div>
            <div className="preview-file-info">
              <span className="preview-file-name">{file.name}</span>
              <span className="preview-file-meta">
                {(file.size / (1024 * 1024)).toFixed(2)} MB &bull; {mode.toUpperCase()} Loaded &bull; Ready for Analysis
              </span>
            </div>
            <button
              type="button"
              className="preview-remove-btn"
              onClick={removeMedia}
            >
              Change Media
            </button>
          </div>
        )}

        {/* Forensic Capabilities Checklist */}
        <div className="forensic-capabilities-grid">
          <div className="cap-badge">
            <Activity size={14} className="cap-icon cyan" />
            <span>Frequency Artifact Analysis</span>
          </div>
          <div className="cap-badge">
            <Shield size={14} className="cap-icon purple" />
            <span>Error Level Analysis (ELA)</span>
          </div>
          <div className="cap-badge">
            <CheckCircle size={14} className="cap-icon amber" />
            <span>Facial Landmark Symmetry</span>
          </div>
          <div className="cap-badge">
            <Zap size={14} className="cap-icon red" />
            <span>Synthetic GAN Signatures</span>
          </div>
        </div>

        <button
          className="analyze-btn cyber-scan-btn"
          type="submit"
          disabled={loading || !file}
        >
          {loading ? (
            <>
              <RefreshCw size={18} className="spin-icon" />
              SCANNING {mode.toUpperCase()} FORENSICS...
            </>
          ) : (
            <>
              {mode === "image" ? <ImageIcon size={18} /> : <Video size={18} />}
              ANALYZE {mode.toUpperCase()} AUTHENTICITY
            </>
          )}
        </button>
      </form>
    </AnalysisShell>
  );
}

// ============================================================
// RESULT
// ============================================================

function ResultPanel({ result }) {
  const analysis = result.analysis || result;

  const risk = analysis.risk_score ?? analysis.riskScore ?? 0;

  const severity = analysis.severity || "UNKNOWN";

  const indicators = analysis.indicators || analysis.evidence || [];

  const actions = analysis.actions || analysis.recommended_actions || [];

  const verdict = analysis.verdict;
  const meta = analysis.metadata_forensics;
  const ela = analysis.compression_forensics;
  const reasons = analysis.reasons || [];

  return (
    <div className="panel result-panel" id="analysis-result-section">
      {verdict && (
        <div className={`verdict-banner verdict-${verdict.color || 'emerald'}`}>
          <div className="verdict-banner-head">
            <span className="verdict-badge">{verdict.badge || verdict.label}</span>
            <span className="verdict-confidence">
              Authenticity: <strong>{analysis.authenticity_score ?? (100 - risk)}%</strong>
            </span>
          </div>
          <p className="verdict-summary">{verdict.summary}</p>
        </div>
      )}

      <div className="result-top">
        <div>
          <span className="result-label">THREAT ASSESSMENT</span>

          <h3>{analysis.threat_type || "SECURITY ANALYSIS"}</h3>
        </div>

        <span className={severityClass(severity)}>{severity}</span>
      </div>

      <div className="risk-score">
        <div>
          <span>Risk Score</span>

          <strong>{risk}</strong>

          <small>/ 100</small>
        </div>

        <div className="score-ring">{risk}</div>
      </div>

      {analysis.decoded_content && (
        <div className="result-section">
          <h4>Decoded QR Payload</h4>
          <div className="decoded-payload-box">
            <span className="decoded-payload-content">{analysis.decoded_content}</span>
            {analysis.domain && (
              <span className="decoded-payload-domain" style={{ display: 'block', marginTop: '6px', fontSize: '0.82rem', color: '#818cf8' }}>
                Extracted Host: <code>{analysis.domain}</code>
              </span>
            )}
          </div>
        </div>
      )}

      {analysis.dns_forensics && (
        <div className="result-section">
          <h4>DNS Resolution & Infrastructure Forensics</h4>
          <div className="meta-forensics-grid">
            <div className="forensics-subcard">
              <div className="forensics-subcard-title">
                <Globe size={14} /> DNS Root Zone & Host Resolution
              </div>
              <div className="forensics-subcard-row">
                <span>DNS Status:</span>
                <strong className={analysis.dns_forensics.status === "RESOLVED" ? "text-emerald" : "text-rose"}>
                  {analysis.dns_forensics.status === "RESOLVED"
                    ? "ACTIVE / RESOLVED"
                    : analysis.dns_forensics.status === "NXDOMAIN"
                    ? "NXDOMAIN (NON-EXISTENT)"
                    : analysis.dns_forensics.status}
                </strong>
              </div>
              <div className="forensics-subcard-row">
                <span>Web Reachability:</span>
                <strong className={analysis.dns_forensics.web_reachable ? "text-emerald" : "text-rose"}>
                  {analysis.dns_forensics.web_reachable
                    ? `LIVE (HTTP ${analysis.dns_forensics.http_status || 200})`
                    : analysis.dns_forensics.status === "RESOLVED"
                    ? "DEAD / UNRESPONSIVE (TIMED OUT)"
                    : "UNREACHABLE (NXDOMAIN)"}
                </strong>
              </div>
              <div className="forensics-subcard-row">
                <span>Resolved IPv4:</span>
                <code>{analysis.dns_forensics.resolved_ip || "None (Unresolvable / Dead Host)"}</code>
              </div>
              <div className="forensics-subcard-row">
                <span>Host Type:</span>
                <strong>{analysis.dns_forensics.is_ip ? "Raw IP Host" : "FQDN Domain"}</strong>
              </div>
            </div>

            <div className="forensics-subcard">
              <div className="forensics-subcard-title">
                <ShieldAlert size={14} /> Domain Attributes & Abuse Tier
              </div>
              <div className="forensics-subcard-row">
                <span>TLD Abuse Tier:</span>
                <strong className={analysis.dns_forensics.tld_risk === "HIGH" ? "text-rose" : analysis.dns_forensics.tld_risk === "SAFE" ? "text-emerald" : ""}>
                  .{analysis.dns_forensics.tld || "unknown"} ({analysis.dns_forensics.tld_risk || "STANDARD"})
                </strong>
              </div>
              <div className="forensics-subcard-row">
                <span>Shannon Entropy:</span>
                <strong className={analysis.dns_forensics.entropy >= 3.8 ? "text-rose" : "text-emerald"}>
                  {analysis.dns_forensics.entropy} bits ({analysis.dns_forensics.entropy >= 3.8 ? "DGA Anomaly" : "Natural Structure"})
                </strong>
              </div>
              {analysis.dns_forensics.impersonated_brand && (
                <div className="forensics-subcard-row">
                  <span>Impersonation Target:</span>
                  <strong className="text-rose">
                    {analysis.dns_forensics.impersonated_brand.toUpperCase()} {analysis.dns_forensics.is_typosquat ? "(Typosquat / Homoglyph)" : "(Spoofing)"}
                  </strong>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {analysis.authenticity_score !== undefined && (
        <div className="result-section">
          <h4>Forensic Media Metrics</h4>
          <div className="forensic-capabilities-grid" style={{ marginTop: '0.5rem', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))' }}>
            <div className="cap-badge">
              <Activity size={14} className="cap-icon cyan" />
              <span>Authenticity: <strong>{analysis.authenticity_score}%</strong></span>
            </div>
            <div className="cap-badge">
              <AlertTriangle size={14} className="cap-icon red" />
              <span>Manipulation: <strong>{analysis.manipulation_score}%</strong></span>
            </div>
            <div className="cap-badge">
              <Shield size={14} className="cap-icon purple" />
              <span>Confidence: <strong>{analysis.model_confidence}%</strong></span>
            </div>
          </div>
        </div>
      )}

      {(meta || ela) && (
        <div className="result-section">
          <h4>Digital Provenance & Compression Forensics</h4>
          <div className="meta-forensics-grid">
            {meta && (
              <div className="forensics-subcard">
                <div className="forensics-subcard-title">
                  <Camera size={14} /> EXIF & Sensor Provenance
                </div>
                <div className="forensics-subcard-row">
                  <span>Hardware Sensor:</span>
                  <strong>{meta.has_exif ? `${meta.camera_make} ${meta.camera_model}`.trim() : "None (Stripped / AI)"}</strong>
                </div>
                <div className="forensics-subcard-row">
                  <span>Editing Software:</span>
                  <strong className={meta.is_edited ? "text-amber" : ""}>{meta.software}</strong>
                </div>
                <div className="forensics-subcard-row">
                  <span>AI Engine Tag:</span>
                  <strong className={meta.ai_detected ? "text-rose" : ""}>{meta.ai_generator || "None"}</strong>
                </div>
              </div>
            )}
            {ela && (
              <div className="forensics-subcard">
                <div className="forensics-subcard-title">
                  <Layers size={14} /> Error Level Analysis (ELA)
                </div>
                <div className="forensics-subcard-row">
                  <span>Compression State:</span>
                  <strong className={ela.is_anomaly ? "text-rose" : "text-emerald"}>
                    {ela.is_anomaly ? "Spliced / Altered Anomaly" : "Uniform Natural Pattern"}
                  </strong>
                </div>
                <div className="forensics-subcard-row">
                  <span>ELA Divergence:</span>
                  <strong>Score: {ela.ela_score} / 100</strong>
                </div>
                <div className="forensics-subcard-row">
                  <span>Mean Error Diff:</span>
                  <strong>{ela.mean_diff}</strong>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {analysis.video_forensics && (
        <div className="result-section">
          <h4>Video Stream & Temporal Deepfake Forensics</h4>
          <div className="meta-forensics-grid">
            <div className="forensics-subcard">
              <div className="forensics-subcard-title">
                <Video size={14} /> Video Stream Specifications
              </div>
              <div className="forensics-subcard-row">
                <span>Resolution:</span>
                <strong>{analysis.video_forensics.resolution}</strong>
              </div>
              <div className="forensics-subcard-row">
                <span>Frame Rate & Timeline:</span>
                <strong>{analysis.video_forensics.fps} FPS ({analysis.video_forensics.duration_seconds}s)</strong>
              </div>
              <div className="forensics-subcard-row">
                <span>Keyframes Inspected:</span>
                <strong>{analysis.video_forensics.sampled_frames} of {analysis.video_forensics.total_frames} frames</strong>
              </div>
              <div className="forensics-subcard-row">
                <span>Bitrate:</span>
                <strong>{analysis.video_forensics.bitrate_kbps ? `${analysis.video_forensics.bitrate_kbps} kbps` : "N/A"}</strong>
              </div>
            </div>

            <div className="forensics-subcard">
              <div className="forensics-subcard-title">
                <Activity size={14} /> Temporal Motion & Continuity
              </div>
              <div className="forensics-subcard-row">
                <span>Temporal Motion Flow:</span>
                <strong className={analysis.video_forensics.temporal_flow === "NATURAL_CONTINUOUS" ? "text-emerald" : "text-rose"}>
                  {analysis.video_forensics.temporal_flow === "NATURAL_CONTINUOUS" ? "NATURAL & CONTINUOUS" : "IRREGULAR JITTER / FLICKER"}
                </strong>
              </div>
              <div className="forensics-subcard-row">
                <span>Motion Jitter Index (StdDev):</span>
                <strong className={analysis.video_forensics.temporal_jitter_std <= 2.5 ? "text-emerald" : "text-rose"}>
                  {analysis.video_forensics.temporal_jitter_std}
                </strong>
              </div>
              <div className="forensics-subcard-row">
                <span>Optical Sharpness Variance:</span>
                <strong className={analysis.video_forensics.blur_stability === "STABLE" ? "text-emerald" : "text-rose"}>
                  {analysis.video_forensics.blur_stability} (Score: {analysis.video_forensics.avg_blur})
                </strong>
              </div>
              <div className="forensics-subcard-row">
                <span>Splicing Cut Anomaly:</span>
                <strong className={analysis.video_forensics.splicing_detected ? "text-rose" : "text-emerald"}>
                  {analysis.video_forensics.splicing_detected ? "DETECTED (SEAM / CUT)" : "NONE (SEAMLESS)"}
                </strong>
              </div>
            </div>
          </div>
        </div>
      )}

      {reasons && reasons.length > 0 && (
        <div className="result-section">
          <h4>Forensic Evidence & Analysis (Why Flagged?)</h4>
          <div className="reasons-list">
            {reasons.map((reason, idx) => (
              <div className="reason-item" key={idx}>
                <span className="reason-bullet">▸</span>
                <span>{reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="result-section">
        <h4>Why was it detected?</h4>

        {indicators.length === 0 ? (
          <p className="muted">No additional indicators returned.</p>
        ) : (
          indicators.map((item, index) => (
            <div className="indicator" key={index}>
              <CheckCircle size={16} />

              <span>
                {typeof item === "string" ? item : JSON.stringify(item)}
              </span>
            </div>
          ))
        )}
      </div>

      <div className="result-section">
        <h4>Recommended Response</h4>

        {actions.length === 0 ? (
          <p className="muted">Review the incident manually.</p>
        ) : (
          actions.map((action, index) => (
            <button className="response-action" key={index}>
              <ShieldAlert size={15} />

              {typeof action === "string" ? action : JSON.stringify(action)}
            </button>
          ))
        )}
      </div>

      {result.event_id && (
        <div className="event-created">
          <CheckCircle size={16} />
          Incident #{result.event_id}
          saved to CYBERGUARD-X
        </div>
      )}
    </div>
  );
}

// ============================================================
// INCIDENTS
// ============================================================

function IncidentsPage({ events, onSelect, onBack }) {
  return (
    <div className="analysis-page">
      <button className="back-btn" onClick={onBack}>
        ← Back to Dashboard
      </button>

      <div className="analysis-title">
        <div className="analysis-icon">
          <ShieldAlert size={28} />
        </div>

        <div>
          <p className="eyebrow">SECURITY INCIDENTS</p>

          <h2>Incident Management</h2>

          <span>Review detected threats and their risk assessments.</span>
        </div>
      </div>

      <div className="panel events-panel">
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>THREAT</th>
                <th>RISK</th>
                <th>SEVERITY</th>
                <th>STATUS</th>
                <th></th>
              </tr>
            </thead>

            <tbody>
              {events
                .slice()
                .reverse()
                .map((event) => (
                  <tr key={event.id}>
                    <td>#{event.id}</td>

                    <td>
                      <div className="threat-name">
                        {threatIconStatic(event.threat_type)}

                        {event.threat_type}
                      </div>
                    </td>

                    <td>{event.risk_score}/100</td>

                    <td>
                      <span className={severityClass(event.severity)}>
                        {event.severity}
                      </span>
                    </td>

                    <td>{event.status}</td>

                    <td>
                      <button
                        className="view-btn"
                        onClick={() => onSelect(event)}
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function threatIconStatic(type) {
  switch (type) {
    case "PHISHING":
      return <Mail size={17} />;

    case "MALICIOUS_URL":
      return <Globe size={17} />;

    case "ACCOUNT_TAKEOVER":
      return <LockKeyhole size={17} />;

    case "DIGITAL_IMPERSONATION":
      return <UserRound size={17} />;

    case "QR_PHISHING":
    case "SUSPICIOUS_QR":
    case "QR_ANALYSIS":
    case "QR_CONTENT":
      return <QrCode size={17} />;

    case "MEDIA_MANIPULATION":
    case "DEEPFAKE_IMAGE":
    case "DEEPFAKE_VIDEO":
      return <ImageIcon size={17} />;

    default:
      return <AlertTriangle size={17} />;
  }
}

// ============================================================
// SIMULATOR
// ============================================================

function SimulatorPage({ onComplete, onBack, onViewIncidents, showToast }) {
  const [activeSim, setActiveSim] = useState("");
  const [lastResult, setLastResult] = useState(null);

  async function runPhishingSimulation() {
    setActiveSim("phishing");
    try {
      const response = await fetch(`${API}/analyze/phishing`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sender: "security-alert@microsoft-365-verify.com",
          subject: "URGENT: Executive Account Suspension Warning - Immediate Verification Required",
          message:
            "Your enterprise single sign-on credentials will expire in 2 hours. Submit your username and current OTP to preserve mailbox connectivity.",
          url: "https://secure-login-365.verify-portal.net/auth",
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Simulation failed");
      setLastResult({
        id: data.event_id,
        title: "PHISHING CAMPAIGN DETECTED",
        score: data.analysis?.risk_score ?? 85,
        severity: data.analysis?.severity ?? "CRITICAL",
        summary: "Simulated credential harvesting email intercepted & logged.",
      });
      onComplete();
      showToast(`Incident #${data.event_id} created in SOC Telemetry`);
    } catch (error) {
      showToast(error.message);
    } finally {
      setActiveSim("");
    }
  }

  async function runUrlSimulation() {
    setActiveSim("url");
    try {
      const response = await fetch(`${API}/analyze/url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: "http://192.168.1.105:8080/secure-banking-login/update.php?user=admin",
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Simulation failed");
      setLastResult({
        id: data.event_id,
        title: "MALICIOUS IP DOMAIN BLOCKED",
        score: data.analysis?.risk_score ?? 90,
        severity: data.analysis?.severity ?? "CRITICAL",
        summary: "Raw IP host with credential harvesting payload detected.",
      });
      onComplete();
      showToast(`Incident #${data.event_id} created in SOC Telemetry`);
    } catch (error) {
      showToast(error.message);
    } finally {
      setActiveSim("");
    }
  }

  async function runQRSimulation() {
    setActiveSim("qr");
    try {
      const res = await fetch("/samples/qr_phishing.png");
      const blob = await res.blob();
      const sampleFile = new File([blob], "phishing_qr.png", { type: "image/png" });
      const formData = new FormData();
      formData.append("file", sampleFile);

      const response = await fetch(`${API}/analyze/qr`, {
        method: "POST",
        body: formData,
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Simulation failed");
      setLastResult({
        id: data.event_id,
        title: "QUISHING MATRIX PAYLOAD INTERCEPTED",
        score: data.analysis?.risk_score ?? 80,
        severity: data.analysis?.severity ?? "HIGH",
        summary: "Physical QR code decoded; malicious destination URL flagged.",
      });
      onComplete();
      showToast(`Incident #${data.event_id} created in SOC Telemetry`);
    } catch (error) {
      showToast(error.message);
    } finally {
      setActiveSim("");
    }
  }

  async function runMediaSimulation() {
    setActiveSim("media");
    try {
      const res = await fetch("/samples/media_deepfake_sample.png");
      const blob = await res.blob();
      const sampleFile = new File([blob], "ai_deepfake.png", { type: "image/png" });
      const formData = new FormData();
      formData.append("file", sampleFile);

      const response = await fetch(`${API}/analyze/image`, {
        method: "POST",
        body: formData,
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Simulation failed");
      setLastResult({
        id: data.event_id,
        title: "SYNTHETIC MEDIA MANIPULATION DETECTED",
        score: data.analysis?.risk_score ?? 75,
        severity: data.analysis?.severity ?? "HIGH",
        summary: "Frequency domain artifacts & synthetic GAN signatures confirmed.",
      });
      onComplete();
      showToast(`Incident #${data.event_id} created in SOC Telemetry`);
    } catch (error) {
      showToast(error.message);
    } finally {
      setActiveSim("");
    }
  }

  async function runLoginSimulation() {
    setActiveSim("login");
    try {
      const response = await fetch(`${API}/analyze/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_id: 1,
          ip_address: "185.220.101.5",
          location: "Moscow, Russia",
          device: "Kali Linux Automated Exploit Suite",
          login_status: "SUCCESS",
          failed_attempts: 12,
          is_new_device: true,
          is_unusual_location: true,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Simulation failed");
      setLastResult({
        id: data.event_id,
        title: "ACCOUNT TAKEOVER & BRUTE FORCE BURST",
        score: data.analysis?.risk_score ?? 95,
        severity: data.analysis?.severity ?? "CRITICAL",
        summary: "12 failed attempts followed by new device from high-risk foreign IP.",
      });
      onComplete();
      showToast(`Incident #${data.event_id} created in SOC Telemetry`);
    } catch (error) {
      showToast(error.message);
    } finally {
      setActiveSim("");
    }
  }

  return (
    <div className="analysis-page">
      <button className="back-btn" onClick={onBack}>
        ← Back to Dashboard
      </button>

      <div className="analysis-title">
        <div className="analysis-icon">
          <Zap size={28} />
        </div>
        <div>
          <p className="eyebrow">PRESENTATION MODE</p>
          <h2>CYBERGUARD-X Demo Simulator</h2>
          <span>
            Safe, reproducible threat events designed for live demonstrations, hackathon judges, and SOC operator drills.
          </span>
        </div>
      </div>

      <div className="simulator-grid">
        {/* Phishing Card */}
        <div className="simulation-card">
          <div className="sim-card-header">
            <div className="sim-icon-box purple">
              <Mail size={24} />
            </div>
            <span className="sim-tag">EMAIL VECTOR</span>
          </div>
          <h3>Credential Phishing Attack</h3>
          <p>
            Injects an urgent executive account suspension notice with psychological coercion and fake SSO credential trap.
          </p>
          <button
            className="sim-run-btn"
            onClick={runPhishingSimulation}
            disabled={!!activeSim}
          >
            {activeSim === "phishing" ? (
              <>
                <RefreshCw size={15} className="spin-icon" />
                SIMULATING ATTACK...
              </>
            ) : (
              <>
                <Zap size={15} />
                SIMULATE PHISHING
              </>
            )}
          </button>
        </div>

        {/* URL Card */}
        <div className="simulation-card">
          <div className="sim-card-header">
            <div className="sim-icon-box cyan">
              <Globe size={24} />
            </div>
            <span className="sim-tag">WEB & NETWORK</span>
          </div>
          <h3>Raw IP Domain Infiltration</h3>
          <p>
            Simulates a stealthy web attack leveraging an unencrypted raw IP address host and obfuscated banking update payload.
          </p>
          <button
            className="sim-run-btn"
            onClick={runUrlSimulation}
            disabled={!!activeSim}
          >
            {activeSim === "url" ? (
              <>
                <RefreshCw size={15} className="spin-icon" />
                SIMULATING ATTACK...
              </>
            ) : (
              <>
                <Zap size={15} />
                SIMULATE MALICIOUS URL
              </>
            )}
          </button>
        </div>

        {/* QR Quishing Card */}
        <div className="simulation-card">
          <div className="sim-card-header">
            <div className="sim-icon-box amber">
              <QrCode size={24} />
            </div>
            <span className="sim-tag">PHYSICAL MATRIX</span>
          </div>
          <h3>Physical-to-Digital Quishing Trap</h3>
          <p>
            Decodes a rogue QR barcode sticker directing victims to a typosquatted Apple ID verification harvest portal.
          </p>
          <button
            className="sim-run-btn"
            onClick={runQRSimulation}
            disabled={!!activeSim}
          >
            {activeSim === "qr" ? (
              <>
                <RefreshCw size={15} className="spin-icon" />
                SIMULATING ATTACK...
              </>
            ) : (
              <>
                <Zap size={15} />
                SIMULATE QUISHING QR
              </>
            )}
          </button>
        </div>

        {/* Media Deepfake Card */}
        <div className="simulation-card">
          <div className="sim-card-header">
            <div className="sim-icon-box emerald">
              <ImageIcon size={24} />
            </div>
            <span className="sim-tag">SYNTHETIC MEDIA</span>
          </div>
          <h3>Synthetic AI Facial Deepfake</h3>
          <p>
            Scans an AI-generated synthetic portrait for facial landmark distortion, compression artifacts, and GAN synthesis noise.
          </p>
          <button
            className="sim-run-btn"
            onClick={runMediaSimulation}
            disabled={!!activeSim}
          >
            {activeSim === "media" ? (
              <>
                <RefreshCw size={15} className="spin-icon" />
                SIMULATING ATTACK...
              </>
            ) : (
              <>
                <Zap size={15} />
                SIMULATE DEEPFAKE
              </>
            )}
          </button>
        </div>

        {/* Account Takeover Card */}
        <div className="simulation-card">
          <div className="sim-card-header">
            <div className="sim-icon-box red">
              <LockKeyhole size={24} />
            </div>
            <span className="sim-tag">IDENTITY VECTOR</span>
          </div>
          <h3>Brute-Force Account Takeover</h3>
          <p>
            Triggers a burst of 12 failed logins followed by an anomalous successful access from an unknown Russian device.
          </p>
          <button
            className="sim-run-btn"
            onClick={runLoginSimulation}
            disabled={!!activeSim}
          >
            {activeSim === "login" ? (
              <>
                <RefreshCw size={15} className="spin-icon" />
                SIMULATING ATTACK...
              </>
            ) : (
              <>
                <Zap size={15} />
                SIMULATE TAKEOVER
              </>
            )}
          </button>
        </div>
      </div>

      {lastResult && (
        <div className="simulation-result">
          <div className="sim-result-left">
            <div className="sim-result-icon">
              <CheckCircle size={24} />
            </div>
            <div className="sim-result-text">
              <strong>INCIDENT #{lastResult.id} LOGGED — {lastResult.title}</strong>
              <span>
                Risk Score: {lastResult.score}/100 &bull; Severity: {lastResult.severity} &bull; {lastResult.summary}
              </span>
            </div>
          </div>
          {onViewIncidents && (
            <button className="sim-view-incidents-btn" onClick={onViewIncidents}>
              View in Incidents →
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ============================================================
// INCIDENT MODAL
// ============================================================

function IncidentModal({ event, onClose }) {
  return (
    <div className="modal-backdrop">
      <div className="incident-modal">
        <button className="close-btn" onClick={onClose}>
          <X size={20} />
        </button>

        <span className="result-label">SECURITY INCIDENT #{event.id}</span>

        <h2>{event.threat_type}</h2>

        <div className="modal-risk">
          <strong>{event.risk_score}</strong>

          <span>/100</span>

          <span className={severityClass(event.severity)}>
            {event.severity}
          </span>
        </div>

        <div className="modal-section">
          <h4>Detection Summary</h4>

          <p>{event.summary || "Security threat detected by CYBERGUARD-X."}</p>
        </div>

        <div className="modal-section">
          <h4>Source</h4>

          <p>{event.source}</p>
        </div>

        <div className="modal-section">
          <h4>Incident Status</h4>

          <span className="status">{event.status}</span>
        </div>

        <button className="analyze-btn" onClick={onClose}>
          Close Incident
        </button>
      </div>
    </div>
  );
}

// ============================================================
// INPUT COMPONENTS
// ============================================================

function Field({ label, value, onChange, placeholder, type = "text" }) {
  return (
    <label className="field">
      <span>{label}</span>

      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        required
      />
    </label>
  );
}

function TextArea({ label, value, onChange, placeholder }) {
  return (
    <label className="field">
      <span>{label}</span>

      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        required
      />
    </label>
  );
}

function SelectField({ label, value, onChange, options }) {
  return (
    <label className="field">
      <span>{label}</span>

      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}



export default App;

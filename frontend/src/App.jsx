import { useEffect, useState } from "react";

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
} from "lucide-react";

import "./App.css";

const API = "http://127.0.0.1:8000";


function severityClass(severity) {
  if (!severity) {
    return "severity safe";
  }

  return `severity ${severity.toLowerCase()}`;
}
function App() {
  const [page, setPage] = useState("dashboard");

  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);

  const [loading, setLoading] = useState(false);

  const [selectedEvent, setSelectedEvent] = useState(null);

  const [toast, setToast] = useState("");

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

    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  }

  // ==========================================================
  // SEVERITY
  // ==========================================================

  // function severityClass(severity) {
  //   if (!severity) {
  //     return "severity safe";
  //   }

  //   return `severity ${severity.toLowerCase()}`;
  // }

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
  };

  // ==========================================================
  // DASHBOARD
  // ==========================================================

  function Dashboard() {
    return (
      <>
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS CENTER</p>

            <h2>Threat Intelligence Dashboard</h2>
          </div>

          <div className="header-right">
            <div className="live-status">
              <span className="pulse"></span>
              LIVE MONITORING
            </div>

            <button className="refresh-btn" onClick={loadDashboard}>
              <RefreshCw size={16} />
              Refresh
            </button>
          </div>
        </header>

        {/* ================================================= */}
        {/* STATISTICS */}
        {/* ================================================= */}

        <section className="stats-grid">
          <StatCard
            icon={<Activity />}
            title="Total Events"
            value={stats?.total_events ?? events.length}
            description="All monitored events"
            type="blue"
          />

          <StatCard
            icon={<ShieldAlert />}
            title="Total Threats"
            value={stats?.total_threats ?? events.length}
            description="Detected security threats"
            type="red"
          />

          <StatCard
            icon={<AlertTriangle />}
            title="Critical"
            value={
              stats?.severity?.critical ??
              events.filter((e) => e.severity === "CRITICAL").length
            }
            description="Immediate attention required"
            type="critical"
          />

          <StatCard
            icon={<ShieldAlert />}
            title="High Risk"
            value={
              stats?.severity?.high ??
              events.filter((e) => e.severity === "HIGH").length
            }
            description="High priority threats"
            type="orange"
          />
        </section>

        {/* ================================================= */}
        {/* QUICK ACTIONS */}
        {/* ================================================= */}

        <section className="quick-actions">
          <div>
            <h3>Threat Analysis Center</h3>

            <p>Analyze a security event directly from CYBERGUARD-X.</p>
          </div>

          <div className="quick-buttons">
            <button onClick={() => navigate("phishing")}>
              <Mail size={17} />
              Analyze Phishing
            </button>

            <button onClick={() => navigate("url")}>
              <Globe size={17} />
              Analyze URL
            </button>

            <button onClick={() => navigate("login")}>
              <LockKeyhole size={17} />
              Analyze Login
            </button>

            <button onClick={() => navigate("impersonation")}>
              <UserRound size={17} />
              Analyze Identity
            </button>
          </div>
        </section>

        {/* ================================================= */}
        {/* TWO PANELS */}
        {/* ================================================= */}

        <section className="content-grid">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Threat Distribution</h3>

                <span>Current severity breakdown</span>
              </div>

              <Shield size={20} />
            </div>

            <SeverityRow
              name="Critical"
              count={stats?.severity?.critical ?? 0}
              type="critical"
            />

            <SeverityRow
              name="High"
              count={stats?.severity?.high ?? 0}
              type="high"
            />

            <SeverityRow
              name="Medium"
              count={stats?.severity?.medium ?? 0}
              type="medium"
            />

            <SeverityRow
              name="Low"
              count={stats?.severity?.low ?? 0}
              type="low"
            />
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Detection Modules</h3>

                <span>Active CYBERGUARD-X engines</span>
              </div>

              <Activity size={20} />
            </div>

            <ModuleRow
              icon={<Mail />}
              name="Phishing Detection"
              count={moduleCounts.phishing}
              onClick={() => navigate("phishing")}
            />

            <ModuleRow
              icon={<Globe />}
              name="Malicious URL"
              count={moduleCounts.maliciousUrl}
              onClick={() => navigate("url")}
            />

            <ModuleRow
              icon={<LockKeyhole />}
              name="Account Takeover"
              count={moduleCounts.accountTakeover}
              onClick={() => navigate("login")}
            />

            <ModuleRow
              icon={<UserRound />}
              name="Digital Impersonation"
              count={moduleCounts.impersonation}
              onClick={() => navigate("impersonation")}
            />

            <ModuleRow
              icon={<QrCode />}
              name="QR Phishing Detection"
              count={moduleCounts.qr}
              onClick={() => navigate("qr")}
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
                  {events
                    .slice()
                    .reverse()
                    .map((event) => (
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
                    ))}
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
      </>
    );
  }

  // ==========================================================
  // MAIN PAGE
  // ==========================================================

  return (
    <div className="app">
      {/* ==================================================== */}
      {/* SIDEBAR */}
      {/* ==================================================== */}

      <aside className="sidebar">
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

        <div className="system-status">
          <span className="status-dot"></span>

          <div>
            <strong>SYSTEM ONLINE</strong>

            <span>AI threat engine active</span>
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

function StatCard({ icon, title, value, description, type }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${type}`}>{icon}</div>

      <div>
        <span>{title}</span>

        <strong>{value}</strong>

        <small>{description}</small>
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
  const width = Math.min(count * 30, 100);

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
          style={{
            width: `${width}%`,
          }}
        />
      </div>
    </div>
  );
}

// ============================================================
// MODULE ROW
// ============================================================

function ModuleRow({ icon, name, count, onClick }) {
  return (
    <button className="module" onClick={onClick}>
      {icon}

      <div>
        <strong>{name}</strong>

        <span>Active</span>
      </div>

      <b>{count}</b>
    </button>
  );
}

// ============================================================
// GENERIC ANALYSIS PAGE
// ============================================================

function AnalysisShell({ title, subtitle, icon, children, result, onBack }) {
  return (
    <div className="analysis-page">
      <button className="back-btn" onClick={onBack}>
        ← Back to Dashboard
      </button>

      <div className="analysis-title">
        <div className="analysis-icon">{icon}</div>

        <div>
          <p className="eyebrow">AI THREAT ANALYSIS</p>

          <h2>{title}</h2>

          <span>{subtitle}</span>
        </div>
      </div>

      <div className="analysis-grid">
        <div className="panel analysis-form">{children}</div>

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

  const [result, setResult] = useState(null);

  function update(key, value) {
    setForm({
      ...form,
      [key]: value,
    });
  }

  async function analyze(event) {
    event.preventDefault();

    setResult(null);

    try {
      const response = await fetch(`${API}/analyze/phishing`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(form),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Analysis failed");
      }

      setResult(data);

      onComplete();
    } catch (error) {
      showToast(error.message);
    }
  }

  return (
    <AnalysisShell
      title="Check a Suspicious Email"
      subtitle="Received a suspicious email? Enter the details below, and we'll check it."
      icon={<Mail size={28} />}
      result={result}
      onBack={onBack}
    >
      <form onSubmit={analyze}>
        <Field
          label="Sender"
          value={form.sender}
          onChange={(v) => update("sender", v)}
          placeholder="security-alert@example.com"
        />

        <Field
          label="Subject"
          value={form.subject}
          onChange={(v) => update("subject", v)}
          placeholder="URGENT: Verify your account"
        />

        <TextArea
          label="Message"
          value={form.message}
          onChange={(v) => update("message", v)}
          placeholder="Enter the suspicious message..."
        />

        <Field
          label="Suspicious URL"
          value={form.url}
          onChange={(v) => update("url", v)}
          placeholder="https://secure-account.example.com/login"
        />

        <button className="analyze-btn" type="submit">
          <Search size={18} />
          CHECK THIS EMAIL
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

  const [result, setResult] = useState(null);

  async function analyze(event) {
    event.preventDefault();

    setResult(null);

    try {
      const response = await fetch(`${API}/analyze/url`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "URL analysis failed");
      }

      setResult(data);

      onComplete();
    } catch (error) {
      showToast(error.message);
    }
  }

  return (
    <AnalysisShell
      title="Check a Website Link"
      subtitle="Not sure if a website link is safe? Enter it below and we'll check it."
      icon={<Globe size={28} />}
      result={result}
      onBack={onBack}
    >
      <form onSubmit={analyze}>
        <div className="url-input-box">
          <Globe size={20} />

          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/login"
            required
          />
        </div>

        <div className="helper-box">
          <strong>What will we check?</strong>

          <span>
            🔹 Does the website address look unusual?
            <br />
            🔹 Does the link look fake or copied?
            <br />
            🔹 Does it redirect somewhere suspicious?
            <br />
            🔹 Are there other warning signs?
          </span>
        </div>

        <button className="analyze-btn" type="submit">
          <Search size={18} />
          CHECK WEBSITE
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

  function update(key, value) {
    setForm({
      ...form,
      [key]: value,
    });
  }

  async function analyze(event) {
    event.preventDefault();

    try {
      const response = await fetch(`${API}/analyze/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ...form,
          user_id: Number(form.user_id),
          failed_attempts: Number(form.failed_attempts),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Login analysis failed");
      }

      setResult(data);

      onComplete();
    } catch (error) {
      showToast(error.message);
    }
  }

  return (
    <AnalysisShell
      title="Check a Suspicious Login"
      subtitle="Something unusual happened during a login? Enter the details below and CYBERGUARD-X will check it."
      icon={<LockKeyhole size={28} />}
      result={result}
      onBack={onBack}
    >
      <form onSubmit={analyze}>
        <div className="form-two">
          {/* <Field
            label="User ID"
            value={form.user_id}
            onChange={(v) => update("user_id", v)}
          /> */}

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

  function update(key, value) {
    setForm({
      ...form,
      [key]: value,
    });
  }

  async function analyze(event) {
    event.preventDefault();

    try {
      const response = await fetch(`${API}/analyze/impersonation`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(form),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Identity analysis failed");
      }

      setResult(data);

      onComplete();
    } catch (error) {
      showToast(error.message);
    }
  }

  return (
    <AnalysisShell
      title="Check if Someone is Pretending to Be Someone Else"
      subtitle="Think someone is pretending to be another person or organization? Enter the details below and we'll check."
      icon={<UserRound size={28} />}
      result={result}
      onBack={onBack}
    >
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

  function handleFileChange(event) {
    const selectedFile = event.target.files?.[0];

    if (!selectedFile) {
      return;
    }

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

    const imageUrl = URL.createObjectURL(selectedFile);
    setPreview(imageUrl);
  }

  async function analyzeQR(event) {
    event.preventDefault();

    if (!file) {
      showToast("Please upload a QR code image first.");
      return;
    }

    setAnalyzing(true);
    setResult(null);

    try {
      const formData = new FormData();

      formData.append("file", file);

      const response = await fetch(`${API}/analyze/qr`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "QR code analysis failed"
        );
      }

      setResult(data);

      onComplete();

    } catch (error) {
      console.error(error);
      showToast(error.message);
    } finally {
      setAnalyzing(false);
    }
  }

  return (
    <AnalysisShell
      title="QR Phishing Detection"
      subtitle="Upload a QR code image and CYBERGUARD-X will decode and analyze its destination."
      icon={<QrCode size={28} />}
      result={result}
      onBack={onBack}
    >
      <form onSubmit={analyzeQR}>

        <div className="qr-upload-box">

          <QrCode size={42} />

          <h3>Upload QR Code</h3>

          <p>
            Select a QR code image to scan for phishing
            and suspicious destinations.
          </p>

          <input
            type="file"
            accept="image/png,image/jpeg,image/jpg,image/webp"
            onChange={handleFileChange}
          />

        </div>

        {preview && (
          <div className="qr-preview">

            <img
              src={preview}
              alt="QR code preview"
            />

            <span>
              {file?.name}
            </span>

          </div>
        )}

        <div className="helper-box">

          <strong>What will we check?</strong>

          <span>
            🔹 Decode the QR code content
            <br />
            🔹 Detect whether it contains a URL
            <br />
            🔹 Analyze the destination for phishing indicators
            <br />
            🔹 Calculate a risk score
            <br />
            🔹 Recommend a security response
          </span>

        </div>

        <button
          className="analyze-btn"
          type="submit"
          disabled={analyzing || !file}
        >
          <QrCode size={18} />

          {analyzing
            ? "ANALYZING QR CODE..."
            : "SCAN QR CODE"}
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

  return (
    <div className="panel result-panel">
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

    default:
      return <AlertTriangle size={17} />;
  }
}

// ============================================================
// SIMULATOR
// ============================================================

function SimulatorPage({ onComplete, onBack, showToast }) {
  const [running, setRunning] = useState(false);

  const [message, setMessage] = useState("");

  async function runPhishingSimulation() {
    setRunning(true);

    setMessage("Simulating phishing attack...");

    try {
      const response = await fetch(`${API}/analyze/phishing`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          sender: "security-alert@simulation.local",

          subject: "URGENT: Verify your account immediately",

          message:
            "Your account will be blocked. Verify your password and OTP immediately by clicking the link below.",

          url: "https://secure-account-verify.example.com/login",
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Simulation failed");
      }

      setMessage(`THREAT DETECTED — Incident #${data.event_id}`);

      onComplete();
    } catch (error) {
      showToast(error.message);
    }

    setRunning(false);
  }

  async function runLoginSimulation() {
    setRunning(true);

    setMessage("Simulating account takeover...");

    try {
      const response = await fetch(`${API}/analyze/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          user_id: 1,

          ip_address: "203.0.113.45",

          location: "Unknown Location",

          device: "Unknown Windows Device",

          login_status: "SUCCESS",

          failed_attempts: 8,

          is_new_device: true,

          is_unusual_location: true,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Simulation failed");
      }

      setMessage(`ACCOUNT TAKEOVER ANALYZED — Incident #${data.event_id}`);

      onComplete();
    } catch (error) {
      showToast(error.message);
    }

    setRunning(false);
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
            Safe simulated events for demonstrating the detection pipeline.
          </span>
        </div>
      </div>

      <div className="simulator-grid">
        <div className="simulation-card">
          <Mail size={28} />

          <h3>Phishing Attack</h3>

          <p>Simulate an urgent credential phishing message.</p>

          <button onClick={runPhishingSimulation} disabled={running}>
            {running ? "RUNNING..." : "RUN PHISHING"}
          </button>
        </div>

        <div className="simulation-card">
          <LockKeyhole size={28} />

          <h3>Account Takeover</h3>

          <p>Simulate failed logins, new device and unusual location.</p>

          <button onClick={runLoginSimulation} disabled={running}>
            {running ? "RUNNING..." : "RUN ACCOUNT TAKEOVER"}
          </button>
        </div>
      </div>

      {message && (
        <div className="simulation-result">
          <CheckCircle size={20} />

          {message}
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

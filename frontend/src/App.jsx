import { useEffect, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:8000";

function App() {
  const [token, setToken] = useState(localStorage.getItem("token"));
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const [dashboard, setDashboard] = useState(null);
  const [threat, setThreat] = useState(null);

  const [users, setUsers] = useState([]);
  const [messages, setMessages] = useState([]);

  const [selectedUser, setSelectedUser] = useState("");
  const [messageText, setMessageText] = useState("");

  const [loading, setLoading] = useState(false);
  const [loadingData, setLoadingData] = useState(false);
  const [sending, setSending] = useState(false);

  const [error, setError] = useState("");
  const [messageStatus, setMessageStatus] = useState("");

  async function request(endpoint, options = {}, authToken = token) {
    const response = await fetch(`${API}${endpoint}`, {
      ...options,
      headers: {
        ...(options.headers || {}),
        Authorization: `Bearer ${authToken}`,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Request failed");
    }

    return data;
  }

  async function loadData(authToken = token) {
    if (!authToken) return;

    setLoadingData(true);
    setError("");

    try {
      const [dashboardData, threatData, usersData, messagesData] =
        await Promise.all([
          request("/dashboard/overview", {}, authToken),
          request("/security/threat", {}, authToken),
          request("/messages/users", {}, authToken),
          request("/messages/", {}, authToken),
        ]);

      setDashboard(dashboardData);
      setThreat(threatData);
      setUsers(usersData);
      setMessages(messagesData);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingData(false);
    }
  }

  async function login(e) {
    e.preventDefault();

    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username,
          password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Login failed");
      }

      localStorage.setItem("token", data.access_token);
      setToken(data.access_token);

      await loadData(data.access_token);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function sendMessage(e) {
    e.preventDefault();

    if (!selectedUser) {
      setMessageStatus("Select a recipient first.");
      return;
    }

    if (!messageText.trim()) {
      setMessageStatus("Enter a message.");
      return;
    }

    setSending(true);
    setMessageStatus("");

    try {
      await request("/messages/send", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          receiver_id: Number(selectedUser),
          content: messageText,
        }),
      });

      setMessageText("");
      setMessageStatus("✓ Message encrypted and sent securely.");

      const updatedMessages = await request("/messages/");
      setMessages(updatedMessages);
    } catch (err) {
      setMessageStatus(`Error: ${err.message}`);
    } finally {
      setSending(false);
    }
  }

  function logout() {
    localStorage.removeItem("token");
    setToken(null);
    setDashboard(null);
    setThreat(null);
    setUsers([]);
    setMessages([]);
    setUsername("");
    setPassword("");
  }

  useEffect(() => {
    if (token) {
      loadData(token);
    }
  }, []);

  useEffect(() => {
    if (!token) return;

    const interval = setInterval(() => {
      loadData(token);
    }, 30000);

    return () => clearInterval(interval);
  }, [token]);

  if (!token) {
    return (
      <div className="login-page">
        <div className="login-card">
          <div className="brand">
            <div className="brand-icon">Q</div>

            <div>
              <h1>QuantumShield</h1>
              <span>Security Intelligence Platform</span>
            </div>
          </div>

          <div className="login-heading">
            <h2>Secure Login</h2>
            <p>Access your security operations dashboard.</p>
          </div>

          <form onSubmit={login}>
            <label>Username</label>

            <input
              type="text"
              placeholder="Enter username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />

            <label>Password</label>

            <input
              type="password"
              placeholder="Enter password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />

            <button
              className="login-button"
              type="submit"
              disabled={loading}
            >
              {loading ? "Authenticating..." : "Sign In"}
            </button>
          </form>

          {error && <div className="error-box">{error}</div>}

          <div className="login-footer">
            🔐 Post-Quantum Security&nbsp; • &nbsp;🤖 AI Threat Detection
          </div>
        </div>
      </div>
    );
  }

  if (loadingData && !dashboard) {
    return (
      <div className="loading-page">
        <div className="loader"></div>
        <h2>Loading QuantumShield</h2>
        <p>Initializing security intelligence...</p>
      </div>
    );
  }

  if (!dashboard) {
    return (
      <div className="loading-page">
        <h2>Unable to load dashboard</h2>
        <p>{error}</p>

        <button onClick={() => loadData(token)}>
          Retry
        </button>
      </div>
    );
  }

  const stats = dashboard.statistics;
  const risk = dashboard.risk.user;
  const prediction = threat?.prediction;

  const threatScore = prediction?.threat_score ?? 0;
  const threatLevel = prediction?.threat_level ?? "LOW";
  const threatProbability = prediction?.threat_probability ?? 0;
  const normalProbability = prediction?.normal_probability ?? 1;

  return (
    <div className="app">

      {/* TOPBAR */}

      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">Q</div>

          <div>
            <h1>QuantumShield</h1>
            <span>Security Operations Center</span>
          </div>
        </div>

        <div className="topbar-right">

          <div className="online-status">
            <span className="status-dot"></span>
            System Online
          </div>

          <div className="user-info">
            <div className="avatar">
              {dashboard.user.username?.charAt(0).toUpperCase()}
            </div>

            <span>{dashboard.user.username}</span>
          </div>

          <button className="logout" onClick={logout}>
            Logout
          </button>

        </div>
      </header>


      {/* DASHBOARD */}

      <main className="dashboard">

        <section className="welcome">
          <div>
            <h2>Security Overview</h2>
            <p>
              Real-time monitoring and AI-powered threat detection
            </p>
          </div>

          <button
            className="refresh-button"
            onClick={() => loadData(token)}
            disabled={loadingData}
          >
            ↻ {loadingData ? "Refreshing..." : "Refresh"}
          </button>
        </section>

        {error && (
          <div className="error-box dashboard-error">
            {error}
          </div>
        )}


        {/* STATISTICS */}

        <section className="stats-grid">

          <div className="stat-card">
            <div className="stat-icon">👥</div>

            <div>
              <span>Total Users</span>
              <strong>{stats.total_users}</strong>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">✉</div>

            <div>
              <span>Total Messages</span>
              <strong>{stats.total_messages}</strong>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">🛡</div>

            <div>
              <span>Security Events</span>
              <strong>{stats.total_security_events}</strong>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">⚠</div>

            <div>
              <span>Failed Logins</span>
              <strong>{stats.failed_logins}</strong>
            </div>
          </div>

        </section>


        {/* AI + RISK */}

        <section className="main-grid">

          <div className="panel threat-panel">

            <div className="panel-header">
              <div>
                <h3>AI Threat Detection</h3>
                <p>Machine-learning security analysis</p>
              </div>

              <span className="ai-badge">
                AI MODEL
              </span>
            </div>

            <div className="threat-content">

              <div className="score-circle">

                <div className="score-inner">
                  <strong>{threatScore}</strong>
                  <span>/ 100</span>
                </div>

              </div>

              <div className="threat-details">

                <span className="label">
                  Current Threat Level
                </span>

                <div
                  className={`threat-level ${threatLevel.toLowerCase()}`}
                >
                  {threatLevel}
                </div>

                <div className="probability">

                  <div className="probability-row">
                    <span>Threat Probability</span>

                    <strong>
                      {(threatProbability * 100).toFixed(1)}%
                    </strong>
                  </div>

                  <div className="progress">
                    <div
                      className="progress-fill"
                      style={{
                        width: `${threatProbability * 100}%`,
                      }}
                    ></div>
                  </div>

                </div>

                <div className="probability">

                  <div className="probability-row">
                    <span>Normal Probability</span>

                    <strong>
                      {(normalProbability * 100).toFixed(1)}%
                    </strong>
                  </div>

                  <div className="progress">
                    <div
                      className="progress-fill normal"
                      style={{
                        width: `${normalProbability * 100}%`,
                      }}
                    ></div>
                  </div>

                </div>

                <p className="model-name">
                  Model:{" "}
                  <strong>
                    {prediction?.model || "Random Forest"}
                  </strong>
                </p>

              </div>
            </div>
          </div>


          <div className="panel risk-panel">

            <div className="panel-header">
              <div>
                <h3>Security Risk</h3>
                <p>Current user risk assessment</p>
              </div>

              <span
                className={`risk-badge ${risk.risk_level.toLowerCase()}`}
              >
                {risk.risk_level}
              </span>
            </div>

            <div className="risk-number">
              <strong>{risk.risk_score}</strong>
              <span>Risk Score</span>
            </div>

            <div className="risk-stats">

              <div>
                <span>Events</span>
                <strong>{risk.event_count}</strong>
              </div>

              <div>
                <span>Failed Logins</span>
                <strong>{risk.failed_logins}</strong>
              </div>

              <div>
                <span>Critical</span>
                <strong>{risk.critical_events}</strong>
              </div>

            </div>

            <div className="risk-window">
              Analysis window: {risk.window_minutes} minutes
            </div>

          </div>

        </section>


        {/* SECURE MESSAGING */}

        <section className="panel messaging-panel">

          <div className="panel-header">

            <div>
              <h3>🔐 Secure Communication</h3>

              <p>
                Post-quantum encrypted messaging using ML-KEM
              </p>
            </div>

            <span className="secure-badge">
              PQC SECURED
            </span>

          </div>


          <div className="messaging-container">

            {/* SEND */}

            <div className="message-compose">

              <h4>Send Secure Message</h4>

              <form onSubmit={sendMessage}>

                <label>Recipient</label>

                <select
                  value={selectedUser}
                  onChange={(e) =>
                    setSelectedUser(e.target.value)
                  }
                >

                  <option value="">
                    Select a user
                  </option>

                  {users.map((user) => (
                    <option
                      key={user.id}
                      value={user.id}
                    >
                      {user.username}
                      {user.pqc_enabled
                        ? " — PQC Enabled"
                        : " — AES Fallback"}
                    </option>
                  ))}

                </select>


                {selectedUser && (
                  <div className="encryption-info">

                    {users.find(
                      (u) => String(u.id) === String(selectedUser)
                    )?.pqc_enabled ? (
                      <>
                        <span>✓</span>
                        ML-KEM post-quantum encryption enabled
                      </>
                    ) : (
                      <>
                        <span>⚠</span>
                        PQC unavailable — AES encryption will be used
                      </>
                    )}

                  </div>
                )}


                <label>Message</label>

                <textarea
                  rows="5"
                  placeholder="Enter your secure message..."
                  value={messageText}
                  onChange={(e) =>
                    setMessageText(e.target.value)
                  }
                ></textarea>


                <button
                  className="send-button"
                  type="submit"
                  disabled={sending}
                >
                  {sending
                    ? "Encrypting..."
                    : "🔐 Encrypt & Send"}
                </button>

              </form>


              {messageStatus && (
                <div
                  className={
                    messageStatus.startsWith("Error")
                      ? "message-status error"
                      : "message-status success"
                  }
                >
                  {messageStatus}
                </div>
              )}

            </div>


            {/* MESSAGE HISTORY */}

            <div className="message-history">

              <div className="history-header">
                <h4>Message History</h4>

                <span>
                  {messages.length} messages
                </span>
              </div>


              {messages.length === 0 ? (

                <div className="empty-messages">
                  <span>🔒</span>

                  <p>
                    No messages yet.
                  </p>

                </div>

              ) : (

                <div className="messages-list">

                  {[...messages]
                    .reverse()
                    .map((message) => {

                      const sent =
                        message.sender_id ===
                        dashboard.user.id;

                      return (
                        <div
                          className={`message-item ${
                            sent ? "sent" : "received"
                          }`}
                          key={message.id}
                        >

                          <div className="message-meta">

                            <strong>
                              {sent
                                ? "You"
                                : `User ${message.sender_id}`}
                            </strong>

                            <span>
                              {message.created_at
                                ? new Date(
                                    message.created_at
                                  ).toLocaleString()
                                : ""}
                            </span>

                          </div>


                          <div className="message-bubble">
                            {message.content}
                          </div>


                          <div className="message-security">
                            🔐 Decrypted securely
                          </div>

                        </div>
                      );
                    })}

                </div>

              )}

            </div>

          </div>

        </section>


        {/* SECURITY ACTIVITY */}

        <section className="panel activity-panel">

          <div className="panel-header">

            <div>
              <h3>Security Activity</h3>
              <p>Event severity distribution</p>
            </div>

          </div>

          <div className="severity-grid">

            <div className="severity-item critical">
              <span>Critical</span>
              <strong>
                {stats.critical_severity_events}
              </strong>
            </div>

            <div className="severity-item high">
              <span>High</span>
              <strong>
                {stats.high_severity_events}
              </strong>
            </div>

            <div className="severity-item medium">
              <span>Medium</span>
              <strong>
                {stats.medium_severity_events}
              </strong>
            </div>

            <div className="severity-item low">
              <span>Low</span>
              <strong>
                {stats.low_severity_events}
              </strong>
            </div>

          </div>

        </section>


        {/* EVENTS */}

        <section className="panel events-panel">

          <div className="panel-header">

            <div>
              <h3>Recent Security Events</h3>

              <p>
                Latest activity detected by QuantumShield
              </p>
            </div>

            <span className="event-count">
              {dashboard.recent_events?.length || 0} events
            </span>

          </div>


          {dashboard.recent_events?.length === 0 ? (

            <div className="empty-state">
              <span>✓</span>
              <h4>No Recent Security Events</h4>
              <p>
                Your account has no recent suspicious activity.
              </p>
            </div>

          ) : (

            <div className="events-list">

              {dashboard.recent_events.map((event) => (

                <div
                  className="event-row"
                  key={event.id}
                >

                  <div className="event-indicator"></div>

                  <div className="event-info">

                    <strong>
                      {event.event_type}
                    </strong>

                    <p>
                      {event.description}
                    </p>

                    <small>
                      {event.created_at
                        ? new Date(
                            event.created_at
                          ).toLocaleString()
                        : "Unknown time"}
                    </small>

                  </div>

                  <span
                    className={`event-badge ${event.severity.toLowerCase()}`}
                  >
                    {event.severity}
                  </span>

                </div>

              ))}

            </div>

          )}

        </section>


        <footer className="footer">
          QuantumShield v1.0.0
          <span>•</span>
          Post-Quantum Secure Communication
          <span>•</span>
          AI Threat Detection
        </footer>

      </main>
    </div>
  );
}

export default App;
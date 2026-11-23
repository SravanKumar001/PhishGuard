import React, { useCallback, useEffect, useState } from "react";

import { apiRequest, downloadFile, jsonBody } from "./api.js";
import "./App.css";

const STATUS_OPTIONS = [
  ["new", "New"],
  ["investigating", "Investigating"],
  ["confirmed_phishing", "Confirmed phishing"],
  ["benign", "Benign"],
  ["needs_review", "Needs review"],
  ["closed", "Closed"],
];

const RISK_LABELS = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

function formatDate(value) {
  return new Date(value).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function ErrorNotice({ children }) {
  if (!children) return null;
  return (
    <div className="notice notice-error" role="alert">
      {children}
    </div>
  );
}

export function App() {
  const [user, setUser] = useState(null);
  const [sessionChecking, setSessionChecking] = useState(true);
  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState({ email: "", password: "" });
  const [authBusy, setAuthBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [stats, setStats] = useState(null);
  const [investigations, setInvestigations] = useState([]);
  const [investigationTotal, setInvestigationTotal] = useState(0);
  const [listOffset, setListOffset] = useState(0);
  const [statusFilter, setStatusFilter] = useState("");
  const [searchDraft, setSearchDraft] = useState("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState({
    findings: [],
    notes: [],
    report: null,
    submissions: [],
  });
  const [preferences, setPreferences] = useState({
    theme: "system",
    compact_mode: false,
  });
  const [activeTab, setActiveTab] = useState("investigations");
  const [showCreate, setShowCreate] = useState(false);
  const [createForm, setCreateForm] = useState({ title: "", description: "" });
  const [analysisForm, setAnalysisForm] = useState({ urls: "", raw_email: "" });
  const [emailFile, setEmailFile] = useState(null);
  const [analysisBusy, setAnalysisBusy] = useState(false);
  const [noteBody, setNoteBody] = useState("");

  const loadOverview = useCallback(async () => {
    const params = new URLSearchParams({ offset: String(listOffset), limit: "50" });
    if (statusFilter) params.set("status", statusFilter);
    if (search.trim()) params.set("q", search.trim());
    const [nextStats, listing] = await Promise.all([
      apiRequest("/api/dashboard/stats"),
      apiRequest(`/api/investigations?${params.toString()}`),
    ]);
    setStats(nextStats);
    setInvestigations(listing.items);
    setInvestigationTotal(listing.total);
  }, [listOffset, search, statusFilter]);

  const loadDetail = useCallback(async (investigationId) => {
    const [findings, notes, submissions] = await Promise.all([
      apiRequest(`/api/investigations/${investigationId}/findings`),
      apiRequest(`/api/investigations/${investigationId}/notes`),
      apiRequest(`/api/investigations/${investigationId}/submissions`),
    ]);
    let report = null;
    if (submissions.length) {
      report = await apiRequest(
        `/api/investigations/${investigationId}/reports/latest`,
      );
    }
    setDetail({ findings, notes, report, submissions });
  }, []);

  useEffect(() => {
    let active = true;
    apiRequest("/api/auth/me")
      .then((currentUser) => {
        if (active) setUser(currentUser);
      })
      .catch((requestError) => {
        if (active && requestError.status !== 401) setError(requestError.message);
      })
      .finally(() => {
        if (active) setSessionChecking(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = preferences.theme;
    document.documentElement.dataset.compact = String(preferences.compact_mode);
  }, [preferences]);

  useEffect(() => {
    if (!user) return;
    let active = true;
    Promise.all([loadOverview(), apiRequest("/api/auth/preferences")])
      .then(([, nextPreferences]) => {
        if (active) setPreferences(nextPreferences);
      })
      .catch((requestError) => {
        if (active) setError(requestError.message);
      });
    return () => {
      active = false;
    };
  }, [user, loadOverview]);

  useEffect(() => {
    if (!user || !selected) {
      setDetail({ findings: [], notes: [], report: null, submissions: [] });
      return;
    }
    let active = true;
    loadDetail(selected.id).catch((requestError) => {
      if (active) setError(requestError.message);
    });
    return () => {
      active = false;
    };
  }, [loadDetail, selected?.id, user]);

  async function submitAuth(event) {
    event.preventDefault();
    setAuthBusy(true);
    setError("");
    try {
      if (authMode === "reset") {
        const result = await apiRequest("/api/auth/password-reset/request", {
          method: "POST",
          body: jsonBody({ email: authForm.email }),
        });
        setNotice(result.detail);
        setAuthMode("login");
        return;
      }
      if (authMode === "register") {
        await apiRequest("/api/auth/register", {
          method: "POST",
          body: jsonBody(authForm),
        });
      }
      const signedIn = await apiRequest("/api/auth/login", {
        method: "POST",
        body: jsonBody(authForm),
      });
      setUser(signedIn);
      setNotice(authMode === "register" ? "Your account is ready." : "Welcome back.");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setAuthBusy(false);
    }
  }

  async function signOut() {
    setError("");
    try {
      await apiRequest("/api/auth/logout", { method: "POST" });
      setUser(null);
      setSelected(null);
      setInvestigations([]);
      setStats(null);
      setNotice("You have been signed out.");
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  async function createInvestigation(event) {
    event.preventDefault();
    setError("");
    try {
      const created = await apiRequest("/api/investigations", {
        method: "POST",
        body: jsonBody(createForm),
      });
      setSelected(created);
      setCreateForm({ title: "", description: "" });
      setShowCreate(false);
      setActiveTab("investigations");
      const alreadyOnFirstPage = listOffset === 0;
      setListOffset(0);
      if (alreadyOnFirstPage) await loadOverview();
      setNotice("Investigation created.");
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  async function updateStatus(nextStatus) {
    if (!selected) return;
    setError("");
    try {
      const updated = await apiRequest(`/api/investigations/${selected.id}`, {
        method: "PATCH",
        body: jsonBody({ status: nextStatus }),
      });
      setSelected(updated);
      await loadOverview();
      setNotice("Investigation status updated.");
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  async function runAnalysis(event) {
    event.preventDefault();
    if (!selected) return;
    const urls = analysisForm.urls
      .split(/\r?\n/)
      .map((url) => url.trim())
      .filter(Boolean);
    const payload = { urls };
    if (analysisForm.raw_email.trim()) payload.raw_email = analysisForm.raw_email;
    if (!urls.length && !payload.raw_email) {
      setError("Enter at least one URL or paste an email message.");
      return;
    }
    setAnalysisBusy(true);
    setError("");
    try {
      await apiRequest(`/api/investigations/${selected.id}/analyze`, {
        method: "POST",
        body: jsonBody(payload),
      });
      setAnalysisForm({ urls: "", raw_email: "" });
      await Promise.all([loadDetail(selected.id), loadOverview()]);
      setNotice("Analysis saved to this investigation.");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setAnalysisBusy(false);
    }
  }

  async function uploadEmail(event) {
    event.preventDefault();
    if (!selected || !emailFile) {
      setError("Choose an .eml file to analyze.");
      return;
    }
    const body = new FormData();
    body.append("file", emailFile);
    const formElement = event.currentTarget;
    setAnalysisBusy(true);
    setError("");
    try {
      await apiRequest(`/api/investigations/${selected.id}/analyze/email/file`, {
        method: "POST",
        body,
      });
      setEmailFile(null);
      formElement.reset();
      await Promise.all([loadDetail(selected.id), loadOverview()]);
      setNotice("Email file analyzed and saved.");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setAnalysisBusy(false);
    }
  }

  async function addNote(event) {
    event.preventDefault();
    if (!selected) return;
    setError("");
    try {
      await apiRequest(`/api/investigations/${selected.id}/notes`, {
        method: "POST",
        body: jsonBody({ body: noteBody }),
      });
      setNoteBody("");
      await loadDetail(selected.id);
      setNotice("Note added.");
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  async function savePreferences(event) {
    event.preventDefault();
    setError("");
    try {
      const saved = await apiRequest("/api/auth/preferences", {
        method: "PUT",
        body: jsonBody(preferences),
      });
      setPreferences(saved);
      setNotice("Preferences saved.");
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  async function downloadLatestReport() {
    if (!selected || !detail.report) return;
    try {
      await downloadFile(
        `/api/investigations/${selected.id}/reports/${detail.report.id}/download`,
        `phishguard-report-${detail.report.id}.json`,
      );
    } catch (requestError) {
      setError(requestError.message);
    }
  }

  if (sessionChecking) {
    return (
      <main className="session-loading">
        <Brand />
        <p>Checking your secure session…</p>
      </main>
    );
  }

  if (!user) {
    return (
      <main className="auth-page">
        <section className="auth-aside">
          <Brand />
          <div className="auth-message">
            <span className="eyebrow">LOCAL-FIRST THREAT TRIAGE</span>
            <h1>Make the evidence clearer.</h1>
            <p>
              Investigate suspicious messages and URLs with explainable evidence.
              Your submitted content stays within this service.
            </p>
            <div className="auth-promise">
              <span className="promise-icon">✓</span>
              <span>No links opened. No attachments executed.</span>
            </div>
          </div>
          <p className="auth-footnote">Private investigations · Offline analysis rules</p>
        </section>
        <section className="auth-form-wrap">
          <div className="auth-form-card">
            <span className="eyebrow">
              {authMode === "login" ? "WELCOME BACK" : authMode === "reset" ? "ACCOUNT RECOVERY" : "GET STARTED"}
            </span>
            <h2>
              {authMode === "login"
                ? "Sign in to PhishGuard"
                : authMode === "reset"
                  ? "Reset your password"
                  : "Create your account"}
            </h2>
            <p className="muted">
              {authMode === "login"
                ? "Access your investigations and saved evidence."
                : authMode === "reset"
                  ? "Request a password reset for your account."
                  : "Start organizing suspicious email and URL evidence."}
            </p>
            <ErrorNotice>{error}</ErrorNotice>
            <form onSubmit={submitAuth} className="stack-form">
              <label>
                Email address
                <input
                  type="email"
                  autoComplete="email"
                  value={authForm.email}
                  onChange={(event) =>
                    setAuthForm({ ...authForm, email: event.target.value })
                  }
                  required
                />
              </label>
              {authMode !== "reset" && (
                <label>
                  Password
                  <input
                    type="password"
                    autoComplete={authMode === "login" ? "current-password" : "new-password"}
                    minLength={10}
                    value={authForm.password}
                    onChange={(event) =>
                      setAuthForm({ ...authForm, password: event.target.value })
                    }
                    required
                  />
                  {authMode === "register" && (
                    <small>Use at least 10 characters.</small>
                  )}
                </label>
              )}
              <button className="button button-primary button-wide" disabled={authBusy}>
                {authBusy
                  ? "Please wait…"
                  : authMode === "login"
                    ? "Sign in"
                    : authMode === "reset"
                      ? "Send reset instructions"
                      : "Create account"}
              </button>
            </form>
            <button
              className="text-button auth-switch"
              onClick={() => {
                setAuthMode(authMode === "login" ? "register" : "login");
                setError("");
              }}
            >
              {authMode === "login"
                ? "New to PhishGuard? Create an account"
                : "Already have an account? Sign in"}
            </button>
            {authMode === "login" && (
              <button
                className="text-button auth-switch"
                onClick={() => {
                  setAuthMode("reset");
                  setError("");
                }}
              >
                Forgot your password?
              </button>
            )}
          </div>
        </section>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Brand />
        <div className="workspace-label">WORKSPACE</div>
        <nav className="side-nav" aria-label="Main navigation">
          <button
            className={activeTab === "investigations" ? "nav-item active" : "nav-item"}
            onClick={() => setActiveTab("investigations")}
          >
            <span className="nav-icon">⌕</span>
            Investigations
            <span className="nav-count">{stats?.investigation_count ?? 0}</span>
          </button>
          <button
            className={activeTab === "settings" ? "nav-item active" : "nav-item"}
            onClick={() => setActiveTab("settings")}
          >
            <span className="nav-icon">⚙</span>
            Preferences
          </button>
        </nav>
        <div className="sidebar-bottom">
          <div className="offline-indicator"><span /> Offline rules active</div>
          <div className="user-card">
            <div className="avatar">{user.email.slice(0, 1).toUpperCase()}</div>
            <div className="user-meta">
              <strong>{user.email}</strong>
              <span>Analyst account</span>
            </div>
            <button className="icon-button" title="Sign out" onClick={signOut}>↗</button>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <span className="eyebrow">PHISHING INVESTIGATION WORKSPACE</span>
            <h1>{activeTab === "settings" ? "Preferences" : "Investigations"}</h1>
          </div>
          {activeTab === "investigations" && (
            <button className="button button-primary" onClick={() => setShowCreate(!showCreate)}>
              <span aria-hidden="true">＋</span> New investigation
            </button>
          )}
        </header>

        <div className="content-area">
          {error && <ErrorNotice>{error}</ErrorNotice>}
          {notice && (
            <div className="notice notice-success" role="status">
              <span>{notice}</span>
              <button className="icon-button" onClick={() => setNotice("")} aria-label="Dismiss">
                ×
              </button>
            </div>
          )}

          {activeTab === "settings" ? (
            <section className="panel settings-panel">
              <div className="panel-heading">
                <div>
                  <h2>Appearance</h2>
                  <p className="muted">Choose how PhishGuard looks on this device.</p>
                </div>
              </div>
              <div className="verification-row">
                <span>
                  <strong>Email verification</strong>
                  <small>
                    {user.email_verified
                      ? "Your email address is verified."
                      : "Your email address has not been verified."}
                  </small>
                </span>
                {!user.email_verified && (
                  <button
                    type="button"
                    className="button button-secondary"
                    onClick={async () => {
                      setError("");
                      try {
                        const result = await apiRequest("/api/auth/email-verification/request", {
                          method: "POST",
                        });
                        setNotice(result.detail);
                      } catch (requestError) {
                        setError(requestError.message);
                      }
                    }}
                  >
                    Send verification email
                  </button>
                )}
              </div>
              <form className="stack-form settings-form" onSubmit={savePreferences}>
                <label>
                  Color theme
                  <select
                    value={preferences.theme}
                    onChange={(event) =>
                      setPreferences({ ...preferences, theme: event.target.value })
                    }
                  >
                    <option value="system">System default</option>
                    <option value="light">Light</option>
                    <option value="dark">Dark</option>
                  </select>
                </label>
                <label className="toggle-row">
                  <span>
                    <strong>Compact layout</strong>
                    <small>Reduce spacing in lists and evidence cards.</small>
                  </span>
                  <input
                    type="checkbox"
                    checked={preferences.compact_mode}
                    onChange={(event) =>
                      setPreferences({ ...preferences, compact_mode: event.target.checked })
                    }
                  />
                </label>
                <button className="button button-primary">Save preferences</button>
              </form>
            </section>
          ) : (
            <>
              <section className="stats-grid" aria-label="Investigation summary">
                <StatCard label="Total investigations" value={stats?.investigation_count ?? "—"} icon="▤" />
                <StatCard label="Needs review" value={stats?.investigations_by_status?.needs_review ?? 0} icon="◷" />
                <StatCard label="Confirmed phishing" value={stats?.investigations_by_status?.confirmed_phishing ?? 0} icon="⚑" />
                <StatCard label="Critical findings" value={stats?.findings_by_severity?.critical ?? 0} icon="!" emphasis />
              </section>

              {showCreate && (
                <section className="panel create-panel">
                  <div className="panel-heading">
                    <div>
                      <span className="eyebrow">CASE SETUP</span>
                      <h2>Create investigation</h2>
                    </div>
                    <button className="icon-button" onClick={() => setShowCreate(false)} aria-label="Close">
                      ×
                    </button>
                  </div>
                  <form className="create-form" onSubmit={createInvestigation}>
                    <label>
                      Investigation title
                      <input
                        value={createForm.title}
                        onChange={(event) =>
                          setCreateForm({ ...createForm, title: event.target.value })
                        }
                        maxLength={160}
                        required
                        placeholder="e.g. Invoice request from unknown sender"
                      />
                    </label>
                    <label>
                      Context <span className="optional-label">Optional</span>
                      <textarea
                        value={createForm.description}
                        onChange={(event) =>
                          setCreateForm({ ...createForm, description: event.target.value })
                        }
                        maxLength={10000}
                        rows={2}
                        placeholder="Add a short note about this case"
                      />
                    </label>
                    <button className="button button-primary">Create case</button>
                  </form>
                </section>
              )}

              <div className="work-grid">
                <section className="panel investigation-panel">
                  <div className="panel-heading list-heading">
                    <div>
                      <h2>Case queue</h2>
                      <p className="muted">{investigations.length} shown · up to 50 per view</p>
                    </div>
                    <span className="panel-count">{stats?.investigation_count ?? 0}</span>
                  </div>
                  <form
                    className="filter-row"
                    onSubmit={(event) => {
                      event.preventDefault();
                      setSearch(searchDraft);
                      setListOffset(0);
                    }}
                  >
                    <label className="search-field">
                      <span aria-hidden="true">⌕</span>
                      <input
                        aria-label="Search investigations"
                        placeholder="Search cases"
                        value={searchDraft}
                        onChange={(event) => setSearchDraft(event.target.value)}
                      />
                    </label>
                    <select
                      aria-label="Filter by status"
                      value={statusFilter}
                      onChange={(event) => {
                        setStatusFilter(event.target.value);
                        setListOffset(0);
                      }}
                    >
                      <option value="">All statuses</option>
                      {STATUS_OPTIONS.map(([value, label]) => (
                        <option key={value} value={value}>{label}</option>
                      ))}
                    </select>
                    <button className="button button-secondary">Filter</button>
                  </form>
                  <div className="case-list">
                    {investigations.length ? investigations.map((item) => (
                      <button
                        className={selected?.id === item.id ? "case-row selected" : "case-row"}
                        key={item.id}
                        onClick={() => {
                          setSelected(item);
                          setError("");
                        }}
                      >
                        <span className="case-marker" />
                        <span className="case-info">
                          <strong>{item.title}</strong>
                          <small>{formatDate(item.updated_at)}</small>
                        </span>
                        <span className={`status-pill status-${item.status}`}>
                          {statusLabel(item.status)}
                        </span>
                      </button>
                    )) : (
                      <div className="empty-state">
                        <span className="empty-icon">⌕</span>
                        <strong>No investigations found</strong>
                        <p>Create a case to start collecting evidence.</p>
                      </div>
                    )}
                  </div>
                  {investigationTotal > 50 && (
                    <div className="pagination">
                      <span>
                        {listOffset + 1}–{Math.min(listOffset + investigations.length, investigationTotal)} of {investigationTotal}
                      </span>
                      <div>
                        <button
                          className="button button-secondary"
                          disabled={listOffset === 0}
                          onClick={() => setListOffset(Math.max(0, listOffset - 50))}
                        >
                          Previous
                        </button>
                        <button
                          className="button button-secondary"
                          disabled={listOffset + 50 >= investigationTotal}
                          onClick={() => setListOffset(listOffset + 50)}
                        >
                          Next
                        </button>
                      </div>
                    </div>
                  )}
                </section>

                <section className="case-detail">
                  {!selected ? (
                    <div className="panel detail-empty">
                      <div className="empty-icon">✳</div>
                      <h2>Select a case to investigate</h2>
                      <p className="muted">Or create a new investigation to analyze URLs and email evidence.</p>
                      <button className="button button-primary" onClick={() => setShowCreate(true)}>
                        Create investigation
                      </button>
                    </div>
                  ) : (
                    <>
                      <section className="panel detail-header">
                        <div className="detail-title">
                          <span className="eyebrow">INVESTIGATION</span>
                          <h2>{selected.title}</h2>
                          <p className="muted">
                            Created {formatDate(selected.created_at)}
                          </p>
                        </div>
                        <label className="status-select">
                          <span>Case status</span>
                          <select
                            value={selected.status}
                            onChange={(event) => updateStatus(event.target.value)}
                          >
                            {STATUS_OPTIONS.map(([value, label]) => (
                              <option key={value} value={value}>{label}</option>
                            ))}
                          </select>
                        </label>
                      </section>

                      <section className="panel analysis-panel">
                        <div className="panel-heading">
                          <div>
                            <span className="eyebrow">LOCAL ANALYSIS</span>
                            <h2>Add evidence</h2>
                            <p className="muted">URLs are never opened; pasted messages and uploads are processed locally.</p>
                          </div>
                        </div>
                        <form className="stack-form" onSubmit={runAnalysis}>
                          <label>
                            URLs <span className="optional-label">One per line · up to 50</span>
                            <textarea
                              value={analysisForm.urls}
                              onChange={(event) =>
                                setAnalysisForm({ ...analysisForm, urls: event.target.value })
                              }
                              rows={3}
                              placeholder={"https://example.com/account\nhttp://192.0.2.10/login"}
                            />
                          </label>
                          <label>
                            Paste email message <span className="optional-label">Optional · RFC 5322</span>
                            <textarea
                              value={analysisForm.raw_email}
                              onChange={(event) =>
                                setAnalysisForm({ ...analysisForm, raw_email: event.target.value })
                              }
                              rows={5}
                              placeholder={"From: sender@example.com\nSubject: Message subject\n\nPaste the message body"}
                            />
                          </label>
                          <div className="analysis-actions">
                            <button className="button button-primary" disabled={analysisBusy}>
                              {analysisBusy ? "Analyzing…" : "Analyze and save"}
                            </button>
                            <span className="muted">Risk points are triage signals, not probabilities.</span>
                          </div>
                        </form>
                        <div className="upload-divider"><span>OR UPLOAD AN EMAIL</span></div>
                        <form className="upload-row" onSubmit={uploadEmail}>
                          <input
                            type="file"
                            accept=".eml,message/rfc822"
                            aria-label="Choose .eml file"
                            onChange={(event) => setEmailFile(event.target.files?.[0] ?? null)}
                          />
                          <button className="button button-secondary" disabled={analysisBusy || !emailFile}>
                            Analyze .eml file
                          </button>
                        </form>
                      </section>

                      <section className="panel evidence-panel">
                        <div className="panel-heading">
                          <div>
                            <span className="eyebrow">EVIDENCE</span>
                            <h2>Findings <span className="heading-count">{detail.findings.length}</span></h2>
                          </div>
                          {detail.report && (
                            <div className="report-actions">
                              <button className="button button-secondary" onClick={downloadLatestReport}>
                                Download JSON
                              </button>
                              <button
                                className="button button-secondary"
                                onClick={async () => {
                                  try {
                                    await downloadFile(
                                      `/api/investigations/${selected.id}/reports/${detail.report.id}/download.pdf`,
                                      `phishguard-report-${detail.report.id}.pdf`,
                                    );
                                  } catch (requestError) {
                                    setError(requestError.message);
                                  }
                                }}
                              >
                                Download PDF
                              </button>
                            </div>
                          )}
                        </div>
                        {detail.findings.length ? (
                          <div className="finding-list">
                            {detail.findings.map((finding) => (
                              <article className="finding-card" key={finding.id}>
                                <span className={`severity-dot severity-${finding.severity}`} />
                                <div className="finding-copy">
                                  <div className="finding-title-row">
                                    <h3>{finding.title}</h3>
                                    <span className={`severity-label severity-text-${finding.severity}`}>
                                      {RISK_LABELS[finding.severity]}
                                    </span>
                                  </div>
                                  <p>{finding.explanation}</p>
                                  <small>{finding.rule_id} · {finding.evidence?.evidence_references?.length ?? 0} evidence references</small>
                                </div>
                              </article>
                            ))}
                          </div>
                        ) : (
                          <div className="inline-empty">
                            <span>◎</span>
                            <div>
                              <strong>No findings saved yet</strong>
                              <p>Analyze a URL or email to collect explainable findings.</p>
                            </div>
                          </div>
                        )}
                        <div className="evidence-meta">
                          <span>{detail.submissions.length} submissions</span>
                          <span>{detail.report ? `Latest report · ${formatDate(detail.report.created_at)}` : "No report generated"}</span>
                        </div>
                      </section>

                      <section className="panel notes-panel">
                        <div className="panel-heading">
                          <div>
                            <span className="eyebrow">CASE JOURNAL</span>
                            <h2>Investigation notes</h2>
                          </div>
                        </div>
                        <form className="note-form" onSubmit={addNote}>
                          <textarea
                            aria-label="New investigation note"
                            value={noteBody}
                            onChange={(event) => setNoteBody(event.target.value)}
                            rows={2}
                            maxLength={5000}
                            placeholder="Record context, verification steps, or next actions"
                          />
                          <button className="button button-secondary" disabled={!noteBody.trim()}>
                            Add note
                          </button>
                        </form>
                        <div className="note-list">
                          {detail.notes.map((note) => (
                            <article className="note-item" key={note.id}>
                              <p>{note.body}</p>
                              <time>{formatDate(note.created_at)}</time>
                            </article>
                          ))}
                          {!detail.notes.length && <p className="muted note-empty">No notes have been added to this case.</p>}
                        </div>
                      </section>
                    </>
                  )}
                </section>
              </div>
            </>
          )}
        </div>
      </main>
    </div>
  );
}

function Brand() {
  return (
    <div className="brand-lockup" aria-label="PhishGuard">
      <div className="brand-mark" aria-hidden="true">P</div>
      <span>phish<span>guard</span></span>
    </div>
  );
}

function StatCard({ label, value, icon, emphasis = false }) {
  return (
    <article className={emphasis ? "stat-card stat-emphasis" : "stat-card"}>
      <span className="stat-icon">{icon}</span>
      <div>
        <span className="stat-label">{label}</span>
        <strong>{value}</strong>
      </div>
      <span className="stat-accent" />
    </article>
  );
}

function statusLabel(status) {
  return STATUS_OPTIONS.find(([value]) => value === status)?.[1] ?? status;
}

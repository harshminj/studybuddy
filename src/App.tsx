import { useState, useEffect, useRef, useCallback } from "react";

const API = "https://studybuddyy-bfop.onrender.com/api";

const EMAILJS_SERVICE  = "service_a77q18z";
const EMAILJS_TEMPLATE = "template_k2zpwrj";
const EMAILJS_KEY      = "VuMsqcmyX4NX7oHvi";

const getToken       = ()    => localStorage.getItem("sb_token");
const setToken       = (t)   => localStorage.setItem("sb_token", t);
const clearToken     = ()    => localStorage.removeItem("sb_token");
const getStoredUser  = ()    => { try { return JSON.parse(localStorage.getItem("sb_user")); } catch { return null; } };
const setStoredUser  = (u)   => localStorage.setItem("sb_user", JSON.stringify(u));
const clearStoredUser = ()   => localStorage.removeItem("sb_user");

async function apiFetch(path, options = {}) {
  const token = getToken();
  try {
    const res = await fetch(`${API}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(options.headers || {}),
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Something went wrong");
    return data;
  } catch (err) {
    if (err.message === "Failed to fetch" || err.message === "Load failed") {
      throw new Error("Server is waking up... Please wait 30 seconds and try again!");
    }
    throw err;
  }
}

const style = `
  @import url('https://fonts.googleapis.com/css2?family=Clash+Display:wght@400;500;600;700&family=DM+Sans:ital,wght@0,300;0,400;0,500;1,300&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --ink: #0d0d0d; --paper: #f5f0e8; --cream: #ede8dc;
    --accent: #e8500a; --accent2: #2563eb; --muted: #8a8070;
    --card: #ffffff; --border: #d4cfc5; --green: #16a34a; --red: #dc2626;
    --shadow: 0 2px 16px rgba(13,13,13,0.10); --shadow-lg: 0 8px 40px rgba(13,13,13,0.18);
  }
  body { font-family: 'DM Sans', sans-serif; background: var(--paper); color: var(--ink); min-height: 100vh; }
  h1,h2,h3,h4,h5 { font-family: 'Clash Display', sans-serif; }
  .app { min-height: 100vh; display: flex; flex-direction: column; }
  .nav { background: var(--ink); color: var(--paper); padding: 0 2rem; height: 60px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; }
  .nav-logo { font-family: 'Clash Display', sans-serif; font-size: 1.4rem; font-weight: 700; letter-spacing: -0.5px; }
  .nav-logo span { color: var(--accent); }
  .nav-tabs { display: flex; gap: 0.25rem; }
  .nav-tab { padding: 0.4rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.85rem; font-weight: 500; color: #bbb; border: none; background: transparent; transition: all 0.15s; }
  .nav-tab:hover { color: var(--paper); background: rgba(255,255,255,0.08); }
  .nav-tab.active { background: var(--accent); color: #fff; }
  .nav-user { display: flex; align-items: center; gap: 0.75rem; }
  .avatar { width: 34px; height: 34px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.85rem; color: #fff; cursor: pointer; }
  .logout-btn { background: rgba(255,255,255,0.1); border: none; color: #bbb; padding: 0.35rem 0.8rem; border-radius: 6px; cursor: pointer; font-size: 0.8rem; }
  .logout-btn:hover { background: rgba(255,255,255,0.2); color: #fff; }
  .auth-wrapper { flex: 1; display: flex; align-items: center; justify-content: center; padding: 2rem; min-height: 100vh; background: linear-gradient(135deg, #0d0d0d 0%, #1a1a2e 50%, #0d0d0d 100%); }
  .auth-card { background: var(--card); border-radius: 20px; padding: 2.5rem; width: 100%; max-width: 420px; box-shadow: var(--shadow-lg); }
  .auth-logo { text-align: center; margin-bottom: 1.5rem; }
  .auth-logo h1 { font-size: 2rem; }
  .auth-logo h1 span { color: var(--accent); }
  .auth-logo p { color: var(--muted); font-size: 0.9rem; margin-top: 0.3rem; }
  .auth-tabs { display: flex; background: var(--cream); border-radius: 10px; padding: 4px; margin-bottom: 1.5rem; }
  .auth-tab { flex: 1; padding: 0.5rem; text-align: center; border-radius: 7px; cursor: pointer; font-weight: 500; font-size: 0.9rem; transition: all 0.15s; }
  .auth-tab.active { background: var(--ink); color: #fff; }
  .form-group { margin-bottom: 1rem; }
  .form-group label { display: block; font-size: 0.82rem; font-weight: 500; color: var(--muted); margin-bottom: 0.35rem; text-transform: uppercase; letter-spacing: 0.5px; }
  .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 0.7rem 0.9rem; border: 1.5px solid var(--border); border-radius: 10px; font-family: 'DM Sans', sans-serif; font-size: 0.95rem; background: var(--cream); color: var(--ink); transition: border 0.15s; outline: none; }
  .form-group input:focus, .form-group select:focus { border-color: var(--accent2); background: #fff; }
  .btn { width: 100%; padding: 0.8rem; border-radius: 10px; border: none; font-family: 'Clash Display', sans-serif; font-size: 1rem; font-weight: 600; cursor: pointer; transition: all 0.15s; letter-spacing: 0.3px; }
  .btn:disabled { opacity: 0.6; cursor: not-allowed; }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-primary:hover:not(:disabled) { background: #c43f08; transform: translateY(-1px); box-shadow: 0 4px 16px rgba(232,80,10,0.3); }
  .btn-outline { background: transparent; border: 1.5px solid var(--border); color: var(--ink); }
  .btn-sm { width: auto; padding: 0.45rem 1rem; font-size: 0.85rem; }
  .auth-switch { text-align: center; margin-top: 1rem; font-size: 0.88rem; color: var(--muted); }
  .auth-switch a { color: var(--accent); cursor: pointer; font-weight: 500; }
  .step-indicator { display: flex; gap: 0.4rem; justify-content: center; margin-bottom: 1.5rem; }
  .step-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--border); transition: all 0.2s; }
  .step-dot.active { background: var(--accent); width: 24px; border-radius: 4px; }
  .err-msg { background: rgba(220,38,38,0.08); border: 1px solid rgba(220,38,38,0.2); color: var(--red); border-radius: 8px; padding: 0.6rem 0.9rem; font-size: 0.85rem; margin-bottom: 1rem; }
  .main { flex: 1; padding: 1.5rem 2rem; max-width: 1200px; margin: 0 auto; width: 100%; }
  .page-title { font-size: 1.6rem; font-weight: 700; margin-bottom: 0.3rem; }
  .page-sub { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
  .card { background: var(--card); border-radius: 16px; padding: 1.5rem; box-shadow: var(--shadow); border: 1px solid var(--border); }
  .loading { display: flex; align-items: center; justify-content: center; padding: 3rem; color: var(--muted); gap: 0.5rem; font-size: 0.9rem; }
  .spinner { width: 20px; height: 20px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.7s linear infinite; flex-shrink:0; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .discover-wrapper { display: flex; gap: 1.5rem; }
  .discover-filters { width: 240px; flex-shrink: 0; }
  .discover-cards { flex: 1; }
  .filter-section { margin-bottom: 1.2rem; }
  .filter-label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600; color: var(--muted); margin-bottom: 0.6rem; }
  .filter-chip { display: inline-flex; align-items: center; gap: 0.3rem; padding: 0.3rem 0.8rem; border-radius: 20px; border: 1.5px solid var(--border); font-size: 0.82rem; cursor: pointer; margin: 0.2rem; transition: all 0.15s; background: var(--cream); }
  .filter-chip.active { border-color: var(--accent); background: rgba(232,80,10,0.08); color: var(--accent); font-weight: 600; }
  .profile-card { background: var(--card); border-radius: 20px; overflow: hidden; box-shadow: var(--shadow-lg); border: 1px solid var(--border); transition: transform 0.2s, box-shadow 0.2s; }
  .profile-card:hover { transform: translateY(-3px); box-shadow: 0 12px 40px rgba(13,13,13,0.15); }
  .profile-card-banner { height: 100px; }
  .profile-card-avatar { width: 56px; height: 56px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; font-family: 'Clash Display', sans-serif; font-size: 1.3rem; font-weight: 700; color: #fff; border: 3px solid var(--card); margin-top: -28px; flex-shrink: 0; }
  .profile-card-body { padding: 0.3rem 1rem 1rem; }
  .profile-card-name { font-size: 1.05rem; font-weight: 700; margin-bottom: 0.1rem; }
  .profile-card-college { font-size: 0.82rem; color: var(--muted); margin-bottom: 0.6rem; }
  .tag { display: inline-flex; align-items: center; padding: 0.2rem 0.65rem; border-radius: 20px; font-size: 0.75rem; font-weight: 600; margin: 0.15rem; }
  .tag-style { background: rgba(37,99,235,0.1); color: var(--accent2); }
  .tag-subject { background: rgba(22,163,74,0.1); color: var(--green); }
  .card-actions { display: flex; gap: 0.6rem; margin-top: 0.8rem; }
  .btn-like { flex: 1; background: var(--accent); color: #fff; border: none; border-radius: 10px; padding: 0.55rem; font-weight: 700; cursor: pointer; transition: all 0.15s; font-size: 0.9rem; }
  .btn-like:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-pass { flex: 1; background: var(--cream); color: var(--muted); border: 1.5px solid var(--border); border-radius: 10px; padding: 0.55rem; font-weight: 600; cursor: pointer; font-size: 0.9rem; }
  .cards-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 1rem; }
  .match-row { display: flex; align-items: center; gap: 1rem; padding: 1rem; border-radius: 14px; cursor: pointer; transition: background 0.15s; border: 1px solid var(--border); margin-bottom: 0.6rem; background: var(--card); }
  .match-row:hover { background: var(--cream); }
  .match-row.active { background: rgba(37,99,235,0.07); border-color: var(--accent2); }
  .match-avatar { width: 46px; height: 46px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 1rem; color: #fff; flex-shrink: 0; }
  .match-info { flex: 1; min-width: 0; }
  .match-name { font-weight: 600; font-size: 0.95rem; }
  .match-preview { font-size: 0.82rem; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .unread-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); flex-shrink: 0; }
  .chat-layout { display: flex; height: calc(100vh - 130px); gap: 1rem; }
  .chat-sidebar { width: 300px; flex-shrink: 0; overflow-y: auto; }
  .chat-main { flex: 1; display: flex; flex-direction: column; background: var(--card); border-radius: 16px; border: 1px solid var(--border); overflow: hidden; }
  .chat-header { padding: 1rem 1.2rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 0.8rem; }
  .chat-messages { flex: 1; overflow-y: auto; padding: 1rem; display: flex; flex-direction: column; gap: 0.6rem; }
  .msg { max-width: 70%; }
  .msg.me { align-self: flex-end; }
  .msg.them { align-self: flex-start; }
  .msg-bubble { padding: 0.6rem 0.9rem; border-radius: 14px; font-size: 0.9rem; line-height: 1.45; }
  .msg.me .msg-bubble { background: var(--accent2); color: #fff; border-bottom-right-radius: 4px; }
  .msg.them .msg-bubble { background: var(--cream); color: var(--ink); border-bottom-left-radius: 4px; border: 1px solid var(--border); }
  .msg-time { font-size: 0.7rem; color: var(--muted); margin-top: 0.2rem; text-align: right; }
  .chat-input-row { padding: 0.8rem 1rem; border-top: 1px solid var(--border); display: flex; gap: 0.6rem; }
  .chat-input { flex: 1; border: 1.5px solid var(--border); border-radius: 10px; padding: 0.6rem 0.9rem; font-family: 'DM Sans', sans-serif; font-size: 0.9rem; background: var(--cream); outline: none; }
  .chat-input:focus { border-color: var(--accent2); background: #fff; }
  .chat-send { background: var(--accent2); color: #fff; border: none; border-radius: 10px; padding: 0.6rem 1rem; cursor: pointer; font-weight: 600; font-size: 0.9rem; }
  .chat-empty { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; color: var(--muted); gap: 0.5rem; }
  .profile-hero { background: var(--ink); color: var(--paper); border-radius: 20px; padding: 2rem; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 1.5rem; }
  .profile-hero-avatar { width: 80px; height: 80px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; font-family: 'Clash Display', sans-serif; font-size: 2rem; font-weight: 700; color: #fff; flex-shrink: 0; }
  .profile-hero-info h2 { font-size: 1.5rem; margin-bottom: 0.2rem; }
  .profile-hero-info p { color: #aaa; font-size: 0.9rem; }
  .style-options { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-top: 0.4rem; }
  .style-opt { padding: 0.45rem 1rem; border-radius: 20px; border: 1.5px solid var(--border); cursor: pointer; font-size: 0.85rem; transition: all 0.15s; background: var(--cream); }
  .style-opt.selected { background: var(--accent2); border-color: var(--accent2); color: #fff; font-weight: 600; }
  .timer-circle { width: 200px; height: 200px; border-radius: 50%; margin: 1.5rem auto; background: conic-gradient(var(--accent) calc(var(--prog, 100) * 1%), var(--cream) 0); display: flex; align-items: center; justify-content: center; font-family: 'Clash Display', sans-serif; font-size: 2.8rem; font-weight: 700; box-shadow: 0 0 0 12px var(--cream), 0 0 0 14px var(--border); }
  .timer-controls { display: flex; gap: 0.6rem; justify-content: center; margin-top: 1rem; }
  .timer-btn { padding: 0.55rem 1.4rem; border-radius: 10px; border: none; font-weight: 700; cursor: pointer; font-family: 'Clash Display', sans-serif; font-size: 0.95rem; }
  .goals-list { list-style: none; }
  .goals-list li { display: flex; align-items: center; gap: 0.6rem; padding: 0.5rem 0; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
  .goals-list li.done { text-decoration: line-through; color: var(--muted); }
  .goals-list li input[type=checkbox] { accent-color: var(--accent2); width: 16px; height: 16px; cursor: pointer; }
  .goal-input-row { display: flex; gap: 0.5rem; margin-top: 0.8rem; }
  .goal-input { flex: 1; border: 1.5px solid var(--border); border-radius: 8px; padding: 0.5rem 0.8rem; font-family: 'DM Sans', sans-serif; font-size: 0.9rem; outline: none; background: var(--cream); }
  .star { font-size: 1.6rem; cursor: pointer; transition: transform 0.1s; }
  .star:hover { transform: scale(1.2); }
  .rating-row { display: flex; align-items: center; justify-content: space-between; padding: 0.6rem 0; border-bottom: 1px solid var(--border); }
  .stat-card { background: var(--card); border-radius: 14px; padding: 1.2rem 1.5rem; border: 1px solid var(--border); }
  .stat-num { font-family: 'Clash Display', sans-serif; font-size: 2rem; font-weight: 700; }
  .stat-label { color: var(--muted); font-size: 0.85rem; margin-top: 0.1rem; }
  .table { width: 100%; border-collapse: collapse; }
  .table th { text-align: left; padding: 0.6rem 1rem; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.6px; color: var(--muted); border-bottom: 2px solid var(--border); }
  .table td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--cream); font-size: 0.9rem; }
  .table tr:hover td { background: var(--cream); }
  .badge { display: inline-flex; padding: 0.2rem 0.6rem; border-radius: 20px; font-size: 0.75rem; font-weight: 700; }
  .badge-active { background: rgba(22,163,74,0.1); color: var(--green); }
  .badge-admin  { background: rgba(232,80,10,0.1); color: var(--accent); }
  .toast { position: fixed; bottom: 1.5rem; right: 1.5rem; z-index: 9999; background: var(--ink); color: var(--paper); padding: 0.75rem 1.25rem; border-radius: 12px; font-size: 0.9rem; font-weight: 500; box-shadow: var(--shadow-lg); animation: slideup 0.3s ease; max-width: 320px; }
  .toast.success { border-left: 4px solid var(--green); }
  .toast.match   { border-left: 4px solid var(--accent); }
  .toast.error   { border-left: 4px solid var(--red); }
  @keyframes slideup { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
  .otp-input { width: 100%; text-align: center; font-size: 2.2rem; font-weight: 700; letter-spacing: 0.8rem; padding: 0.9rem 1rem; border: 2.5px solid var(--accent); border-radius: 14px; background: var(--cream); outline: none; font-family: 'Clash Display', sans-serif; }
  @media (max-width: 768px) {
    .discover-wrapper { flex-direction: column; }
    .discover-filters { width: 100%; }
    .chat-layout { flex-direction: column; height: auto; }
    .chat-sidebar { width: 100%; }
    .grid-2 { grid-template-columns: 1fr; }
    .main { padding: 1rem; }
    .nav-tabs { display: none; }
  }
`;

const STUDY_STYLES  = ["Quiet","Collaborative","Exam Prep","Group Discussion","Online Only"];
const SUBJECTS_LIST = ["Machine Learning","Data Structures","Algorithms","Web Dev","React","Statistics","Calculus","Linear Algebra","Networks","Operating Systems","Python","Physics","Chemistry","Database","Cloud Computing"];
const COLORS        = ["#e8500a","#2563eb","#16a34a","#7c3aed","#db2777","#d97706"];
const userColor     = (id) => COLORS[(id || 0) % COLORS.length];
const getInitials   = (name) => (name || "?").split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase();
const fmtTime       = (ts)  => new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

function Toast({ msg, type, onClose }) {
  useEffect(() => { const t = setTimeout(onClose, 3500); return () => clearTimeout(t); }, []);
  return <div className={`toast ${type}`}>{msg}</div>;
}

function Auth({ onLogin }) {
  const [tab,        setTab]        = useState("login");
  const [step,       setStep]       = useState(1);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState("");
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPass,  setLoginPass]  = useState("");
  const [email,      setEmail]      = useState("");
  const [password,   setPassword]   = useState("");
  const [otpValue,   setOtpValue]   = useState("");
  const [name,       setName]       = useState("");
  const [college,    setCollege]    = useState("");
  const [location,   setLocation]   = useState("");
  const [subjects,   setSubjects]   = useState([]);
  const [studyStyle, setStudyStyle] = useState("");
  const [otpData,    setOtpData]    = useState(null);

  const toggleSubject = (s) => setSubjects(p => p.includes(s) ? p.filter(x => x !== s) : [...p, s]);

  const doLogin = async () => {
    setError(""); setLoading(true);
    try {
      const data = await apiFetch("/auth/login", { method: "POST", body: { email: loginEmail, password: loginPass } });
      setToken(data.token); setStoredUser(data.user); onLogin(data.user);
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const doSendOtp = async () => {
    setError(""); setLoading(true);
    try {
      const data = await apiFetch("/auth/send-otp", { method: "POST", body: { email } });
      setOtpData(data);
      // Send via EmailJS
      try {
        await fetch("https://api.emailjs.com/api/v1.0/email/send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            service_id: EMAILJS_SERVICE,
            template_id: EMAILJS_TEMPLATE,
            user_id: EMAILJS_KEY,
            template_params: { to_email: email, otp: String(data.otp) }
          })
        });
      } catch (emailErr) { console.log("EmailJS:", emailErr); }
      setStep(2);
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const doVerifyOtp = async () => {
    setError(""); setLoading(true);
    try {
      const data = await apiFetch("/auth/verify-otp", { method: "POST", body: { email, otp: otpValue } });
      setToken(data.token);
      setStep(3);
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const doSignup = async () => {
    setError(""); setLoading(true);
    try {
      const data = await apiFetch("/auth/signup", {
        method: "POST",
        body: { password, name, college, subjects, style: studyStyle, location }
      });
      setToken(data.token); setStoredUser(data.user); onLogin(data.user);
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const switchTab = (t) => { setTab(t); setStep(1); setError(""); };

  return (
    <div className="auth-wrapper">
      <div className="auth-card">
        <div className="auth-logo">
          <h1>Study<span>Buddy</span></h1>
          <p>Find your perfect study partner</p>
        </div>
        <div className="auth-tabs">
          <div className={`auth-tab ${tab === "login"  ? "active" : ""}`} onClick={() => switchTab("login")}>Login</div>
          <div className={`auth-tab ${tab === "signup" ? "active" : ""}`} onClick={() => switchTab("signup")}>Sign Up</div>
        </div>

        {error && <div className="err-msg">⚠ {error}</div>}

        {tab === "login" && (
          <>
            <div className="form-group"><label>Email</label><input type="email" placeholder="you@college.edu" value={loginEmail} onChange={e => setLoginEmail(e.target.value)} /></div>
            <div className="form-group"><label>Password</label><input type="password" placeholder="••••••••" value={loginPass} onChange={e => setLoginPass(e.target.value)} onKeyDown={e => e.key === "Enter" && doLogin()} /></div>
            <button className="btn btn-primary" onClick={doLogin} disabled={loading}>{loading ? "Logging in..." : "Login →"}</button>
            <p className="auth-switch">No account? <a onClick={() => switchTab("signup")}>Sign Up</a></p>
          </>
        )}

        {tab === "signup" && (
          <>
            <div className="step-indicator">
              {[1,2,3].map(s => <div key={s} className={`step-dot ${step >= s ? "active" : ""}`} />)}
            </div>

            {step === 1 && (
              <>
                <div className="form-group"><label>Email</label><input type="email" placeholder="you@college.edu" value={email} onChange={e => setEmail(e.target.value)} /></div>
                <div className="form-group"><label>Password</label><input type="password" placeholder="Create a password" value={password} onChange={e => setPassword(e.target.value)} /></div>
                <button className="btn btn-primary" onClick={doSendOtp} disabled={loading}>{loading ? "Sending OTP..." : "Send OTP →"}</button>
              </>
            )}

            {step === 2 && (
              <>
                <p style={{ textAlign:"center", color:"var(--muted)", fontSize:"0.88rem", marginBottom:"1rem" }}>
                  Enter the 5-digit OTP sent to <strong>{email}</strong>
                </p>
                <div className="form-group">
                  <input
                    className="otp-input"
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={5}
                    placeholder="- - - - -"
                    value={otpValue}
                    onChange={e => setOtpValue(e.target.value.replace(/[^0-9]/g, "").slice(0, 5))}
                    autoFocus
                  />
                </div>
                <button className="btn btn-primary" onClick={doVerifyOtp} disabled={loading || otpValue.length < 5}>{loading ? "Verifying..." : "Verify OTP →"}</button>
                <p className="auth-switch"><a onClick={doSendOtp}>Resend OTP</a></p>
              </>
            )}

            {step === 3 && (
              <>
                <div className="form-group"><label>Full Name</label><input value={name} onChange={e => setName(e.target.value)} placeholder="Your full name" /></div>
                <div className="form-group"><label>College / University</label><input value={college} onChange={e => setCollege(e.target.value)} placeholder="Your college" /></div>
                <div className="form-group"><label>City / Location</label><input value={location} onChange={e => setLocation(e.target.value)} placeholder="e.g. Chennai, India" /></div>
                <div className="form-group">
                  <label>Study Style</label>
                  <div className="style-options">
                    {STUDY_STYLES.map(s => <div key={s} className={`style-opt ${studyStyle === s ? "selected" : ""}`} onClick={() => setStudyStyle(s)}>{s}</div>)}
                  </div>
                </div>
                <div className="form-group">
                  <label>Subjects</label>
                  <div className="style-options">
                    {SUBJECTS_LIST.map(s => <div key={s} className={`style-opt ${subjects.includes(s) ? "selected" : ""}`} onClick={() => toggleSubject(s)}>{s}</div>)}
                  </div>
                </div>
                <button className="btn btn-primary" style={{ marginTop:"0.5rem" }} onClick={doSignup} disabled={loading || !name || !college}>
                  {loading ? "Creating account..." : "Create Account 🎉"}
                </button>
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function Discover({ user, onMatch, onToast }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [liking, setLiking] = useState(null);
  const [styleFilter, setStyleFilter] = useState("");
  const [subjectFilter, setSubjectFilter] = useState("");

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (styleFilter) params.set("style", styleFilter);
      if (subjectFilter) params.set("subject", subjectFilter);
      const data = await apiFetch(`/discover?${params}`);
      setUsers(data);
    } catch (e) { onToast(e.message, "error"); }
    setLoading(false);
  }, [styleFilter, subjectFilter]);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  const like = async (targetId, targetName) => {
    setLiking(targetId);
    try {
      const res = await apiFetch(`/like/${targetId}`, { method: "POST" });
      setUsers(p => p.filter(u => u.id !== targetId));
      if (res.matched) onMatch({ id: targetId, name: targetName });
      else onToast(`You liked ${targetName}!`, "success");
    } catch (e) { onToast(e.message, "error"); }
    setLiking(null);
  };

  const pass = (targetId) => setUsers(p => p.filter(u => u.id !== targetId));

  return (
    <div>
      <h2 className="page-title">Discover</h2>
      <p className="page-sub">Find your study partner</p>
      <div className="discover-wrapper">
        <div className="discover-filters card">
          <div className="filter-section">
            <div className="filter-label">Study Style</div>
            {STUDY_STYLES.map(s => (
              <div key={s} className={`filter-chip ${styleFilter === s ? "active" : ""}`} onClick={() => setStyleFilter(p => p === s ? "" : s)}>{s}</div>
            ))}
          </div>
          <div className="filter-section">
            <div className="filter-label">Subject</div>
            {SUBJECTS_LIST.slice(0,8).map(s => (
              <div key={s} className={`filter-chip ${subjectFilter === s ? "active" : ""}`} onClick={() => setSubjectFilter(p => p === s ? "" : s)}>{s}</div>
            ))}
          </div>
          {(styleFilter || subjectFilter) && (
            <div className="filter-chip" style={{ color:"var(--red)", borderColor:"var(--red)" }} onClick={() => { setStyleFilter(""); setSubjectFilter(""); }}>✕ Clear</div>
          )}
        </div>
        <div className="discover-cards">
          {loading && <div className="loading"><div className="spinner" /> Finding students...</div>}
          {!loading && users.length === 0 && (
            <div className="card" style={{ textAlign:"center", padding:"3rem", color:"var(--muted)" }}>
              <div style={{ fontSize:"2.5rem", marginBottom:"0.5rem" }}>🎓</div>
              <div style={{ fontWeight:600 }}>No more profiles right now!</div>
              <div style={{ fontSize:"0.88rem", marginTop:"0.3rem" }}>Try clearing filters or check back later.</div>
              <button className="btn btn-outline btn-sm" style={{ marginTop:"1rem" }} onClick={fetchUsers}>Refresh</button>
            </div>
          )}
          <div className="cards-grid">
            {users.map(u => (
              <div className="profile-card" key={u.id}>
                <div className="profile-card-banner" style={{ background:`linear-gradient(135deg, ${userColor(u.id)} 0%, #1e293b 100%)` }} />
                <div style={{ padding:"0 1rem" }}>
                  <div className="profile-card-avatar" style={{ background:userColor(u.id) }}>{u.initials || getInitials(u.name)}</div>
                </div>
                <div className="profile-card-body">
                  <div className="profile-card-name">{u.name}</div>
                  <div className="profile-card-college">📍 {u.college}{u.location ? ` · ${u.location}` : ""}</div>
                  <div>
                    {u.style && <span className="tag tag-style">🎯 {u.style}</span>}
                    {(Array.isArray(u.subjects) ? u.subjects : []).slice(0,3).map(s => <span key={s} className="tag tag-subject">{s}</span>)}
                  </div>
                  <div className="card-actions">
                    <button className="btn-pass" onClick={() => pass(u.id)}>Pass</button>
                    <button className="btn-like" onClick={() => like(u.id, u.name)} disabled={liking === u.id}>
                      {liking === u.id ? "..." : "❤ Like"}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function Messages({ user, onToast }) {
  const [matches, setMatches] = useState([]);
  const [active, setActive] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const pollRef = useRef(null);
  const bottomRef = useRef();

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const data = await apiFetch("/matches");
        setMatches(data);
        if (data.length > 0) setActive(data[0]);
      } catch (e) { onToast(e.message, "error"); }
      setLoading(false);
    })();
  }, []);

  useEffect(() => {
    if (!active) return;
    setMessages([]);
    apiFetch(`/messages/${active.match_id}`).then(data => {
      if (Array.isArray(data)) setMessages(data);
    }).catch(() => {});

    clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const data = await apiFetch(`/messages/${active.match_id}`);
        if (Array.isArray(data)) setMessages(data);
      } catch {}
    }, 3000);

    return () => clearInterval(pollRef.current);
  }, [active?.match_id]);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  const send = async () => {
    if (!input.trim() || !active || sending) return;
    const text = input.trim(); setInput(""); setSending(true);
    try {
      const msg = await apiFetch(`/messages/${active.match_id}`, { method: "POST", body: { text } });
      setMessages(p => [...p, msg]);
      setMatches(p => p.map(m => m.match_id === active.match_id ? { ...m, last_message: text } : m));
    } catch (e) { onToast(e.message, "error"); setInput(text); }
    setSending(false);
  };

  return (
    <div>
      <h2 className="page-title">Messages</h2>
      <p className="page-sub">Chat with your study matches</p>
      <div className="chat-layout">
        <div className="chat-sidebar">
          {loading && <div className="loading"><div className="spinner" /></div>}
          {!loading && matches.length === 0 && (
            <div className="card" style={{ textAlign:"center", color:"var(--muted)", padding:"2rem", fontSize:"0.9rem" }}>
              No matches yet. Start discovering! 🔍
            </div>
          )}
          {matches.map(m => (
            <div key={m.match_id} className={`match-row ${active?.match_id === m.match_id ? "active" : ""}`} onClick={() => setActive(m)}>
              <div className="match-avatar" style={{ background:userColor(m.id) }}>{m.initials || getInitials(m.name)}</div>
              <div className="match-info">
                <div className="match-name">{m.name}</div>
                <div className="match-preview">{m.last_message || "Say hi! 👋"}</div>
              </div>
              {m.unread_count > 0 && <div className="unread-dot" />}
            </div>
          ))}
        </div>
        <div className="chat-main">
          {!active ? (
            <div className="chat-empty"><div style={{ fontSize:"2rem" }}>💬</div><div>Select a match to chat</div></div>
          ) : (
            <>
              <div className="chat-header">
                <div className="match-avatar" style={{ background:userColor(active.id), width:38, height:38, fontSize:"0.85rem" }}>
                  {active.initials || getInitials(active.name)}
                </div>
                <div>
                  <div style={{ fontWeight:600 }}>{active.name}</div>
                  <div style={{ fontSize:"0.78rem", color:"var(--muted)" }}>{active.college}</div>
                </div>
              </div>
              <div className="chat-messages">
                {messages.length === 0 && (
                  <div style={{ textAlign:"center", color:"var(--muted)", padding:"2rem", fontSize:"0.9rem" }}>Start the conversation! 👋</div>
                )}
                {messages.map((m, i) => (
                  <div key={m.id || i} className={`msg ${m.sender_id === user.id ? "me" : "them"}`}>
                    <div className="msg-bubble">{m.text}</div>
                    <div className="msg-time">{fmtTime(m.created_at)}</div>
                  </div>
                ))}
                <div ref={bottomRef} />
              </div>
              <div className="chat-input-row">
                <input className="chat-input" value={input} onChange={e => setInput(e.target.value)}
                  placeholder="Type a message..." onKeyDown={e => e.key === "Enter" && send()} />
                <button className="chat-send" onClick={send} disabled={sending}>{sending ? "..." : "Send"}</button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function Profile({ user, setUser, onToast }) {
  const [name, setName] = useState(user.name || "");
  const [college, setCollege] = useState(user.college || "");
  const [location, setLocation] = useState(user.location || "");
  const [subjects, setSubjects] = useState(user.subjects || []);
  const [studyStyle, setStudyStyle] = useState(user.style || "");
  const [loading, setLoading] = useState(false);
  const toggleSubject = (s) => setSubjects(p => p.includes(s) ? p.filter(x => x !== s) : [...p, s]);
  const save = async () => {
    setLoading(true);
    try {
      await apiFetch("/profile/me", { method: "PUT", body: { name, college, subjects, style: studyStyle, location } });
      const updated = { ...user, name, college, subjects, style: studyStyle, location, initials: getInitials(name) };
      setUser(updated); setStoredUser(updated);
      onToast("Profile saved!", "success");
    } catch (e) { onToast(e.message, "error"); }
    setLoading(false);
  };
  return (
    <div>
      <div className="profile-hero">
        <div className="profile-hero-avatar" style={{ background:userColor(user.id) }}>{user.initials || getInitials(user.name)}</div>
        <div className="profile-hero-info">
          <h2>{user.name}</h2>
          <p>{user.college} · {user.style}</p>
          <p style={{ marginTop:"0.3rem", fontSize:"0.85rem" }}>{(user.subjects||[]).join(", ")}</p>
        </div>
      </div>
      <div style={{ maxWidth:600 }}>
        <div className="card">
          <h3 style={{ marginBottom:"1.2rem" }}>Edit Profile</h3>
          <div className="form-group"><label>Full Name</label><input value={name} onChange={e => setName(e.target.value)} /></div>
          <div className="form-group"><label>College</label><input value={college} onChange={e => setCollege(e.target.value)} /></div>
          <div className="form-group"><label>Location</label><input value={location} onChange={e => setLocation(e.target.value)} /></div>
          <div className="form-group">
            <label>Study Style</label>
            <div className="style-options">
              {STUDY_STYLES.map(s => <div key={s} className={`style-opt ${studyStyle===s?"selected":""}`} onClick={() => setStudyStyle(s)}>{s}</div>)}
            </div>
          </div>
          <div className="form-group">
            <label>Subjects</label>
            <div className="style-options">
              {SUBJECTS_LIST.map(s => <div key={s} className={`style-opt ${subjects.includes(s)?"selected":""}`} onClick={() => toggleSubject(s)}>{s}</div>)}
            </div>
          </div>
          <button className="btn btn-primary" style={{ width:"auto", padding:"0.7rem 2rem", marginTop:"0.5rem" }} onClick={save} disabled={loading}>
            {loading ? "Saving..." : "Save Changes"}
          </button>
        </div>
      </div>
    </div>
  );
}

function StudyTools({ onToast }) {
  const [secs, setSecs] = useState(25*60);
  const [running, setRunning] = useState(false);
  const [mode, setMode] = useState("focus");
  const [goals, setGoals] = useState([]);
  const [newGoal, setNewGoal] = useState("");
  const total = mode==="focus" ? 25*60 : 5*60;
  const prog  = ((total-secs)/total)*100;
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => {
      setSecs(p => {
        if (p <= 1) { setRunning(false); onToast(mode==="focus"?"Focus done! 🎉 Take a break":"Break over! Back to work 💪","success"); return mode==="focus"?5*60:25*60; }
        return p-1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, [running, mode]);
  const fmt = (s) => `${String(Math.floor(s/60)).padStart(2,"0")}:${String(s%60).padStart(2,"0")}`;
  const switchMode = (m) => { setMode(m); setSecs(m==="focus"?25*60:5*60); setRunning(false); };
  const addGoal = () => { if (!newGoal.trim()) return; setGoals(p=>[...p,{id:Date.now(),text:newGoal,done:false}]); setNewGoal(""); };
  return (
    <div>
      <h2 className="page-title">Study Tools</h2>
      <p className="page-sub">Stay focused and productive</p>
      <div className="grid-2" style={{ maxWidth:800 }}>
        <div className="card" style={{ textAlign:"center" }}>
          <div style={{ display:"flex", gap:"0.5rem", justifyContent:"center", marginBottom:"0.5rem" }}>
            <div className={`filter-chip ${mode==="focus"?"active":""}`} onClick={() => switchMode("focus")}>🍅 Focus 25m</div>
            <div className={`filter-chip ${mode==="break"?"active":""}`} onClick={() => switchMode("break")}>☕ Break 5m</div>
          </div>
          <div className="timer-circle" style={{"--prog":prog}}>{fmt(secs)}</div>
          <div className="timer-controls">
            <button className="timer-btn" style={{ background:"var(--ink)", color:"var(--paper)" }} onClick={() => setRunning(p=>!p)}>{running ? "⏸ Pause" : "▶ Start"}</button>
            <button className="timer-btn" style={{ background:"var(--cream)", border:"1.5px solid var(--border)" }} onClick={() => { setRunning(false); setSecs(mode==="focus"?25*60:5*60); }}>↺ Reset</button>
          </div>
        </div>
        <div className="card">
          <h3 style={{ marginBottom:"1rem" }}>Session Goals</h3>
          {goals.length===0 && <p style={{ color:"var(--muted)", fontSize:"0.88rem", marginBottom:"0.5rem" }}>Add goals for this session...</p>}
          <ul className="goals-list">
            {goals.map(g => (
              <li key={g.id} className={g.done?"done":""}>
                <input type="checkbox" checked={g.done} onChange={() => setGoals(p=>p.map(x=>x.id===g.id?{...x,done:!x.done}:x))}/>
                <span style={{ flex:1 }}>{g.text}</span>
                <span style={{ cursor:"pointer", color:"var(--muted)" }} onClick={() => setGoals(p=>p.filter(x=>x.id!==g.id))}>✕</span>
              </li>
            ))}
          </ul>
          <div className="goal-input-row">
            <input className="goal-input" placeholder="Add a goal..." value={newGoal} onChange={e=>setNewGoal(e.target.value)} onKeyDown={e=>e.key==="Enter"&&addGoal()}/>
            <button className="btn btn-primary btn-sm" onClick={addGoal}>+ Add</button>
          </div>
          {goals.length>0 && (
            <div style={{ marginTop:"1rem", padding:"0.6rem 0.8rem", background:"var(--cream)", borderRadius:"10px", fontSize:"0.85rem", color:"var(--muted)" }}>
              ✅ {goals.filter(g=>g.done).length}/{goals.length} goals complete
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Rating({ user, onToast }) {
  const [matches, setMatches] = useState([]);
  const [selected, setSelected] = useState("");
  const [ratings, setRatings] = useState({ punctuality:0, helpfulness:0, focus:0 });
  const [feedback, setFeedback] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  useEffect(() => {
    (async () => {
      try { const d = await apiFetch("/matches"); setMatches(d); if(d.length>0) setSelected(d[0].id); }
      catch {}
      setLoading(false);
    })();
  }, []);
  const star = (cat, val) => setRatings(p => ({ ...p, [cat]:val }));
  const submit = async () => {
    if (!selected || !ratings.punctuality || !ratings.helpfulness || !ratings.focus) { onToast("Please fill all star ratings", "error"); return; }
    setSubmitting(true);
    try {
      await apiFetch("/ratings", { method:"POST", body:{ toId:selected, ...ratings, feedback } });
      setSubmitted(true); onToast("Rating submitted! 🙏","success");
    } catch(e) { onToast(e.message,"error"); }
    setSubmitting(false);
  };
  const StarRow = ({ label, cat }) => (
    <div className="rating-row">
      <div style={{ fontWeight:500, fontSize:"0.9rem" }}>{label}</div>
      <div>{[1,2,3,4,5].map(v=><span key={v} className="star" onClick={()=>star(cat,v)}>{v<=ratings[cat]?"⭐":"☆"}</span>)}</div>
    </div>
  );
  if (loading) return <div className="loading"><div className="spinner"/></div>;
  if (!matches.length) return <div><h2 className="page-title">Rate Your Partner</h2><p className="page-sub">Get some matches first!</p></div>;
  return (
    <div>
      <h2 className="page-title">Rate Your Partner</h2>
      <p className="page-sub">Help build a quality community</p>
      <div className="card" style={{ maxWidth:480 }}>
        <div className="form-group">
          <label>Select Study Partner</label>
          <select value={selected} onChange={e=>{ setSelected(Number(e.target.value)); setSubmitted(false); setRatings({punctuality:0,helpfulness:0,focus:0}); }}>
            {matches.map(m=><option key={m.match_id} value={m.id}>{m.name}</option>)}
          </select>
        </div>
        {!submitted ? (
          <>
            <StarRow label="⏰ Punctuality" cat="punctuality"/>
            <StarRow label="🤝 Helpfulness" cat="helpfulness"/>
            <StarRow label="🎯 Focus" cat="focus"/>
            <div className="form-group" style={{ marginTop:"1rem" }}>
              <label>Written Feedback (optional)</label>
              <textarea rows={3} placeholder="Share your experience..." style={{ resize:"vertical" }} value={feedback} onChange={e=>setFeedback(e.target.value)}/>
            </div>
            <button className="btn btn-primary" style={{ marginTop:"0.5rem" }} onClick={submit} disabled={submitting}>{submitting ? "Submitting..." : "Submit Rating"}</button>
          </>
        ) : (
          <div style={{ textAlign:"center", padding:"2rem", color:"var(--green)" }}>
            <div style={{ fontSize:"2.5rem" }}>✅</div>
            <div style={{ fontWeight:700, fontSize:"1.1rem", marginTop:"0.5rem" }}>Rating Submitted!</div>
            <div style={{ color:"var(--muted)", fontSize:"0.9rem", marginTop:"0.3rem" }}>Thank you for helping our community.</div>
          </div>
        )}
      </div>
    </div>
  );
}

function Admin({ onToast }) {
  const [stats, setStats] = useState(null);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState(null);
  useEffect(() => {
    (async () => {
      try {
        const [s, u] = await Promise.all([apiFetch("/admin/stats"), apiFetch("/admin/users")]);
        setStats(s); setUsers(u.users || u);
      } catch(e) { onToast(e.message,"error"); }
      setLoading(false);
    })();
  }, []);
  const deleteUser = async (id, name) => {
    if (!window.confirm(`Remove ${name}?`)) return;
    setDeleting(id);
    try {
      await apiFetch(`/admin/users/${id}`, { method:"DELETE" });
      setUsers(p=>p.filter(u=>u.id!==id)); onToast(`${name} removed.`,"success");
    } catch(e) { onToast(e.message,"error"); }
    setDeleting(null);
  };
  if (loading) return <div className="loading"><div className="spinner"/> Loading dashboard...</div>;
  const statCards = [
    { label:"Total Users", num:stats?.totalUsers||0, icon:"👥" },
    { label:"Total Matches", num:stats?.totalMatches||0, icon:"💞" },
    { label:"Total Messages", num:stats?.totalMessages||0, icon:"💬" },
    { label:"Today's Signups", num:stats?.todaySignups||0, icon:"🆕" },
  ];
  return (
    <div>
      <h2 className="page-title">Admin Dashboard</h2>
      <p className="page-sub">Monitor & manage the platform</p>
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:"1rem", marginBottom:"1.5rem" }}>
        {statCards.map(s=>(
          <div key={s.label} className="stat-card">
            <div style={{ fontSize:"1.5rem" }}>{s.icon}</div>
            <div className="stat-num">{s.num}</div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>
      <div className="card">
        <h3 style={{ marginBottom:"1rem" }}>All Users ({users.length})</h3>
        <table className="table">
          <thead><tr><th>Name</th><th>Email</th><th>College</th><th>Style</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>
            {users.map(u=>(
              <tr key={u.id}>
                <td><div style={{ display:"flex", alignItems:"center", gap:"0.6rem" }}><div className="match-avatar" style={{ width:30, height:30, fontSize:"0.75rem", background:userColor(u.id) }}>{u.initials||getInitials(u.name)}</div>{u.name}</div></td>
                <td style={{ fontSize:"0.82rem", color:"var(--muted)" }}>{u.email}</td>
                <td>{u.college}</td>
                <td>{u.style&&<span className="tag tag-style">{u.style}</span>}</td>
                <td><span className={`badge ${u.is_admin?"badge-admin":"badge-active"}`}>{u.is_admin?"Admin":"Active"}</span></td>
                <td>{!u.is_admin&&(<button className="btn btn-outline btn-sm" style={{ fontSize:"0.78rem", color:"var(--red)", borderColor:"var(--red)" }} onClick={()=>deleteUser(u.id,u.name)} disabled={deleting===u.id}>{deleting===u.id?"...":"Remove"}</button>)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function MatchPopup({ match, onClose }) {
  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(13,13,13,0.7)", zIndex:1000, display:"flex", alignItems:"center", justifyContent:"center", padding:"1rem" }}>
      <div style={{ background:"var(--card)", borderRadius:"24px", padding:"2.5rem", textAlign:"center", maxWidth:"340px", width:"100%", boxShadow:"var(--shadow-lg)" }}>
        <div style={{ fontSize:"3rem", marginBottom:"0.5rem" }}>🎉</div>
        <h2 style={{ color:"var(--accent)", marginBottom:"0.3rem" }}>It's a Match!</h2>
        <p style={{ color:"var(--muted)", marginBottom:"1.5rem", fontSize:"0.9rem" }}>You and <strong>{match.name}</strong> liked each other!</p>
        <div style={{ display:"flex", gap:"0.5rem" }}>
          <button className="btn btn-outline btn-sm" style={{ flex:1 }} onClick={()=>onClose(false)}>Continue</button>
          <button className="btn btn-primary btn-sm" style={{ flex:1 }} onClick={()=>onClose(true)}>Message →</button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [authed, setAuthed] = useState(!!getToken() && !!getStoredUser());
  const [user, setUser] = useState(getStoredUser());
  const [tab, setTab] = useState("discover");
  const [toast, setToast] = useState(null);
  const [matchPopup, setMatchPopup] = useState(null);

  useEffect(() => {
    if (!getToken()) return;
    apiFetch("/profile/me").then(data => {
      setUser(data); setStoredUser(data); setAuthed(true);
    }).catch(() => { clearToken(); clearStoredUser(); setAuthed(false); });
  }, []);

  const showToast = (msg, type="success") => setToast({ msg, type });
  const handleMatch = (matchedUser) => setMatchPopup(matchedUser);
  const handleMatchClose = (goToMessages) => { setMatchPopup(null); if(goToMessages) setTab("messages"); };
  const logout = () => { clearToken(); clearStoredUser(); setAuthed(false); setUser(null); };

  if (!authed) return (
    <>
      <style>{style}</style>
      <Auth onLogin={u => { setUser(u); setAuthed(true); }} />
      {toast && <Toast msg={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
    </>
  );

  const TABS = [
    { id:"discover", label:"🔍 Discover" },
    { id:"messages", label:"💬 Messages" },
    { id:"tools",    label:"⏱ Study Tools" },
    { id:"rating",   label:"⭐ Rate" },
    { id:"profile",  label:"👤 Profile" },
    { id:"admin",    label:"⚙ Admin" },
  ];

  return (
    <>
      <style>{style}</style>
      <div className="app">
        <nav className="nav">
          <div className="nav-logo">Study<span>Buddy</span></div>
          <div className="nav-tabs">
            {TABS.map(t => (
              <button key={t.id} className={`nav-tab ${tab===t.id?"active":""}`} onClick={()=>setTab(t.id)}>{t.label}</button>
            ))}
          </div>
          <div className="nav-user">
            <div className="avatar" style={{ background:userColor(user?.id) }} onClick={()=>setTab("profile")}>
              {user?.initials||getInitials(user?.name)}
            </div>
            <button className="logout-btn" onClick={logout}>Logout</button>
          </div>
        </nav>
        <div className="main">
          {tab==="discover" && <Discover user={user} onMatch={handleMatch} onToast={showToast}/>}
          {tab==="messages" && <Messages user={user} onToast={showToast}/>}
          {tab==="tools"    && <StudyTools onToast={showToast}/>}
          {tab==="rating"   && <Rating user={user} onToast={showToast}/>}
          {tab==="profile"  && <Profile user={user} setUser={setUser} onToast={showToast}/>}
          {tab==="admin"    && <Admin onToast={showToast}/>}
        </div>
      </div>
      {matchPopup && <MatchPopup match={matchPopup} onClose={handleMatchClose}/>}
      {toast && <Toast msg={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
    </>
  );
}

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
  .avatar { width: 34px; height: 34px; border-radius: 50%; background: var(--accent); display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.85rem; color: #fff; cursor: pointer; overflow: hidden; }
  .avatar img { width: 100%; height: 100%; object-fit: cover; border-radius: 50%; }
  .profile-card-avatar img, .match-avatar img, .profile-hero-avatar img { width: 100%; height: 100%; object-fit: cover; border-radius: 50%; }
  .pic-upload-wrap { position: relative; display: inline-block; cursor: pointer; }
  .pic-upload-wrap:hover .pic-overlay { opacity: 1; }
  .pic-overlay { position: absolute; inset: 0; border-radius: 50%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; color: #fff; font-size: 0.7rem; font-weight: 600; opacity: 0; transition: opacity 0.2s; text-align: center; }
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
  .room-card { background: var(--card); border-radius: 18px; border: 1px solid var(--border); overflow: hidden; transition: transform 0.15s, box-shadow 0.15s; }
  .room-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-lg); }
  .room-banner { height: 80px; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; }
  .room-body { padding: 1rem 1.2rem 1.2rem; }
  .room-name { font-family: 'Clash Display', sans-serif; font-size: 1.1rem; font-weight: 700; margin-bottom: 0.2rem; }
  .room-meta { font-size: 0.8rem; color: var(--muted); margin-bottom: 0.75rem; }
  .room-members { display: flex; gap: -6px; margin-bottom: 0.75rem; }
  .room-avatar { width: 28px; height: 28px; border-radius: 50%; border: 2px solid var(--card); display: flex; align-items: center; justify-content: center; font-size: 0.65rem; font-weight: 700; color: #fff; margin-right: -6px; overflow: hidden; }
  .room-inside { background: var(--ink); color: var(--paper); border-radius: 20px; padding: 1.5rem; margin-bottom: 1.5rem; }
  .room-timer-display { font-family: 'Clash Display', sans-serif; font-size: 4rem; font-weight: 700; text-align: center; letter-spacing: -2px; }
  .room-phase { text-align: center; font-size: 0.9rem; color: #aaa; margin-bottom: 1rem; }
  .lofi-player { background: rgba(255,255,255,0.05); border-radius: 14px; padding: 1rem; margin-top: 1rem; display: flex; align-items: center; gap: 1rem; }
  .lofi-info { flex: 1; }
  .lofi-title { font-weight: 600; font-size: 0.9rem; }
  .lofi-sub { font-size: 0.75rem; color: #888; }
  .lofi-btn { width: 40px; height: 40px; border-radius: 50%; background: var(--accent); border: none; color: #fff; font-size: 1.1rem; cursor: pointer; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .member-chip { display: flex; align-items: center; gap: 0.4rem; background: rgba(255,255,255,0.08); border-radius: 20px; padding: 0.3rem 0.75rem 0.3rem 0.3rem; font-size: 0.8rem; }
  .mobile-nav { display: none; }
  @media (max-width: 768px) {
    .discover-wrapper { flex-direction: column; }
    .discover-filters { width: 100%; }
    .chat-layout { flex-direction: column; height: auto; }
    .chat-sidebar { width: 100%; }
    .grid-2 { grid-template-columns: 1fr; }
    .main { padding: 1rem; padding-bottom: 80px; }
    .nav-tabs { display: none; }
    .mobile-nav { display: flex; position: fixed; bottom: 0; left: 0; right: 0; background: var(--ink); z-index: 200; border-top: 1px solid rgba(255,255,255,0.1); padding: 0.4rem 0 0.6rem; }
    .mobile-nav-btn { flex: 1; display: flex; flex-direction: column; align-items: center; gap: 0.15rem; background: none; border: none; color: #888; cursor: pointer; padding: 0.3rem 0; font-size: 0.6rem; font-family: 'DM Sans', sans-serif; transition: color 0.15s; }
    .mobile-nav-btn.active { color: var(--accent); }
    .mobile-nav-btn span:first-child { font-size: 1.2rem; }
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

  const [customStyle, setCustomStyle] = useState("");
  const [customSubject, setCustomSubject] = useState("");
  const toggleSubject = (s) => setSubjects(p => p.includes(s) ? p.filter(x => x !== s) : [...p, s]);
  const addCustomStyle = () => {
    const s = customStyle.trim();
    if (!s) return;
    setStudyStyle(s);
    setCustomStyle("");
  };
  const addCustomSubject = () => {
    const s = customSubject.trim();
    if (!s || subjects.includes(s)) return;
    setSubjects(p => [...p, s]);
    setCustomSubject("");
  };

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
                  <div className="style-options" style={{ marginBottom:"0.5rem" }}>
                    {STUDY_STYLES.map(s => <div key={s} className={`style-opt ${studyStyle === s ? "selected" : ""}`} onClick={() => setStudyStyle(s)}>{s}</div>)}
                    {studyStyle && !STUDY_STYLES.includes(studyStyle) && (
                      <div className="style-opt selected" onClick={() => setStudyStyle("")}>{studyStyle} ✕</div>
                    )}
                  </div>
                  <div style={{ display:"flex", gap:"0.5rem" }}>
                    <input placeholder="Add your own style..." value={customStyle} onChange={e => setCustomStyle(e.target.value)}
                      onKeyDown={e => e.key==="Enter" && addCustomStyle()}
                      style={{ flex:1, padding:"0.5rem 0.75rem", border:"1.5px solid var(--border)", borderRadius:8, fontSize:"0.88rem", background:"var(--cream)", outline:"none", fontFamily:"inherit" }} />
                    <button className="btn btn-outline btn-sm" onClick={addCustomStyle}>+ Add</button>
                  </div>
                </div>
                <div className="form-group">
                  <label>Subjects</label>
                  <div className="style-options" style={{ marginBottom:"0.5rem" }}>
                    {SUBJECTS_LIST.map(s => <div key={s} className={`style-opt ${subjects.includes(s) ? "selected" : ""}`} onClick={() => toggleSubject(s)}>{s}</div>)}
                    {subjects.filter(s => !SUBJECTS_LIST.includes(s)).map(s => (
                      <div key={s} className="style-opt selected" onClick={() => toggleSubject(s)}>{s} ✕</div>
                    ))}
                  </div>
                  <div style={{ display:"flex", gap:"0.5rem" }}>
                    <input placeholder="Add your own subject..." value={customSubject} onChange={e => setCustomSubject(e.target.value)}
                      onKeyDown={e => e.key==="Enter" && addCustomSubject()}
                      style={{ flex:1, padding:"0.5rem 0.75rem", border:"1.5px solid var(--border)", borderRadius:8, fontSize:"0.88rem", background:"var(--cream)", outline:"none", fontFamily:"inherit" }} />
                    <button className="btn btn-outline btn-sm" onClick={addCustomSubject}>+ Add</button>
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
                  <div className="profile-card-avatar" style={{ background:userColor(u.id) }}>{u.photo ? <img src={u.photo} alt={u.name} /> : (u.initials || getInitials(u.name))}</div>
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
              <div className="match-avatar" style={{ background:userColor(m.id) }}>{m.photo ? <img src={m.photo} alt={m.name} /> : (m.initials || getInitials(m.name))}</div>
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
  const [photo, setPhoto] = useState(user.photo || null);
  const fileRef = useRef(null);

  const [customStyle, setCustomStyle] = useState("");
  const [customSubject, setCustomSubject] = useState("");
  const toggleSubject = (s) => setSubjects(p => p.includes(s) ? p.filter(x => x !== s) : [...p, s]);
  const addCustomStyle = () => {
    const s = customStyle.trim();
    if (!s) return;
    setStudyStyle(s);
    setCustomStyle("");
  };
  const addCustomSubject = () => {
    const s = customSubject.trim();
    if (!s || subjects.includes(s)) return;
    setSubjects(p => [...p, s]);
    setCustomSubject("");
  };

  const handlePhoto = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) { onToast("Image too large! Max 10MB", "error"); return; }
    const reader = new FileReader();
    reader.onload = (ev) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement("canvas");
        const MAX = 400;
        let w = img.width, h = img.height;
        if (w > h) { if (w > MAX) { h = h * MAX / w; w = MAX; } }
        else { if (h > MAX) { w = w * MAX / h; h = MAX; } }
        canvas.width = w; canvas.height = h;
        canvas.getContext("2d").drawImage(img, 0, 0, w, h);
        const compressed = canvas.toDataURL("image/jpeg", 0.7);
        setPhoto(compressed);
      };
      img.src = ev.target.result as string;
    };
    reader.readAsDataURL(file);
  };

  const save = async () => {
    setLoading(true);
    try {
      await apiFetch("/profile/me", { method: "PUT", body: { name, college, subjects, style: studyStyle, location, photo } });
      const updated = { ...user, name, college, subjects, style: studyStyle, location, initials: getInitials(name), photo };
      setUser(updated); setStoredUser(updated);
      onToast("Profile saved!", "success");
    } catch (e) { onToast(e.message, "error"); }
    setLoading(false);
  };

  return (
    <div>
      <div className="profile-hero">
        <div className="pic-upload-wrap" onClick={() => fileRef.current?.click()}>
          <div className="profile-hero-avatar" style={{ background:userColor(user.id) }}>
            {photo ? <img src={photo} alt="avatar" /> : (user.initials || getInitials(user.name))}
          </div>
          <div className="pic-overlay">📷<br/>Change</div>
        </div>
        <input ref={fileRef} type="file" accept="image/*" style={{ display:"none" }} onChange={handlePhoto} />
        <div className="profile-hero-info">
          <h2>{user.name}</h2>
          <p>{user.college} · {user.style}</p>
          <p style={{ marginTop:"0.3rem", fontSize:"0.85rem" }}>{(user.subjects||[]).join(", ")}</p>
        </div>
      </div>
      <div style={{ maxWidth:600 }}>
        <div className="card">
          <h3 style={{ marginBottom:"1.2rem" }}>Edit Profile</h3>
          <div className="form-group" style={{ textAlign:"center", marginBottom:"1.5rem" }}>
            <label>Profile Picture</label>
            <div style={{ display:"flex", justifyContent:"center", marginTop:"0.5rem" }}>
              <div className="pic-upload-wrap" onClick={() => fileRef.current?.click()}>
                <div style={{ width:90, height:90, borderRadius:"50%", background:userColor(user.id), display:"flex", alignItems:"center", justifyContent:"center", fontSize:"2rem", fontWeight:700, color:"#fff", overflow:"hidden", border:"3px solid var(--accent)" }}>
                  {photo ? <img src={photo} alt="avatar" style={{ width:"100%", height:"100%", objectFit:"cover" }} /> : (user.initials || getInitials(user.name))}
                </div>
                <div className="pic-overlay">📷<br/>Upload</div>
              </div>
            </div>
            <p style={{ fontSize:"0.75rem", color:"var(--muted)", marginTop:"0.4rem" }}>Max 2MB · JPG, PNG</p>
          </div>
          <div className="form-group"><label>Full Name</label><input value={name} onChange={e => setName(e.target.value)} /></div>
          <div className="form-group"><label>College</label><input value={college} onChange={e => setCollege(e.target.value)} /></div>
          <div className="form-group"><label>Location</label><input value={location} onChange={e => setLocation(e.target.value)} /></div>
          <div className="form-group">
            <label>Study Style</label>
            <div className="style-options" style={{ marginBottom:"0.5rem" }}>
              {STUDY_STYLES.map(s => <div key={s} className={`style-opt ${studyStyle===s?"selected":""}`} onClick={() => setStudyStyle(s)}>{s}</div>)}
              {studyStyle && !STUDY_STYLES.includes(studyStyle) && (
                <div className="style-opt selected">{studyStyle} ✕<span style={{ cursor:"pointer", marginLeft:"0.2rem" }} onClick={() => setStudyStyle("")}></span></div>
              )}
            </div>
            <div style={{ display:"flex", gap:"0.5rem", marginTop:"0.4rem" }}>
              <input placeholder="Add custom style..." value={customStyle} onChange={e => setCustomStyle(e.target.value)}
                onKeyDown={e => e.key==="Enter" && addCustomStyle()}
                style={{ flex:1, padding:"0.5rem 0.75rem", border:"1.5px solid var(--border)", borderRadius:8, fontSize:"0.88rem", background:"var(--cream)", outline:"none", fontFamily:"inherit" }} />
              <button className="btn btn-outline btn-sm" onClick={addCustomStyle}>+ Add</button>
            </div>
          </div>
          <div className="form-group">
            <label>Subjects</label>
            <div className="style-options" style={{ marginBottom:"0.5rem" }}>
              {SUBJECTS_LIST.map(s => <div key={s} className={`style-opt ${subjects.includes(s)?"selected":""}`} onClick={() => toggleSubject(s)}>{s}</div>)}
              {subjects.filter(s => !SUBJECTS_LIST.includes(s)).map(s => (
                <div key={s} className="style-opt selected" onClick={() => toggleSubject(s)}>{s} ✕</div>
              ))}
            </div>
            <div style={{ display:"flex", gap:"0.5rem", marginTop:"0.4rem" }}>
              <input placeholder="Add custom subject..." value={customSubject} onChange={e => setCustomSubject(e.target.value)}
                onKeyDown={e => e.key==="Enter" && addCustomSubject()}
                style={{ flex:1, padding:"0.5rem 0.75rem", border:"1.5px solid var(--border)", borderRadius:8, fontSize:"0.88rem", background:"var(--cream)", outline:"none", fontFamily:"inherit" }} />
              <button className="btn btn-outline btn-sm" onClick={addCustomSubject}>+ Add</button>
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
  const MODES = [
    { id:"focus25",  label:"🍅 Focus 25m",  secs:25*60,  type:"focus" },
    { id:"focus55",  label:"🔥 Focus 55m",  secs:55*60,  type:"focus" },
    { id:"focus99",  label:"⚡ Focus 99m",  secs:99*60,  type:"focus" },
    { id:"break5",   label:"☕ Break 5m",   secs:5*60,   type:"break" },
    { id:"break15",  label:"🌿 Break 15m",  secs:15*60,  type:"break" },
  ];
  const [modeId, setModeId] = useState("focus25");
  const [secs, setSecs] = useState(25*60);
  const [running, setRunning] = useState(false);
  const [goals, setGoals] = useState([]);
  const [newGoal, setNewGoal] = useState("");
  const curMode = MODES.find(m => m.id === modeId) || MODES[0];
  const total = curMode.secs;
  const prog  = ((total-secs)/total)*100;
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => {
      setSecs(p => {
        if (p <= 1) {
          setRunning(false);
          onToast(curMode.type==="focus" ? "Focus done! 🎉 Take a break" : "Break over! Back to work 💪", "success");
          return total;
        }
        return p-1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, [running, modeId]);
  const fmt = (s) => `${String(Math.floor(s/60)).padStart(2,"0")}:${String(s%60).padStart(2,"0")}`;
  const switchMode = (id) => { const m = MODES.find(x=>x.id===id); setModeId(id); setSecs(m.secs); setRunning(false); };
  const addGoal = () => { if (!newGoal.trim()) return; setGoals(p=>[...p,{id:Date.now(),text:newGoal,done:false}]); setNewGoal(""); };
  return (
    <div>
      <h2 className="page-title">Study Tools</h2>
      <p className="page-sub">Stay focused and productive</p>
      <div className="grid-2" style={{ maxWidth:800 }}>
        <div className="card" style={{ textAlign:"center" }}>
          <div style={{ marginBottom:"0.75rem" }}>
            <div style={{ fontSize:"0.72rem", fontWeight:600, color:"var(--muted)", textTransform:"uppercase", letterSpacing:"0.5px", marginBottom:"0.4rem" }}>Focus</div>
            <div style={{ display:"flex", gap:"0.4rem", justifyContent:"center", flexWrap:"wrap", marginBottom:"0.5rem" }}>
              {MODES.filter(m=>m.type==="focus").map(m => (
                <div key={m.id} className={`filter-chip ${modeId===m.id?"active":""}`} onClick={() => switchMode(m.id)}>{m.label}</div>
              ))}
            </div>
            <div style={{ fontSize:"0.72rem", fontWeight:600, color:"var(--muted)", textTransform:"uppercase", letterSpacing:"0.5px", marginBottom:"0.4rem" }}>Break</div>
            <div style={{ display:"flex", gap:"0.4rem", justifyContent:"center", flexWrap:"wrap" }}>
              {MODES.filter(m=>m.type==="break").map(m => (
                <div key={m.id} className={`filter-chip ${modeId===m.id?"active":""}`} onClick={() => switchMode(m.id)}>{m.label}</div>
              ))}
            </div>
          </div>
          <div className="timer-circle" style={{"--prog":prog}}>{fmt(secs)}</div>
          <div className="timer-controls">
            <button className="timer-btn" style={{ background:"var(--ink)", color:"var(--paper)" }} onClick={() => setRunning(p=>!p)}>{running ? "⏸ Pause" : "▶ Start"}</button>
            <button className="timer-btn" style={{ background:"var(--cream)", border:"1.5px solid var(--border)" }} onClick={() => { setRunning(false); setSecs(curMode.secs); }}>↺ Reset</button>
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
      try { const d = await apiFetch("/matches"); if(Array.isArray(d)){ setMatches(d); if(d.length>0) setSelected(String(d[0].id)); } }
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
          <select value={selected} onChange={e=>{ setSelected(e.target.value); setSubmitted(false); setRatings({punctuality:0,helpfulness:0,focus:0}); }}>
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

  const load = async () => {
    try {
      const [s, u] = await Promise.all([apiFetch("/admin/stats"), apiFetch("/admin/users")]);
      setStats(s);
      setUsers(Array.isArray(u) ? u : (u.users || []));
    } catch(e) { onToast(e.message, "error"); }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  // Auto-refresh every 15 seconds
  useEffect(() => {
    const t = setInterval(() => load(), 15000);
    return () => clearInterval(t);
  }, []);

  if (loading) return <div className="loading"><div className="spinner"/> Loading dashboard...</div>;

  const statCards = [
    { label:"Total Users",    num:stats?.totalUsers    || 0, icon:"👥" },
    { label:"Total Matches",  num:stats?.totalMatches  || 0, icon:"💞" },
    { label:"Total Messages", num:stats?.totalMessages || 0, icon:"💬" },
    { label:"Today's Signups",num:stats?.todaySignups  || 0, icon:"🆕" },
  ];

  return (
    <div>
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:"0.25rem" }}>
        <h2 className="page-title" style={{ marginBottom:0 }}>Admin Dashboard</h2>
        <button className="btn btn-outline btn-sm" onClick={load}>🔄 Refresh</button>
      </div>
      <p className="page-sub">Monitor & manage the platform</p>

      <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:"1rem", marginBottom:"1.5rem" }}>
        {statCards.map(s=>(
          <div key={s.label} className="stat-card">
            <div style={{ fontSize:"1.5rem" }}>{s.icon}</div>
            <div className="stat-num">{s.num}</div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="card" style={{ overflowX:"auto" }}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:"1rem" }}>
          <h3>All Users ({users.length})</h3>
        </div>
        {users.length === 0 ? (
          <div style={{ textAlign:"center", padding:"2rem", color:"var(--muted)" }}>No users signed up yet</div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>College</th>
                <th>Style</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u=>(
                <tr key={u.id}>
                  <td>
                    <div style={{ display:"flex", alignItems:"center", gap:"0.6rem" }}>
                      <div style={{ width:32, height:32, borderRadius:"50%", background:userColor(u.id), display:"flex", alignItems:"center", justifyContent:"center", fontSize:"0.75rem", fontWeight:700, color:"#fff", overflow:"hidden", flexShrink:0 }}>
                        {u.photo ? <img src={u.photo} alt={u.name} style={{ width:"100%", height:"100%", objectFit:"cover" }} /> : (u.initials||getInitials(u.name))}
                      </div>
                      {u.name}
                    </div>
                  </td>
                  <td style={{ fontSize:"0.82rem", color:"var(--muted)" }}>{u.email}</td>
                  <td>{u.college}</td>
                  <td>{u.style && <span className="tag tag-style">{u.style}</span>}</td>
                  <td><span className={`badge ${u.is_admin?"badge-admin":"badge-active"}`}>{u.is_admin?"Admin":"Active"}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}


function Friends({ user, onToast, onMessage }) {
  const [matches, setMatches] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    apiFetch("/matches").then(data => {
      if (Array.isArray(data)) setMatches(data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading"><div className="spinner" /></div>;

  return (
    <div>
      <h2 className="page-title">👫 Friends</h2>
      <p className="page-sub">Your study partners — tap a card to see full profile</p>

      {matches.length === 0 && (
        <div className="card" style={{ textAlign:"center", padding:"3rem", color:"var(--muted)" }}>
          <div style={{ fontSize:"3rem", marginBottom:"1rem" }}>🤝</div>
          <div style={{ fontWeight:600, marginBottom:"0.5rem" }}>No friends yet!</div>
          <div style={{ fontSize:"0.9rem" }}>Start liking people in Discover to get matches</div>
        </div>
      )}

      <div className="grid-2">
        {matches.map(m => {
          const isOpen = expanded === m.match_id;
          return (
            <div key={m.match_id} className="card" style={{ padding:0, overflow:"hidden" }}>
              <div style={{ height:70, background:`linear-gradient(135deg, ${userColor(m.id)} 0%, #1e293b 100%)` }} />
              <div style={{ padding:"0 1rem 1rem" }}>
                <div style={{ display:"flex", alignItems:"flex-end", gap:"0.75rem", marginTop:-30, marginBottom:"0.6rem" }}>
                  <div style={{ width:60, height:60, borderRadius:"50%", background:userColor(m.id), display:"flex", alignItems:"center", justifyContent:"center", fontSize:"1.4rem", fontWeight:700, color:"#fff", border:"3px solid var(--card)", flexShrink:0, overflow:"hidden" }}>
                    {m.photo ? <img src={m.photo} alt={m.name} style={{ width:"100%", height:"100%", objectFit:"cover" }} /> : (m.initials || getInitials(m.name))}
                  </div>
                  <div style={{ paddingBottom:"0.2rem", flex:1 }}>
                    <div style={{ fontWeight:700, fontSize:"1.05rem" }}>{m.name}</div>
                    <div style={{ fontSize:"0.8rem", color:"var(--muted)" }}>📍 {m.college || "Unknown"}</div>
                  </div>
                  <button onClick={() => setExpanded(isOpen ? null : m.match_id)}
                    style={{ background:"var(--cream)", border:"1.5px solid var(--border)", borderRadius:8, padding:"0.3rem 0.7rem", fontSize:"0.78rem", cursor:"pointer", fontWeight:600, color:"var(--ink)", marginBottom:"0.2rem", flexShrink:0 }}>
                    {isOpen ? "▲ Hide" : "▼ View"}
                  </button>
                </div>

                {isOpen && (
                  <div style={{ borderTop:"1px solid var(--border)", paddingTop:"0.75rem", marginBottom:"0.75rem" }}>
                    {m.style && (
                      <div style={{ marginBottom:"0.5rem" }}>
                        <div style={{ fontSize:"0.72rem", fontWeight:600, color:"var(--muted)", textTransform:"uppercase", letterSpacing:"0.5px", marginBottom:"0.25rem" }}>Study Style</div>
                        <span className="tag tag-style">{m.style}</span>
                      </div>
                    )}
                    {m.subjects?.length > 0 && (
                      <div style={{ marginBottom:"0.5rem" }}>
                        <div style={{ fontSize:"0.72rem", fontWeight:600, color:"var(--muted)", textTransform:"uppercase", letterSpacing:"0.5px", marginBottom:"0.25rem" }}>Subjects</div>
                        <div style={{ display:"flex", flexWrap:"wrap", gap:"0.3rem" }}>
                          {m.subjects.map(s => <span key={s} className="tag">{s}</span>)}
                        </div>
                      </div>
                    )}
                    {!m.style && !m.subjects?.length && (
                      <div style={{ color:"var(--muted)", fontSize:"0.85rem", marginBottom:"0.5rem" }}>No extra info yet</div>
                    )}
                  </div>
                )}

                <button className="btn btn-primary btn-sm" style={{ width:"100%", marginTop:"0.25rem" }} onClick={() => onMessage(m)}>
                  💬 Message
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}


const LOFI_TRACKS = [
  { title: "Lo-Fi Hip Hop", sub: "Beats to study/relax to", emoji: "🎵", url: "https://www.youtube.com/embed/jfKfPfyJRdk?autoplay=1&controls=0" },
  { title: "Jazz Cafe Vibes", sub: "Smooth focus music", emoji: "🎷", url: "https://www.youtube.com/embed/VMAPTo7RVCo?autoplay=1&controls=0" },
  { title: "Rainy Day Focus", sub: "Rain + ambient sounds", emoji: "🌧️", url: "https://www.youtube.com/embed/mPZkdNFkNps?autoplay=1&controls=0" },
  { title: "Deep Focus", sub: "No distractions", emoji: "🧠", url: "https://www.youtube.com/embed/5qap5aO4i9A?autoplay=1&controls=0" },
];

const PRESET_ROOMS = [
  { id:"r1", name:"Lo-Fi Focus Room", emoji:"🎧", bg:"linear-gradient(135deg,#1e1b4b,#312e81)", subject:"General", vibe:"Quiet focus + lo-fi beats" },
  { id:"r2", name:"Math & Science Hub", emoji:"🔬", bg:"linear-gradient(135deg,#064e3b,#065f46)", subject:"Math/Science", vibe:"Collaborative problem solving" },
  { id:"r3", name:"Code & Build", emoji:"💻", bg:"linear-gradient(135deg,#1e3a5f,#1e40af)", subject:"CS/Programming", vibe:"Deep work sessions" },
  { id:"r4", name:"Exam Prep Zone", emoji:"📚", bg:"linear-gradient(135deg,#7c2d12,#9a3412)", subject:"All subjects", vibe:"Intense study mode" },
  { id:"r5", name:"Chill Study Lounge", emoji:"☕", bg:"linear-gradient(135deg,#422006,#713f12)", subject:"Any", vibe:"Relaxed pace, any topic" },
  { id:"r6", name:"Night Owl Session", emoji:"🌙", bg:"linear-gradient(135deg,#0f172a,#1e293b)", subject:"Any", vibe:"Late night grinders only" },
];

function StudyRooms({ user, onToast }) {
  const [activeRoom, setActiveRoom] = useState(null);
  const [members, setMembers] = useState([]);
  const [trackIdx, setTrackIdx] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [pomSecs, setPomSecs] = useState(25 * 60);
  const [pomRunning, setPomRunning] = useState(false);
  const [pomMode, setPomMode] = useState("focus"); // focus | break
  const [chat, setChat] = useState([]);
  const [chatInput, setChatInput] = useState("");
  const iframeRef = useRef(null);
  const chatBottomRef = useRef(null);

  const POM_TIMES = { focus: 25 * 60, break: 5 * 60 };

  // Pomodoro timer
  useEffect(() => {
    if (!pomRunning) return;
    const t = setInterval(() => {
      setPomSecs(p => {
        if (p <= 1) {
          setPomRunning(false);
          const next = pomMode === "focus" ? "break" : "focus";
          setPomMode(next);
          setPomSecs(POM_TIMES[next]);
          onToast(pomMode === "focus" ? "🎉 Focus done! Take a break" : "💪 Break over! Back to work", "success");
          return POM_TIMES[next];
        }
        return p - 1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, [pomRunning, pomMode]);

  const fmt = (s) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  const pomPct = ((POM_TIMES[pomMode] - pomSecs) / POM_TIMES[pomMode]) * 100;

  const joinRoom = (room) => {
    setActiveRoom(room);
    setPomSecs(25 * 60); setPomMode("focus"); setPomRunning(false);
    setPlaying(false); setTrackIdx(0);
    // Simulate other members in room
    const fakeMembers = [
      { id: "f1", name: "Alex", initials: "AX", color: "#7c3aed" },
      { id: "f2", name: "Sam", initials: "SM", color: "#2563eb" },
      { id: "f3", name: "Mia", initials: "MI", color: "#db2777" },
    ].slice(0, Math.floor(Math.random() * 3) + 1);
    setMembers([{ id: user.id, name: user.name, initials: user.initials || getInitials(user.name), color: "#e8500a", photo: user.photo }, ...fakeMembers]);
    setChat([{ id: 1, from: "System", text: `Welcome to ${room.name}! Stay focused 🎯`, sys: true }]);
  };

  const leaveRoom = () => { setActiveRoom(null); setPlaying(false); setPomRunning(false); };

  const sendChat = () => {
    if (!chatInput.trim()) return;
    setChat(p => [...p, { id: Date.now(), from: user.name, text: chatInput.trim(), mine: true }]);
    setChatInput("");
    setTimeout(() => chatBottomRef.current?.scrollIntoView({ behavior: "smooth" }), 50);
  };

  // Room list view
  if (!activeRoom) return (
    <div>
      <h2 className="page-title">🎧 Study Rooms</h2>
      <p className="page-sub">Join a virtual room, study together with lo-fi beats</p>
      <div className="grid-2">
        {PRESET_ROOMS.map(room => {
          const count = Math.floor(Math.random() * 8) + 1;
          return (
            <div key={room.id} className="room-card">
              <div className="room-banner" style={{ background: room.bg }}>{room.emoji}</div>
              <div className="room-body">
                <div className="room-name">{room.name}</div>
                <div className="room-meta">📖 {room.subject} · ✨ {room.vibe}</div>
                <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginTop:"0.5rem" }}>
                  <div style={{ fontSize:"0.8rem", color:"var(--muted)" }}>👥 {count} studying now</div>
                  <button className="btn btn-primary btn-sm" onClick={() => joinRoom(room)}>Join Room →</button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );

  const track = LOFI_TRACKS[trackIdx];

  // Inside room view
  return (
    <div>
      <div style={{ display:"flex", alignItems:"center", gap:"1rem", marginBottom:"1.2rem" }}>
        <button className="btn btn-outline btn-sm" onClick={leaveRoom}>← Leave Room</button>
        <div>
          <h2 style={{ fontFamily:"'Clash Display',sans-serif", fontSize:"1.3rem", fontWeight:700 }}>{activeRoom.emoji} {activeRoom.name}</h2>
          <div style={{ fontSize:"0.8rem", color:"var(--muted)" }}>{activeRoom.vibe}</div>
        </div>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 320px", gap:"1.5rem" }}>
        {/* Left: Timer + Lo-Fi */}
        <div>
          <div className="room-inside">
            {/* Members */}
            <div style={{ display:"flex", flexWrap:"wrap", gap:"0.5rem", marginBottom:"1.2rem" }}>
              {members.map(m => (
                <div key={m.id} className="member-chip">
                  <div style={{ width:24, height:24, borderRadius:"50%", background:m.color, display:"flex", alignItems:"center", justifyContent:"center", fontSize:"0.6rem", fontWeight:700, color:"#fff", overflow:"hidden", flexShrink:0 }}>
                    {m.photo ? <img src={m.photo} style={{ width:"100%", height:"100%", objectFit:"cover" }} /> : m.initials}
                  </div>
                  {m.name}
                </div>
              ))}
              <div className="member-chip" style={{ color:"#888" }}>+ more online</div>
            </div>

            {/* Pomodoro */}
            <div style={{ textAlign:"center", marginBottom:"1rem" }}>
              <div style={{ fontSize:"0.75rem", textTransform:"uppercase", letterSpacing:"1px", color: pomMode==="focus" ? "var(--accent)" : "#4ade80", marginBottom:"0.3rem", fontWeight:600 }}>
                {pomMode === "focus" ? "🍅 Focus Time" : "☕ Break Time"}
              </div>
              <div className="room-timer-display">{fmt(pomSecs)}</div>
              {/* Progress bar */}
              <div style={{ background:"rgba(255,255,255,0.1)", borderRadius:99, height:6, margin:"0.75rem auto", maxWidth:200 }}>
                <div style={{ background: pomMode==="focus" ? "var(--accent)" : "#4ade80", borderRadius:99, height:"100%", width:`${pomPct}%`, transition:"width 1s linear" }} />
              </div>
              <div style={{ display:"flex", gap:"0.5rem", justifyContent:"center", marginTop:"0.5rem" }}>
                <button onClick={() => setPomRunning(p=>!p)} style={{ background: pomRunning?"#374151":"var(--accent)", border:"none", color:"#fff", borderRadius:10, padding:"0.5rem 1.5rem", fontWeight:700, cursor:"pointer", fontFamily:"'Clash Display',sans-serif" }}>
                  {pomRunning ? "⏸ Pause" : "▶ Start"}
                </button>
                <button onClick={() => { setPomRunning(false); setPomSecs(POM_TIMES[pomMode]); }} style={{ background:"rgba(255,255,255,0.1)", border:"none", color:"#fff", borderRadius:10, padding:"0.5rem 1rem", cursor:"pointer" }}>
                  ↺
                </button>
                <button onClick={() => { const n = pomMode==="focus"?"break":"focus"; setPomMode(n); setPomSecs(POM_TIMES[n]); setPomRunning(false); }} style={{ background:"rgba(255,255,255,0.1)", border:"none", color:"#aaa", borderRadius:10, padding:"0.5rem 1rem", cursor:"pointer", fontSize:"0.8rem" }}>
                  {pomMode==="focus" ? "→ Break" : "→ Focus"}
                </button>
              </div>
            </div>

            {/* Lo-Fi Player */}
            <div className="lofi-player">
              <div style={{ fontSize:"1.8rem" }}>{track.emoji}</div>
              <div className="lofi-info">
                <div className="lofi-title">{track.title}</div>
                <div className="lofi-sub">{track.sub}</div>
              </div>
              <button className="lofi-btn" onClick={() => setTrackIdx(p => (p - 1 + LOFI_TRACKS.length) % LOFI_TRACKS.length)}>⏮</button>
              <button className="lofi-btn" onClick={() => setPlaying(p => !p)}>{playing ? "⏸" : "▶"}</button>
              <button className="lofi-btn" onClick={() => setTrackIdx(p => (p + 1) % LOFI_TRACKS.length)}>⏭</button>
            </div>
            {playing && (
              <iframe ref={iframeRef} src={track.url} style={{ display:"none" }} allow="autoplay" />
            )}
            <div style={{ marginTop:"0.75rem", display:"flex", gap:"0.5rem", flexWrap:"wrap" }}>
              {LOFI_TRACKS.map((t, i) => (
                <div key={i} onClick={() => { setTrackIdx(i); setPlaying(true); }}
                  style={{ cursor:"pointer", padding:"0.3rem 0.75rem", borderRadius:20, fontSize:"0.78rem", background: trackIdx===i ? "var(--accent)" : "rgba(255,255,255,0.08)", color: trackIdx===i ? "#fff" : "#aaa", fontWeight: trackIdx===i ? 600 : 400 }}>
                  {t.emoji} {t.title}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Room Chat */}
        <div style={{ background:"var(--card)", borderRadius:18, border:"1px solid var(--border)", display:"flex", flexDirection:"column", height:480 }}>
          <div style={{ padding:"1rem 1rem 0.75rem", borderBottom:"1px solid var(--border)", fontWeight:700, fontFamily:"'Clash Display',sans-serif" }}>
            💬 Room Chat
          </div>
          <div style={{ flex:1, overflowY:"auto", padding:"0.75rem 1rem", display:"flex", flexDirection:"column", gap:"0.5rem" }}>
            {chat.map(m => (
              <div key={m.id} style={{ textAlign: m.sys ? "center" : m.mine ? "right" : "left" }}>
                {m.sys ? (
                  <span style={{ fontSize:"0.78rem", color:"var(--muted)", background:"var(--cream)", borderRadius:20, padding:"0.2rem 0.75rem" }}>{m.text}</span>
                ) : (
                  <div>
                    {!m.mine && <div style={{ fontSize:"0.72rem", color:"var(--muted)", marginBottom:"0.1rem" }}>{m.from}</div>}
                    <span style={{ background: m.mine ? "var(--accent)" : "var(--cream)", color: m.mine ? "#fff" : "var(--ink)", borderRadius:12, padding:"0.4rem 0.75rem", fontSize:"0.88rem", display:"inline-block", maxWidth:"90%", textAlign:"left" }}>{m.text}</span>
                  </div>
                )}
              </div>
            ))}
            <div ref={chatBottomRef} />
          </div>
          <div style={{ padding:"0.75rem", borderTop:"1px solid var(--border)", display:"flex", gap:"0.5rem" }}>
            <input value={chatInput} onChange={e => setChatInput(e.target.value)}
              onKeyDown={e => e.key==="Enter" && sendChat()}
              placeholder="Say something..." className="chat-input" style={{ flex:1, fontSize:"0.85rem" }} />
            <button className="chat-send" onClick={sendChat}>Send</button>
          </div>
        </div>
      </div>

      {/* Mobile layout fix */}
      <style>{`@media(max-width:768px){ .rooms-grid { grid-template-columns: 1fr !important; } }`}</style>
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
    { id:"friends",  label:"👫 Friends" },
    { id:"messages", label:"💬 Messages" },
    { id:"rooms",    label:"🎧 Rooms" },
    { id:"tools",    label:"⏱ Study Tools" },
    { id:"rating",   label:"⭐ Rate" },
    { id:"profile",  label:"👤 Profile" },
    ...(user?.is_admin ? [{ id:"admin", label:"⚙ Admin" }] : []),
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
              {user?.photo ? <img src={user.photo} alt="me" /> : (user?.initials||getInitials(user?.name))}
            </div>
            <button className="logout-btn" onClick={logout}>Logout</button>
          </div>
        </nav>
        <div className="main">
          {tab==="discover" && <Discover user={user} onMatch={handleMatch} onToast={showToast}/>}
          {tab==="friends"  && <Friends user={user} onToast={showToast} onMessage={m => { setTab("messages"); }} />}
          {tab==="messages" && <Messages user={user} onToast={showToast}/>}
          {tab==="rooms"    && <StudyRooms user={user} onToast={showToast}/>}
          {tab==="tools"    && <StudyTools onToast={showToast}/>}
          {tab==="rating"   && <Rating user={user} onToast={showToast}/>}
          {tab==="profile"  && <Profile user={user} setUser={setUser} onToast={showToast}/>}
          {tab==="admin"    && <Admin onToast={showToast}/>}
        </div>
      </div>
      {matchPopup && <MatchPopup match={matchPopup} onClose={handleMatchClose}/>}
      {toast && <Toast msg={toast.msg} type={toast.type} onClose={()=>setToast(null)}/>}
      <nav className="mobile-nav">
        {[
          { id:"discover", icon:"🔍", label:"Discover" },
          { id:"friends",  icon:"👫", label:"Friends" },
          { id:"messages", icon:"💬", label:"Messages" },
          { id:"rooms",    icon:"🎧", label:"Rooms" },
          { id:"tools",    icon:"⏱",  label:"Tools" },
          { id:"rating",   icon:"⭐", label:"Rate" },
          { id:"profile",  icon:"👤", label:"Profile" },
          ...(user?.is_admin ? [{ id:"admin", icon:"⚙", label:"Admin" }] : []),
        ].map(t => (
          <button key={t.id} className={`mobile-nav-btn ${tab===t.id?"active":""}`} onClick={()=>setTab(t.id)}>
            <span>{t.icon}</span>
            <span>{t.label}</span>
          </button>
        ))}
      </nav>
    </>
  );
}

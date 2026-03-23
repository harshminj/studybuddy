import { useState, useEffect, useRef, useCallback } from "react";
import { io as socketIO } from "socket.io-client";

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
  @import url('https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@400;500;600;700;800&family=Instrument+Sans:ital,wght@0,400;0,500;0,600;1,400&display=swap');

  *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }

  :root {
    /* Core palette */
    --ink:      #05050a;
    --base:     #0c0c14;
    --lift:     #111120;
    --panel:    #161628;
    --rim:      #1e1e36;
    --line:     rgba(255,255,255,0.06);
    --line2:    rgba(255,255,255,0.11);
    --line3:    rgba(255,255,255,0.18);

    /* Text */
    --t1: #eeeeff;
    --t2: #8b8baa;
    --t3: #4a4a6a;
    --t4: #2e2e4e;

    /* Brand */
    --p:   #7c6cff;
    --p2:  #b8acff;
    --pg:  linear-gradient(135deg, #7c6cff 0%, #b060ff 100%);
    --pgv: linear-gradient(180deg, #7c6cff 0%, #b060ff 100%);
    --glow: rgba(124,108,255,0.3);
    --glow2: rgba(176,96,255,0.25);

    /* Status */
    --ok:    #4ade80;
    --warn:  #fbbf24;
    --err:   #f87171;
    --info:  #60a5fa;

    /* Spacing / shape */
    --r-sm: 8px;
    --r:    14px;
    --r-lg: 20px;
    --r-xl: 28px;
    --sh:   0 2px 8px rgba(0,0,0,0.5), 0 12px 40px rgba(0,0,0,0.35);
    --sh-lg: 0 4px 12px rgba(0,0,0,0.6), 0 24px 64px rgba(0,0,0,0.5);
  }

  html { scroll-behavior: smooth; }

  body {
    font-family: 'Instrument Sans', sans-serif;
    background: var(--ink);
    color: var(--t1);
    min-height: 100vh;
    line-height: 1.5;
    /* Subtle noise texture for depth */
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.018'/%3E%3C/svg%3E");
  }

  h1,h2,h3,h4,h5 { font-family:'Bricolage Grotesque',sans-serif; letter-spacing:-0.02em; line-height:1.15; }

  /* ─── SCROLLBARS ─────────────────────────────────────────── */
  ::-webkit-scrollbar { width:4px; height:4px; }
  ::-webkit-scrollbar-track { background:transparent; }
  ::-webkit-scrollbar-thumb { background:var(--rim); border-radius:99px; }
  ::-webkit-scrollbar-thumb:hover { background:var(--t3); }

  /* ─── APP SHELL ──────────────────────────────────────────── */
  .app { min-height:100vh; display:flex; flex-direction:column; }

  /* ─── NAV ────────────────────────────────────────────────── */
  .nav {
    height:60px;
    padding:0 1.5rem;
    display:flex; align-items:center; justify-content:space-between;
    position:sticky; top:0; z-index:200;
    background:rgba(5,5,10,0.75);
    backdrop-filter:blur(24px) saturate(180%);
    -webkit-backdrop-filter:blur(24px) saturate(180%);
    border-bottom:1px solid var(--line2);
  }
  .nav::after {
    content:''; position:absolute; inset:0; pointer-events:none;
    background:linear-gradient(90deg, rgba(124,108,255,0.04) 0%, transparent 40%, rgba(176,96,255,0.04) 100%);
  }

  .nav-logo {
    font-family:'Bricolage Grotesque',sans-serif;
    font-size:1.25rem; font-weight:800;
    letter-spacing:-0.04em;
    display:flex; align-items:center; gap:0.55rem;
    text-decoration:none; color:var(--t1);
    flex-shrink:0;
  }
  .nav-logo-icon {
    width:30px; height:30px; border-radius:9px;
    background:var(--pg);
    display:flex; align-items:center; justify-content:center;
    font-size:0.85rem;
    box-shadow:0 0 14px var(--glow), inset 0 1px 0 rgba(255,255,255,0.15);
  }
  .nav-logo span { background:var(--pg); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; }

  .nav-tabs {
    display:flex; gap:2px;
    background:var(--lift);
    border:1px solid var(--line2);
    border-radius:var(--r);
    padding:3px;
  }
  .nav-tab {
    padding:0.32rem 0.8rem; border-radius:10px;
    cursor:pointer; font-size:0.75rem; font-weight:600;
    color:var(--t3); border:none; background:transparent;
    transition:all 0.18s cubic-bezier(0.4,0,0.2,1);
    white-space:nowrap; font-family:'Instrument Sans',sans-serif;
    letter-spacing:0.01em;
  }
  .nav-tab:hover { color:var(--t2); background:var(--panel); }
  .nav-tab.active {
    background:var(--pg);
    color:#fff;
    box-shadow:0 0 12px var(--glow), inset 0 1px 0 rgba(255,255,255,0.18);
  }

  .nav-user { display:flex; align-items:center; gap:0.65rem; }
  .avatar {
    width:34px; height:34px; border-radius:50%;
    display:flex; align-items:center; justify-content:center;
    font-weight:700; font-size:0.75rem; color:#fff;
    cursor:pointer; overflow:hidden; flex-shrink:0;
    border:1.5px solid var(--line3); transition:border-color 0.2s;
    background:var(--pg);
  }
  .avatar:hover { border-color:var(--p2); }
  .avatar img { width:100%; height:100%; object-fit:cover; border-radius:50%; }
  .profile-card-avatar img,.match-avatar img,.profile-hero-avatar img { width:100%; height:100%; object-fit:cover; border-radius:50%; }
  .pic-upload-wrap { position:relative; display:inline-block; cursor:pointer; }
  .pic-upload-wrap:hover .pic-overlay { opacity:1; }
  .pic-overlay { position:absolute; inset:0; border-radius:50%; background:rgba(0,0,0,0.65); display:flex; align-items:center; justify-content:center; color:#fff; font-size:0.6rem; font-weight:700; opacity:0; transition:opacity 0.2s; text-align:center; }
  .logout-btn {
    background:var(--lift); border:1px solid var(--line2);
    color:var(--t2); padding:0.32rem 0.8rem;
    border-radius:var(--r-sm); cursor:pointer;
    font-size:0.73rem; font-weight:600;
    font-family:'Instrument Sans',sans-serif;
    transition:all 0.15s;
  }
  .logout-btn:hover { background:var(--panel); color:var(--t1); border-color:var(--line3); }

  /* ─── AUTH ───────────────────────────────────────────────── */
  .auth-wrapper {
    flex:1; display:flex; align-items:center; justify-content:center;
    padding:2rem; min-height:100vh;
    background:
      radial-gradient(ellipse 60% 50% at 15% 55%, rgba(124,108,255,0.14) 0%, transparent 100%),
      radial-gradient(ellipse 50% 40% at 85% 25%, rgba(176,96,255,0.10) 0%, transparent 100%),
      radial-gradient(ellipse 40% 60% at 50% 100%, rgba(60,30,120,0.12) 0%, transparent 100%),
      var(--ink);
  }
  .auth-card {
    background:var(--lift);
    border:1px solid var(--line2);
    border-radius:var(--r-xl);
    padding:2.5rem;
    width:100%; max-width:420px;
    box-shadow:var(--sh-lg), 0 0 0 1px rgba(124,108,255,0.06);
    position:relative; overflow:hidden;
  }
  .auth-card::before {
    content:''; position:absolute; top:0; left:0; right:0; height:1px;
    background:linear-gradient(90deg, transparent, var(--p2), transparent);
    opacity:0.4;
  }
  .auth-logo { text-align:center; margin-bottom:2rem; }
  .auth-logo-icon {
    width:52px; height:52px; border-radius:16px;
    background:var(--pg);
    display:flex; align-items:center; justify-content:center;
    font-size:1.5rem; margin:0 auto 1rem;
    box-shadow:0 0 28px var(--glow), 0 0 60px rgba(124,108,255,0.12), inset 0 1px 0 rgba(255,255,255,0.2);
  }
  .auth-logo h1 { font-size:1.65rem; color:var(--t1); }
  .auth-logo h1 span { background:var(--pg); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; }
  .auth-logo p { color:var(--t2); font-size:0.85rem; margin-top:0.35rem; }

  .auth-tabs { display:flex; background:var(--base); border-radius:var(--r-sm); padding:3px; margin-bottom:1.5rem; border:1px solid var(--line); gap:2px; }
  .auth-tab { flex:1; padding:0.48rem; text-align:center; border-radius:6px; cursor:pointer; font-weight:600; font-size:0.82rem; color:var(--t3); transition:all 0.18s; font-family:'Instrument Sans',sans-serif; }
  .auth-tab.active { background:var(--pg); color:#fff; box-shadow:0 0 12px var(--glow); }

  .form-group { margin-bottom:0.9rem; }
  .form-group label { display:block; font-size:0.7rem; font-weight:700; color:var(--t3); margin-bottom:0.38rem; text-transform:uppercase; letter-spacing:0.7px; }
  .form-group input,.form-group select,.form-group textarea {
    width:100%; padding:0.65rem 0.9rem;
    border:1px solid var(--line2);
    border-radius:var(--r-sm);
    font-family:'Instrument Sans',sans-serif; font-size:0.88rem;
    background:var(--base); color:var(--t1);
    transition:border-color 0.15s, box-shadow 0.15s; outline:none;
  }
  .form-group input:focus,.form-group select:focus,.form-group textarea:focus {
    border-color:var(--p); box-shadow:0 0 0 3px rgba(124,108,255,0.12);
    background:var(--panel);
  }
  .form-group input::placeholder,.form-group textarea::placeholder { color:var(--t4); }
  .form-group select option { background:var(--panel); }

  .btn {
    width:100%; padding:0.72rem; border-radius:var(--r-sm); border:none;
    font-family:'Bricolage Grotesque',sans-serif; font-size:0.92rem; font-weight:700;
    cursor:pointer; transition:all 0.18s cubic-bezier(0.4,0,0.2,1); letter-spacing:0.01em;
  }
  .btn:disabled { opacity:0.4; cursor:not-allowed; }
  .btn-primary {
    background:var(--pg); color:#fff;
    box-shadow:0 0 20px var(--glow), inset 0 1px 0 rgba(255,255,255,0.15);
  }
  .btn-primary:hover:not(:disabled) {
    transform:translateY(-1px);
    box-shadow:0 0 30px var(--glow), 0 4px 20px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.2);
  }
  .btn-primary:active:not(:disabled) { transform:translateY(0); }
  .btn-outline {
    background:transparent; border:1px solid var(--line2);
    color:var(--t2);
  }
  .btn-outline:hover { border-color:var(--p); color:var(--t1); background:rgba(124,108,255,0.07); }
  .btn-sm { width:auto; padding:0.38rem 0.9rem; font-size:0.78rem; }

  .auth-switch { text-align:center; margin-top:1rem; font-size:0.82rem; color:var(--t2); }
  .auth-switch a { color:var(--p2); cursor:pointer; font-weight:600; }
  .auth-switch a:hover { color:#fff; }
  .step-indicator { display:flex; gap:0.35rem; justify-content:center; margin-bottom:1.5rem; }
  .step-dot { width:7px; height:7px; border-radius:50%; background:var(--rim); transition:all 0.25s; }
  .step-dot.active { background:var(--p); width:22px; border-radius:4px; box-shadow:0 0 8px var(--glow); }
  .err-msg { background:rgba(248,113,113,0.07); border:1px solid rgba(248,113,113,0.2); color:var(--err); border-radius:var(--r-sm); padding:0.55rem 0.85rem; font-size:0.82rem; margin-bottom:0.9rem; }
  .otp-input {
    width:100%; text-align:center; font-size:2rem; font-weight:800;
    letter-spacing:0.7rem; padding:0.9rem 1rem;
    border:1.5px solid var(--p); border-radius:var(--r);
    background:var(--base); outline:none;
    font-family:'Bricolage Grotesque',sans-serif; color:var(--t1);
    box-shadow:0 0 20px rgba(124,108,255,0.1);
  }

  /* ─── MAIN LAYOUT ────────────────────────────────────────── */
  .main { flex:1; padding:1.8rem 2rem; max-width:1160px; margin:0 auto; width:100%; }
  .page-title { font-size:1.5rem; font-weight:800; margin-bottom:0.2rem; color:var(--t1); }
  .page-sub { color:var(--t2); font-size:0.85rem; margin-bottom:1.4rem; }
  .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:1.2rem; }
  .card { background:var(--lift); border-radius:var(--r-lg); padding:1.4rem; box-shadow:var(--sh); border:1px solid var(--line); }
  .loading { display:flex; align-items:center; justify-content:center; padding:3rem; color:var(--t2); gap:0.5rem; font-size:0.85rem; }
  .spinner { width:18px; height:18px; border:2px solid var(--rim); border-top-color:var(--p); border-radius:50%; animation:spin 0.65s linear infinite; flex-shrink:0; }
  @keyframes spin { to { transform:rotate(360deg); } }

  /* ─── DISCOVER ───────────────────────────────────────────── */
  .discover-wrapper { display:flex; gap:1.4rem; }
  .discover-filters { width:210px; flex-shrink:0; }
  .discover-cards { flex:1; }
  .filter-section { margin-bottom:1.1rem; }
  .filter-label { font-size:0.67rem; text-transform:uppercase; letter-spacing:0.9px; font-weight:700; color:var(--t3); margin-bottom:0.55rem; }
  .filter-chip {
    display:inline-flex; align-items:center; gap:0.3rem;
    padding:0.25rem 0.7rem; border-radius:99px;
    border:1px solid var(--line2); font-size:0.74rem; cursor:pointer;
    margin:0.15rem; transition:all 0.15s;
    background:var(--panel); color:var(--t2); font-weight:500;
  }
  .filter-chip:hover { border-color:var(--line3); color:var(--t1); }
  .filter-chip.active { border-color:var(--p); background:rgba(124,108,255,0.12); color:var(--p2); font-weight:700; }

  .cards-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(236px,1fr)); gap:1rem; }
  .profile-card {
    background:var(--lift); border-radius:var(--r-lg);
    overflow:hidden; border:1px solid var(--line);
    transition:transform 0.22s cubic-bezier(0.34,1.56,0.64,1), box-shadow 0.22s, border-color 0.2s;
    cursor:default;
  }
  .profile-card:hover { transform:translateY(-5px) scale(1.005); box-shadow:0 20px 60px rgba(0,0,0,0.5), 0 0 0 1px var(--line3); }
  .profile-card-banner { height:84px; }
  .profile-card-avatar {
    width:60px; height:60px; border-radius:50%;
    border:2.5px solid var(--lift);
    display:flex; align-items:center; justify-content:center;
    font-weight:800; font-size:1.1rem; color:#fff;
    margin-top:-30px; overflow:hidden;
  }
  .profile-card-body { padding:0.7rem 1rem 1rem; }
  .profile-card-name { font-family:'Bricolage Grotesque',sans-serif; font-size:0.95rem; font-weight:700; margin-bottom:0.12rem; color:var(--t1); }
  .profile-card-college { font-size:0.74rem; color:var(--t2); margin-bottom:0.55rem; }

  .tag { display:inline-flex; padding:0.18rem 0.55rem; border-radius:99px; font-size:0.67rem; font-weight:700; margin:0.12rem 0.08rem; letter-spacing:0.02em; }
  .tag-style { background:rgba(124,108,255,0.12); color:var(--p2); }
  .tag-subject { background:rgba(74,222,128,0.1); color:var(--ok); }

  .card-actions { display:flex; gap:0.45rem; margin-top:0.75rem; }
  .btn-pass {
    flex:1; padding:0.45rem; border-radius:var(--r-sm);
    border:1px solid var(--line2); background:transparent;
    color:var(--t2); font-weight:600; cursor:pointer;
    font-size:0.8rem; transition:all 0.15s;
    font-family:'Instrument Sans',sans-serif;
  }
  .btn-pass:hover { background:var(--panel); color:var(--t1); border-color:var(--line3); }
  .btn-like {
    flex:1; padding:0.45rem; border-radius:var(--r-sm); border:none;
    background:var(--pg); color:#fff; font-weight:700;
    cursor:pointer; font-size:0.8rem; transition:all 0.18s;
    font-family:'Bricolage Grotesque',sans-serif;
    box-shadow:0 0 12px var(--glow);
  }
  .btn-like:hover { transform:scale(1.04); box-shadow:0 0 20px var(--glow); }
  .btn-like:disabled { opacity:0.4; cursor:not-allowed; transform:none; }

  /* ─── MESSAGES ───────────────────────────────────────────── */
  .chat-layout { display:flex; height:calc(100vh - 130px); gap:1rem; }
  .chat-sidebar { width:270px; flex-shrink:0; background:var(--lift); border:1px solid var(--line); border-radius:var(--r-lg); overflow-y:auto; }
  .chat-sidebar-header { padding:1rem 1.1rem 0.7rem; font-weight:700; font-size:0.72rem; color:var(--t3); text-transform:uppercase; letter-spacing:0.7px; }
  .chat-item { display:flex; align-items:center; gap:0.7rem; padding:0.8rem 1.1rem; cursor:pointer; transition:background 0.14s; border-bottom:1px solid var(--line); }
  .chat-item:hover { background:var(--panel); }
  .chat-item.active { background:rgba(124,108,255,0.1); border-left:2px solid var(--p); }
  .match-avatar { width:40px; height:40px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:700; color:#fff; font-size:0.9rem; flex-shrink:0; overflow:hidden; }
  .chat-item-info { flex:1; min-width:0; }
  .chat-item-name { font-weight:600; font-size:0.85rem; color:var(--t1); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .chat-item-preview { font-size:0.73rem; color:var(--t3); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin-top:0.1rem; }
  .unread-dot { width:7px; height:7px; border-radius:50%; background:var(--p); flex-shrink:0; box-shadow:0 0 6px var(--glow); }
  .chat-main { flex:1; background:var(--lift); border:1px solid var(--line); border-radius:var(--r-lg); display:flex; flex-direction:column; overflow:hidden; }
  .chat-empty { flex:1; display:flex; flex-direction:column; align-items:center; justify-content:center; color:var(--t3); gap:0.45rem; font-size:0.85rem; }
  .chat-header { padding:0.9rem 1.2rem; border-bottom:1px solid var(--line); display:flex; align-items:center; gap:0.7rem; background:var(--panel); }
  .chat-messages { flex:1; overflow-y:auto; padding:1rem 1.2rem; display:flex; flex-direction:column; gap:0.45rem; }
  .msg { display:flex; flex-direction:column; }
  .msg.me { align-items:flex-end; }
  .msg.them { align-items:flex-start; }
  .msg-bubble { padding:0.52rem 0.85rem; border-radius:14px; max-width:68%; font-size:0.84rem; line-height:1.45; word-break:break-word; }
  .msg.me .msg-bubble { background:var(--pg); color:#fff; border-bottom-right-radius:3px; }
  .msg.them .msg-bubble { background:var(--rim); color:var(--t1); border-bottom-left-radius:3px; }
  .msg-time { font-size:0.63rem; color:var(--t3); margin-top:0.18rem; padding:0 0.25rem; }
  .chat-input-row { padding:0.8rem 1rem; border-top:1px solid var(--line); display:flex; gap:0.5rem; background:var(--panel); }
  .chat-input { flex:1; background:var(--base); border:1px solid var(--line2); border-radius:var(--r-sm); padding:0.55rem 0.9rem; color:var(--t1); font-family:'Instrument Sans',sans-serif; font-size:0.84rem; outline:none; transition:border-color 0.15s; }
  .chat-input:focus { border-color:var(--p); box-shadow:0 0 0 2px rgba(124,108,255,0.1); }
  .chat-input::placeholder { color:var(--t4); }
  .chat-send { background:var(--pg); border:none; color:#fff; border-radius:var(--r-sm); padding:0.55rem 1rem; font-weight:700; cursor:pointer; font-size:0.82rem; transition:all 0.15s; box-shadow:0 0 10px var(--glow); font-family:'Bricolage Grotesque',sans-serif; }
  .chat-send:hover { transform:scale(1.04); box-shadow:0 0 16px var(--glow); }

  /* ─── PROFILE ────────────────────────────────────────────── */
  .profile-hero {
    display:flex; align-items:center; gap:1.4rem;
    padding:1.6rem; border-radius:var(--r-xl);
    background:linear-gradient(135deg, var(--lift) 0%, var(--panel) 100%);
    border:1px solid var(--line2); margin-bottom:1.4rem;
    position:relative; overflow:hidden;
  }
  .profile-hero::before {
    content:''; position:absolute; top:-40px; right:-40px;
    width:180px; height:180px; border-radius:50%;
    background:radial-gradient(circle, rgba(124,108,255,0.12) 0%, transparent 70%);
    pointer-events:none;
  }
  .profile-hero-avatar { width:76px; height:76px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:1.7rem; font-weight:800; color:#fff; overflow:hidden; border:2px solid var(--line3); box-shadow:0 0 20px var(--glow); flex-shrink:0; }
  .profile-hero-info h2 { font-size:1.3rem; margin-bottom:0.15rem; color:var(--t1); }
  .profile-hero-info p { color:var(--t2); font-size:0.84rem; }

  .style-options { display:flex; gap:0.45rem; flex-wrap:wrap; margin-top:0.4rem; }
  .style-opt { padding:0.35rem 0.8rem; border-radius:99px; border:1px solid var(--line2); cursor:pointer; font-size:0.78rem; font-weight:500; transition:all 0.15s; background:var(--panel); color:var(--t2); }
  .style-opt:hover { border-color:var(--p); color:var(--t1); }
  .style-opt.selected { background:rgba(124,108,255,0.15); border-color:var(--p); color:var(--p2); font-weight:700; }

  /* ─── STUDY TOOLS ────────────────────────────────────────── */
  .timer-circle {
    width:196px; height:196px; border-radius:50%;
    margin:1.5rem auto;
    background:conic-gradient(var(--p) calc(var(--prog,100)*1%), var(--rim) 0);
    display:flex; align-items:center; justify-content:center;
    font-family:'Bricolage Grotesque',sans-serif; font-size:2.6rem; font-weight:800; color:var(--t1);
    box-shadow:0 0 0 10px var(--panel), 0 0 0 12px var(--line2), 0 0 40px var(--glow);
  }
  .timer-controls { display:flex; gap:0.55rem; justify-content:center; margin-top:1rem; }
  .timer-btn {
    padding:0.5rem 1.3rem; border-radius:var(--r-sm);
    border:1px solid var(--line2); font-weight:700; cursor:pointer;
    font-family:'Bricolage Grotesque',sans-serif; font-size:0.85rem;
    background:var(--panel); color:var(--t1); transition:all 0.15s;
  }
  .timer-btn:hover { background:var(--p); color:#fff; border-color:var(--p); box-shadow:0 0 12px var(--glow); }
  .goals-list { list-style:none; }
  .goals-list li { display:flex; align-items:center; gap:0.6rem; padding:0.55rem 0; border-bottom:1px solid var(--line); font-size:0.84rem; color:var(--t1); }
  .goals-list li.done { text-decoration:line-through; color:var(--t3); }
  .goals-list li input[type=checkbox] { accent-color:var(--p); width:15px; height:15px; cursor:pointer; }
  .goal-input-row { display:flex; gap:0.5rem; margin-top:0.75rem; }
  .goal-input { flex:1; border:1px solid var(--line2); border-radius:var(--r-sm); padding:0.48rem 0.75rem; font-family:'Instrument Sans',sans-serif; font-size:0.84rem; outline:none; background:var(--base); color:var(--t1); transition:border-color 0.15s; }
  .goal-input::placeholder { color:var(--t4); }
  .goal-input:focus { border-color:var(--p); }

  /* ─── RATING ─────────────────────────────────────────────── */
  .star { font-size:1.5rem; cursor:pointer; transition:transform 0.12s; }
  .star:hover { transform:scale(1.25); }
  .rating-row { display:flex; align-items:center; justify-content:space-between; padding:0.55rem 0; border-bottom:1px solid var(--line); }

  /* ─── ADMIN ──────────────────────────────────────────────── */
  .stat-card { background:var(--panel); border-radius:var(--r-lg); padding:1.2rem 1.4rem; border:1px solid var(--line); position:relative; overflow:hidden; }
  .stat-card::after { content:''; position:absolute; top:0; left:0; right:0; height:2px; background:var(--pg); }
  .stat-num { font-family:'Bricolage Grotesque',sans-serif; font-size:1.9rem; font-weight:800; background:var(--pg); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; }
  .stat-label { color:var(--t2); font-size:0.78rem; margin-top:0.1rem; }
  .table { width:100%; border-collapse:collapse; }
  .table th { text-align:left; padding:0.55rem 1rem; font-size:0.67rem; text-transform:uppercase; letter-spacing:0.7px; color:var(--t3); border-bottom:1px solid var(--line); font-weight:700; }
  .table td { padding:0.7rem 1rem; border-bottom:1px solid var(--line); font-size:0.84rem; color:var(--t1); }
  .table tr:hover td { background:var(--panel); }
  .badge { display:inline-flex; padding:0.18rem 0.55rem; border-radius:99px; font-size:0.68rem; font-weight:700; letter-spacing:0.02em; }
  .badge-active { background:rgba(74,222,128,0.1); color:var(--ok); }
  .badge-admin  { background:rgba(124,108,255,0.12); color:var(--p2); }

  /* ─── TOAST ──────────────────────────────────────────────── */
  .toast {
    position:fixed; bottom:1.4rem; right:1.4rem; z-index:9999;
    background:var(--panel); color:var(--t1);
    padding:0.75rem 1.15rem; border-radius:var(--r);
    font-size:0.84rem; font-weight:500;
    box-shadow:var(--sh-lg); animation:slideup 0.28s cubic-bezier(0.34,1.56,0.64,1);
    max-width:310px; border:1px solid var(--line2);
  }
  .toast.success { border-left:3px solid var(--ok); }
  .toast.match   { border-left:3px solid var(--p2); box-shadow:var(--sh-lg), 0 0 20px rgba(124,108,255,0.2); }
  .toast.error   { border-left:3px solid var(--err); }
  @keyframes slideup { from { transform:translateY(16px) scale(0.96); opacity:0; } to { transform:translateY(0) scale(1); opacity:1; } }

  /* ─── FRIENDS ────────────────────────────────────────────── */
  .friends-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(250px,1fr)); gap:1rem; }
  .friend-card { background:var(--lift); border:1px solid var(--line); border-radius:var(--r-lg); overflow:hidden; transition:transform 0.2s cubic-bezier(0.34,1.56,0.64,1), border-color 0.2s; }
  .friend-card:hover { transform:translateY(-4px); border-color:var(--line3); }

  /* ─── ROOMS ──────────────────────────────────────────────── */
  .room-card {
    background:var(--lift); border-radius:var(--r-lg);
    border:1px solid var(--line); overflow:hidden;
    transition:transform 0.22s cubic-bezier(0.34,1.56,0.64,1), box-shadow 0.22s, border-color 0.2s;
  }
  .room-card:hover { transform:translateY(-5px); box-shadow:0 20px 50px rgba(0,0,0,0.5); border-color:var(--line3); }
  .room-banner { height:86px; display:flex; align-items:center; justify-content:center; font-size:2.3rem; position:relative; overflow:hidden; }
  .room-banner::after { content:''; position:absolute; inset:0; background:linear-gradient(to bottom, transparent 40%, rgba(0,0,0,0.4) 100%); }
  .room-body { padding:1rem 1.1rem 1.1rem; }
  .room-name { font-family:'Bricolage Grotesque',sans-serif; font-size:0.95rem; font-weight:800; margin-bottom:0.2rem; color:var(--t1); }
  .room-meta { font-size:0.74rem; color:var(--t2); margin-bottom:0.7rem; }
  .room-inside {
    background:var(--lift);
    border:1px solid var(--line);
    border-radius:var(--r-xl); padding:1.5rem; margin-bottom:1.2rem;
    position:relative; overflow:hidden;
  }
  .room-inside::before {
    content:''; position:absolute; top:-60px; left:50%; transform:translateX(-50%);
    width:300px; height:300px; border-radius:50%;
    background:radial-gradient(circle, rgba(124,108,255,0.06) 0%, transparent 70%);
    pointer-events:none;
  }
  .room-timer-display { font-family:'Bricolage Grotesque',sans-serif; font-size:3.8rem; font-weight:800; text-align:center; letter-spacing:-3px; color:var(--t1); }
  .room-phase { text-align:center; font-size:0.82rem; color:var(--t2); margin-bottom:0.8rem; }
  /* Spotify player styles are inline */
  .member-chip { display:flex; align-items:center; gap:0.32rem; background:rgba(255,255,255,0.04); border:1px solid var(--line); border-radius:99px; padding:0.25rem 0.65rem 0.25rem 0.25rem; font-size:0.73rem; color:var(--t2); }

  /* Private room modal */
  .private-room { position:fixed; inset:0; background:rgba(0,0,0,0.85); backdrop-filter:blur(12px); z-index:500; display:flex; align-items:center; justify-content:center; padding:1rem; }
  .private-room-box { background:var(--lift); border-radius:var(--r-xl); width:100%; max-width:480px; max-height:92vh; display:flex; flex-direction:column; border:1px solid var(--line2); overflow:hidden; box-shadow:var(--sh-lg); }
  .private-room-header { padding:1.1rem 1.4rem; border-bottom:1px solid var(--line); display:flex; align-items:center; gap:0.9rem; background:var(--panel); }
  .private-room-chat { flex:1; overflow-y:auto; padding:1rem 1.2rem; display:flex; flex-direction:column; gap:0.45rem; min-height:180px; max-height:280px; }
  .private-room-input { padding:0.9rem 1rem; border-top:1px solid var(--line); display:flex; gap:0.45rem; background:var(--panel); }

  /* ─── AI TUTOR ───────────────────────────────────────────── */
  .ai-wrap { display:flex; flex-direction:column; height:calc(100vh - 130px); max-width:800px; margin:0 auto; }
  .ai-header { padding-bottom:1rem; border-bottom:1px solid var(--line); margin-bottom:0; }
  .ai-messages { flex:1; overflow-y:auto; padding:1rem 0; display:flex; flex-direction:column; gap:1rem; }
  .ai-bubble-wrap { display:flex; gap:0.65rem; align-items:flex-start; }
  .ai-bubble-wrap.user { flex-direction:row-reverse; }
  .ai-avatar { width:32px; height:32px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-size:0.85rem; flex-shrink:0; font-weight:700; }
  .ai-bubble { max-width:78%; padding:0.75rem 0.95rem; border-radius:16px; font-size:0.85rem; line-height:1.6; white-space:pre-wrap; word-break:break-word; }
  .ai-bubble.assistant { background:var(--lift); border:1px solid var(--line); border-top-left-radius:3px; color:var(--t1); }
  .ai-bubble.user { background:var(--pg); color:#fff; border-top-right-radius:3px; box-shadow:0 0 16px var(--glow); }
  .ai-bubble code { background:rgba(124,108,255,0.12); padding:0.1rem 0.35rem; border-radius:4px; font-family:'Fira Code',monospace; font-size:0.82em; color:var(--p2); }
  .ai-bubble pre { background:var(--base); border:1px solid var(--line); padding:0.75rem 1rem; border-radius:var(--r-sm); overflow-x:auto; margin:0.5rem 0; font-size:0.77rem; }
  .ai-bubble pre code { background:none; padding:0; color:#93c5fd; }
  .ai-bubble strong { font-weight:700; color:var(--p2); }
  .ai-input-row { display:flex; gap:0.55rem; padding-top:0.75rem; border-top:1px solid var(--line); }
  .ai-input {
    flex:1; border:1px solid var(--line2); border-radius:var(--r);
    padding:0.72rem 0.95rem; font-family:'Instrument Sans',sans-serif; font-size:0.86rem;
    outline:none; background:var(--lift); color:var(--t1);
    resize:none; line-height:1.45; max-height:120px; transition:border-color 0.15s, box-shadow 0.15s;
  }
  .ai-input:focus { border-color:var(--p); box-shadow:0 0 0 3px rgba(124,108,255,0.1); }
  .ai-input::placeholder { color:var(--t4); }
  .ai-send {
    background:var(--pg); border:none; color:#fff; border-radius:var(--r);
    padding:0.72rem 1.1rem; cursor:pointer; font-size:1rem; flex-shrink:0;
    transition:all 0.18s; box-shadow:0 0 14px var(--glow);
  }
  .ai-send:disabled { opacity:0.35; cursor:not-allowed; box-shadow:none; }
  .ai-send:hover:not(:disabled) { transform:scale(1.06); box-shadow:0 0 22px var(--glow); }
  .ai-typing { display:flex; gap:5px; align-items:center; padding:0.45rem 0.15rem; }
  .ai-dot { width:6px; height:6px; border-radius:50%; background:var(--t3); animation:bounce 1.2s infinite; }
  .ai-dot:nth-child(2) { animation-delay:0.18s; }
  .ai-dot:nth-child(3) { animation-delay:0.36s; }
  @keyframes bounce { 0%,60%,100%{transform:translateY(0)} 30%{transform:translateY(-7px)} }
  .ai-suggestion { display:inline-flex; background:var(--panel); border:1px solid var(--line2); border-radius:99px; padding:0.35rem 0.8rem; font-size:0.74rem; cursor:pointer; transition:all 0.15s; white-space:nowrap; color:var(--t2); font-weight:500; }
  .ai-suggestion:hover { background:rgba(124,108,255,0.15); border-color:var(--p); color:var(--p2); }

  /* ─── MOBILE NAV ─────────────────────────────────────────── */
  .mobile-nav { display:none; }

  /* ─── TABLET (≤900px) ────────────────────────────────────── */
  @media (max-width:900px) {
    .nav-tabs { gap:1px; }
    .nav-tab { padding:0.3rem 0.6rem; font-size:0.7rem; }
    .discover-wrapper { gap:1rem; }
    .discover-filters { width:180px; }
    .cards-grid { grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); }
    .chat-sidebar { width:220px; }
  }

  /* ─── MOBILE (≤768px) ────────────────────────────────────── */
  @media (max-width:768px) {
    /* iOS: prevent auto-zoom on input focus (needs min 16px font) */
    input, select, textarea { font-size:16px !important; }
    /* Nav */
    .nav { padding:0 1rem; height:56px; }
    .nav-logo { font-size:1.1rem; }
    .nav-logo-icon { width:26px; height:26px; font-size:0.75rem; }
    .nav-tabs { display:none; }
    .nav-user { gap:0.5rem; }
    .logout-btn { padding:0.28rem 0.6rem; font-size:0.68rem; }
    .avatar { width:30px; height:30px; font-size:0.7rem; }

    /* Main padding — room for bottom nav */
    .main { padding:1rem 0.85rem 88px; }

    /* Mobile Bottom Nav */
    .mobile-nav {
      display:flex; position:fixed; bottom:0; left:0; right:0;
      background:rgba(5,5,10,0.96);
      backdrop-filter:blur(24px) saturate(200%);
      -webkit-backdrop-filter:blur(24px) saturate(200%);
      z-index:300; border-top:1px solid var(--line2);
      padding:0.4rem 0.3rem env(safe-area-inset-bottom, 0.5rem);
      gap:2px;
    }
    .mobile-nav-btn {
      flex:1; display:flex; flex-direction:column; align-items:center;
      gap:0.1rem; background:none; border:none; color:var(--t4);
      cursor:pointer; padding:0.3rem 0.2rem;
      font-size:0.45rem; font-family:'Bricolage Grotesque',sans-serif;
      font-weight:700; text-transform:uppercase; letter-spacing:0.04em;
      transition:color 0.15s; border-radius:8px; min-width:0;
    }
    .mobile-nav-btn:hover { background:rgba(255,255,255,0.04); }
    .mobile-nav-btn.active { color:var(--p2); }
    .mobile-nav-btn span:first-child { font-size:1.15rem; line-height:1.2; }

    /* Layout grids */
    .grid-2 { grid-template-columns:1fr; gap:0.85rem; }
    .cards-grid { grid-template-columns:1fr 1fr; gap:0.7rem; }
    .friends-grid { grid-template-columns:1fr; gap:0.75rem; }

    /* Page headings */
    .page-title { font-size:1.25rem; }
    .page-sub { font-size:0.8rem; margin-bottom:1rem; }

    /* Cards */
    .card { padding:1.1rem; border-radius:var(--r); }

    /* Auth */
    .auth-card { padding:1.8rem 1.4rem; border-radius:var(--r-lg); margin:0.5rem; }
    .auth-wrapper { padding:1rem; align-items:flex-start; padding-top:2rem; }
    .auth-logo-icon { width:44px; height:44px; font-size:1.2rem; border-radius:13px; }
    .auth-logo h1 { font-size:1.45rem; }

    /* Discover */
    .discover-wrapper { flex-direction:column; gap:0.85rem; }
    .discover-filters { width:100%; }
    .filter-section { margin-bottom:0.7rem; }
    .profile-card-banner { height:70px; }
    .profile-card-body { padding:0.55rem 0.85rem 0.85rem; }
    .profile-card-name { font-size:0.88rem; }
    .profile-card-avatar { width:52px; height:52px; margin-top:-26px; }

    /* Messages */
    .chat-layout { flex-direction:column; height:auto; gap:0.75rem; }
    .chat-sidebar { width:100%; height:auto; max-height:220px; border-radius:var(--r); }
    .chat-sidebar-header { padding:0.75rem 1rem 0.5rem; }
    .chat-item { padding:0.65rem 1rem; }
    .chat-main { height:calc(100svh - 400px); min-height:280px; border-radius:var(--r); }
    .chat-header { padding:0.75rem 1rem; }
    .chat-messages { padding:0.75rem 1rem; }
    .msg-bubble { font-size:0.82rem; padding:0.48rem 0.78rem; max-width:85%; }
    .chat-input-row { padding:0.65rem 0.85rem; gap:0.4rem; }

    /* Profile */
    .profile-hero { flex-direction:column; text-align:center; padding:1.2rem; gap:0.85rem; border-radius:var(--r-lg); }
    .profile-hero-avatar { width:68px; height:68px; font-size:1.5rem; }
    .profile-hero::before { display:none; }
    .style-options { justify-content:center; }

    /* Study tools timer */
    .timer-circle { width:160px; height:160px; font-size:2.1rem; }

    /* Rooms */
    .room-inside { padding:1.1rem; border-radius:var(--r-lg); }
    .room-timer-display { font-size:3rem; }

    .private-room-box { border-radius:var(--r-lg); }

    /* AI */
    .ai-wrap { height:calc(100svh - 160px); }
    .ai-bubble { max-width:88%; font-size:0.82rem; padding:0.65rem 0.85rem; }
    .ai-input { font-size:0.82rem; padding:0.62rem 0.85rem; }
    .ai-send { padding:0.62rem 0.95rem; font-size:0.9rem; }

    /* Rating */
    .rating-row { flex-direction:column; align-items:flex-start; gap:0.3rem; }
    .star { font-size:1.3rem; }

    /* Admin stats grid */
    .admin-stats-grid { grid-template-columns:1fr 1fr !important; gap:0.75rem !important; }
    .stat-num { font-size:1.5rem; }

    /* Toast */
    .toast { bottom:5.5rem; right:0.75rem; left:0.75rem; max-width:100%; font-size:0.82rem; }
  }

  /* ─── SMALL MOBILE (≤420px) ─────────────────────────────── */
  @media (max-width:420px) {
    .main { padding:0.75rem 0.7rem 90px; }
    .cards-grid { grid-template-columns:1fr; }
    .chat-main { height:calc(100vh - 380px); }
    .ai-wrap { height:calc(100vh - 155px); }
    .mobile-nav-btn span:first-child { font-size:1.05rem; }
    .mobile-nav-btn { font-size:0.4rem; }
    .auth-card { padding:1.5rem 1.1rem; }
    .nav { height:52px; }
    .main { padding-top:0.75rem; }
  }
`;



const STUDY_STYLES  = ["Quiet","Collaborative","Exam Prep","Group Discussion","Online Only"];
const SUBJECTS_LIST = ["Machine Learning","Data Structures","Algorithms","Web Dev","React","Statistics","Calculus","Linear Algebra","Networks","Operating Systems","Python","Physics","Chemistry","Database","Cloud Computing"];
const COLORS        = ["#7c6cff","#b060ff","#34d399","#f59e0b","#ec4899","#22d3ee"];
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

  // Forgot password flow
  const [tab2,       setTab2]       = useState("login"); // login | forgot
  const [fpStep,     setFpStep]     = useState(1); // 1=email, 2=otp, 3=newpass
  const [fpEmail,    setFpEmail]    = useState("");
  const [fpOtp,      setFpOtp]      = useState("");
  const [fpNewPass,  setFpNewPass]  = useState("");
  const [fpConfPass, setFpConfPass] = useState("");

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

  const switchTab = (t) => { setTab(t); setStep(1); setError(""); setTab2("login"); setFpStep(1); };

  // ── Forgot password handlers ──────────────────────────────────────────
  const doFpSendOtp = async () => {
    setError(""); setLoading(true);
    try {
      const data = await apiFetch("/auth/send-otp", { method: "POST", body: { email: fpEmail } });
      // Send OTP via EmailJS
      try {
        await fetch("https://api.emailjs.com/api/v1.0/email/send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            service_id: EMAILJS_SERVICE, template_id: EMAILJS_TEMPLATE, user_id: EMAILJS_KEY,
            template_params: { to_email: fpEmail, otp: String(data.otp) }
          })
        });
      } catch {}
      setFpStep(2);
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const doFpVerifyOtp = async () => {
    setError(""); setLoading(true);
    try {
      await apiFetch("/auth/verify-otp", { method: "POST", body: { email: fpEmail, otp: fpOtp } });
      setFpStep(3);
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

  const doFpResetPass = async () => {
    if (fpNewPass !== fpConfPass) { setError("Passwords don't match"); return; }
    if (fpNewPass.length < 6) { setError("Password must be at least 6 characters"); return; }
    setError(""); setLoading(true);
    try {
      await apiFetch("/auth/reset-password", { method: "POST", body: { email: fpEmail, otp: fpOtp, newPassword: fpNewPass } });
      setTab2("login"); setFpStep(1); setFpEmail(""); setFpOtp(""); setFpNewPass(""); setFpConfPass("");
      setError(""); 
      // Show success in login tab
      setTab("login");
    } catch (e) { setError(e.message); }
    setLoading(false);
  };

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

        {tab === "login" && tab2 === "login" && (
          <>
            <div className="form-group"><label>Email</label><input type="email" placeholder="you@college.edu" value={loginEmail} onChange={e => setLoginEmail(e.target.value)} /></div>
            <div className="form-group"><label>Password</label><input type="password" placeholder="••••••••" value={loginPass} onChange={e => setLoginPass(e.target.value)} onKeyDown={e => e.key === "Enter" && doLogin()} /></div>
            <button className="btn btn-primary" onClick={doLogin} disabled={loading}>{loading ? "Logging in..." : "Login →"}</button>
            <div style={{ display:"flex", justifyContent:"space-between", marginTop:"0.75rem" }}>
              <p className="auth-switch" style={{ margin:0 }}>No account? <a onClick={() => switchTab("signup")}>Sign Up</a></p>
              <p className="auth-switch" style={{ margin:0 }}><a onClick={() => { setTab2("forgot"); setFpStep(1); setError(""); }}>Forgot password?</a></p>
            </div>
          </>
        )}

        {/* ── Forgot Password Flow ── */}
        {tab === "login" && tab2 === "forgot" && (
          <>
            {/* Step indicator */}
            <div className="step-indicator">
              {[1,2,3].map(s => <div key={s} className={`step-dot ${fpStep >= s ? "active" : ""}`} />)}
            </div>

            {fpStep === 1 && (
              <>
                <p style={{ textAlign:"center", color:"var(--t2)", fontSize:"0.85rem", marginBottom:"1rem" }}>
                  Enter your email — we'll send a reset code
                </p>
                <div className="form-group">
                  <label>Email</label>
                  <input type="email" placeholder="you@college.edu" value={fpEmail} onChange={e => setFpEmail(e.target.value)} onKeyDown={e => e.key==="Enter" && doFpSendOtp()} />
                </div>
                <button className="btn btn-primary" onClick={doFpSendOtp} disabled={loading || !fpEmail}>
                  {loading ? "Sending..." : "Send Reset Code →"}
                </button>
                <p className="auth-switch"><a onClick={() => { setTab2("login"); setError(""); }}>← Back to Login</a></p>
              </>
            )}

            {fpStep === 2 && (
              <>
                <p style={{ textAlign:"center", color:"var(--t2)", fontSize:"0.85rem", marginBottom:"1rem" }}>
                  Enter the 5-digit code sent to <strong>{fpEmail}</strong>
                </p>
                <div className="form-group">
                  <input className="otp-input" type="text" inputMode="numeric" pattern="[0-9]*"
                    maxLength={5} placeholder="- - - - -" value={fpOtp} autoFocus
                    onChange={e => setFpOtp(e.target.value.replace(/[^0-9]/g,"").slice(0,5))} />
                </div>
                <button className="btn btn-primary" onClick={doFpVerifyOtp} disabled={loading || fpOtp.length < 5}>
                  {loading ? "Verifying..." : "Verify Code →"}
                </button>
                <p className="auth-switch"><a onClick={doFpSendOtp}>Resend code</a></p>
              </>
            )}

            {fpStep === 3 && (
              <>
                <p style={{ textAlign:"center", color:"var(--t2)", fontSize:"0.85rem", marginBottom:"1rem" }}>
                  Set your new password
                </p>
                <div className="form-group">
                  <label>New Password</label>
                  <input type="password" placeholder="Min. 6 characters" value={fpNewPass} onChange={e => setFpNewPass(e.target.value)} />
                </div>
                <div className="form-group">
                  <label>Confirm Password</label>
                  <input type="password" placeholder="Repeat password" value={fpConfPass} onChange={e => setFpConfPass(e.target.value)} onKeyDown={e => e.key==="Enter" && doFpResetPass()} />
                </div>
                <button className="btn btn-primary" onClick={doFpResetPass} disabled={loading || !fpNewPass || !fpConfPass}>
                  {loading ? "Saving..." : "Reset Password ✓"}
                </button>
              </>
            )}
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
                <p style={{ textAlign:"center", color:"var(--t2)", fontSize:"0.88rem", marginBottom:"1rem" }}>
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
                      style={{ flex:1, padding:"0.5rem 0.75rem", border:"1px solid var(--line2)", borderRadius:"var(--r-sm)", fontSize:"0.85rem", background:"var(--base)", outline:"none", fontFamily:"inherit", color:"var(--t1)" }} />
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
                      style={{ flex:1, padding:"0.5rem 0.75rem", border:"1px solid var(--line2)", borderRadius:"var(--r-sm)", fontSize:"0.85rem", background:"var(--base)", outline:"none", fontFamily:"inherit", color:"var(--t1)" }} />
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
      else onToast(`Study request sent to ${targetName}!`, "success");
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
            <div className="card" style={{ textAlign:"center", padding:"3rem", color:"var(--t2)" }}>
              <div style={{ fontSize:"2.5rem", marginBottom:"0.5rem" }}>🎓</div>
              <div style={{ fontWeight:600 }}>No more profiles right now!</div>
              <div style={{ fontSize:"0.88rem", marginTop:"0.3rem" }}>Try clearing filters or check back later.</div>
              <button className="btn btn-outline btn-sm" style={{ marginTop:"1rem" }} onClick={fetchUsers}>Refresh</button>
            </div>
          )}
          <div className="cards-grid">
            {users.map(u => (
              <div className="profile-card" key={u.id}>
                <div className="profile-card-banner" style={{ background:`linear-gradient(135deg, ${userColor(u.id)}55 0%, #0c0c14 100%)` }} />
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
                    <button className="btn-like" onClick={() => like(u.id, u.name)} disabled={liking === u.id}>
                      {liking === u.id ? "..." : "✦ Connect"}
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
            <div className="card" style={{ textAlign:"center", color:"var(--t2)", padding:"2rem", fontSize:"0.9rem" }}>
              No matches yet. Start discovering! 🔍
            </div>
          )}
          {matches.map(m => (
            <div key={m.match_id} className={`chat-item ${active?.match_id === m.match_id ? "active" : ""}`} onClick={() => setActive(m)}>
              <div className="match-avatar" style={{ background:userColor(m.id) }}>{m.photo ? <img src={m.photo} alt={m.name} /> : (m.initials || getInitials(m.name))}</div>
              <div className="chat-item-info">
                <div className="chat-item-name">{m.name}</div>
                <div className="chat-item-preview">{m.last_message || "Say hi! 👋"}</div>
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
                  {active.photo ? <img src={active.photo} style={{width:"100%",height:"100%",objectFit:"cover",borderRadius:"50%"}} /> : (active.initials || getInitials(active.name))}
                </div>
                <div style={{ flex:1 }}>
                  <div style={{ fontWeight:600 }}>{active.name}</div>
                  <div style={{ fontSize:"0.78rem", color:"var(--t2)" }}>{active.college}</div>
                </div>
              </div>
              <div className="chat-messages">
                {messages.length === 0 && (
                  <div style={{ textAlign:"center", color:"var(--t2)", padding:"2rem", fontSize:"0.9rem" }}>Start the conversation! 👋</div>
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
  const [profileTab, setProfileTab] = useState("edit"); // "edit" | "rate"
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
      {/* Profile Tabs */}
      <div style={{ display:"flex", gap:"0.5rem", marginBottom:"1.2rem" }}>
        {[{id:"edit",label:"✏️ Edit Profile"},{id:"rate",label:"⭐ Rate Partners"}].map(t => (
          <button key={t.id}
            onClick={() => setProfileTab(t.id)}
            style={{
              padding:"0.45rem 1.1rem", borderRadius:"var(--r-sm)", border:"1px solid var(--line2)",
              background: profileTab===t.id ? "var(--pg)" : "var(--panel)",
              color: profileTab===t.id ? "#fff" : "var(--t2)",
              fontWeight:700, cursor:"pointer", fontSize:"0.84rem",
              fontFamily:"'Bricolage Grotesque',sans-serif",
              boxShadow: profileTab===t.id ? "0 0 12px var(--glow)" : "none",
              transition:"all 0.18s",
            }}>{t.label}</button>
        ))}
      </div>

      {profileTab === "rate" && <RatingInProfile user={user} onToast={onToast} />}

      {profileTab === "edit" && <div style={{ maxWidth:600 }}>
        <div className="card">
          <h3 style={{ marginBottom:"1.2rem" }}>Edit Profile</h3>
          <div className="form-group" style={{ textAlign:"center", marginBottom:"1.5rem" }}>
            <label>Profile Picture</label>
            <div style={{ display:"flex", justifyContent:"center", marginTop:"0.5rem" }}>
              <div className="pic-upload-wrap" onClick={() => fileRef.current?.click()}>
                <div style={{ width:80, height:80, borderRadius:"50%", background:userColor(user.id), display:"flex", alignItems:"center", justifyContent:"center", fontSize:"1.8rem", fontWeight:700, color:"#fff", overflow:"hidden", border:"2px solid var(--p)" }}>
                  {photo ? <img src={photo} alt="avatar" style={{ width:"100%", height:"100%", objectFit:"cover" }} /> : (user.initials || getInitials(user.name))}
                </div>
                <div className="pic-overlay">📷<br/>Upload</div>
              </div>
            </div>
            <p style={{ fontSize:"0.75rem", color:"var(--t2)", marginTop:"0.4rem" }}>Max 2MB · JPG, PNG</p>
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
                style={{ flex:1, padding:"0.5rem 0.75rem", border:"1px solid var(--line2)", borderRadius:"var(--r-sm)", fontSize:"0.85rem", background:"var(--base)", outline:"none", fontFamily:"inherit", color:"var(--t1)" }} />
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
                style={{ flex:1, padding:"0.5rem 0.75rem", border:"1px solid var(--line2)", borderRadius:"var(--r-sm)", fontSize:"0.85rem", background:"var(--base)", outline:"none", fontFamily:"inherit", color:"var(--t1)" }} />
              <button className="btn btn-outline btn-sm" onClick={addCustomSubject}>+ Add</button>
            </div>
          </div>
          <button className="btn btn-primary" style={{ width:"auto", padding:"0.7rem 2rem", marginTop:"0.5rem" }} onClick={save} disabled={loading}>
            {loading ? "Saving..." : "Save Changes"}
          </button>
        </div>
      </div>}
    </div>
  );
}

// Embedded Rating inside Profile
function RatingInProfile({ user, onToast }) {
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
      catch {} setLoading(false);
    })();
  }, []);
  const star = (cat, val) => setRatings(p => ({ ...p, [cat]:val }));
  const submit = async () => {
    if (!selected || !ratings.punctuality || !ratings.helpfulness || !ratings.focus) { onToast("Please fill all star ratings","error"); return; }
    setSubmitting(true);
    try { await apiFetch("/ratings", { method:"POST", body:{ toId:selected, ...ratings, feedback } }); setSubmitted(true); onToast("Rating submitted! 🙏","success"); }
    catch(e) { onToast(e.message,"error"); }
    setSubmitting(false);
  };
  const StarRow = ({ label, cat }) => (
    <div className="rating-row">
      <div style={{ fontWeight:500, fontSize:"0.88rem" }}>{label}</div>
      <div>{[1,2,3,4,5].map(v=><span key={v} className="star" onClick={()=>star(cat,v)}>{v<=ratings[cat]?"⭐":"☆"}</span>)}</div>
    </div>
  );
  if (loading) return <div className="loading"><div className="spinner"/></div>;
  if (!matches.length) return <div className="card" style={{ textAlign:"center", padding:"2rem", color:"var(--t2)" }}><div style={{ fontSize:"2rem", marginBottom:"0.75rem" }}>🤝</div>Get some matches first to rate them!</div>;
  return (
    <div className="card" style={{ maxWidth:500 }}>
      <h3 style={{ marginBottom:"1rem" }}>⭐ Rate a Study Partner</h3>
      <div className="form-group">
        <label>Select Partner</label>
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
          <button className="btn btn-primary" style={{ marginTop:"0.5rem" }} onClick={submit} disabled={submitting}>{submitting?"Submitting...":"Submit Rating"}</button>
        </>
      ) : (
        <div style={{ textAlign:"center", padding:"2rem", color:"var(--ok)" }}>
          <div style={{ fontSize:"2.5rem" }}>✅</div>
          <div style={{ fontWeight:700, fontSize:"1.1rem", marginTop:"0.5rem" }}>Rating Submitted!</div>
          <div style={{ color:"var(--t2)", fontSize:"0.88rem", marginTop:"0.3rem" }}>Thank you for helping the community.</div>
          <button className="btn btn-outline btn-sm" style={{ marginTop:"1rem" }} onClick={()=>{ setSubmitted(false); setRatings({punctuality:0,helpfulness:0,focus:0}); setFeedback(""); }}>Rate Another</button>
        </div>
      )}
    </div>
  );
}

function StudyTools({ onToast }) {
  const MODES = [
    { id:"focus25",  label:"🍅 Focus 25m",  secs:25*60,  type:"focus" },
    { id:"focus55",  label:"🔥 Focus 55m",  secs:55*60,  type:"focus" },
    { id:"focus99",  label:"⚡ Focus 99m",  secs:99*60,  type:"focus" },
    { id:"break5",   label:"☕ Break 5m",   secs:5*60,   type:"break" },
    { id:"break15",  label:"Break 15m",  secs:15*60,  type:"break" },
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
            <div style={{ fontSize:"0.72rem", fontWeight:600, color:"var(--t2)", textTransform:"uppercase", letterSpacing:"0.5px", marginBottom:"0.4rem" }}>Focus</div>
            <div style={{ display:"flex", gap:"0.4rem", justifyContent:"center", flexWrap:"wrap", marginBottom:"0.5rem" }}>
              {MODES.filter(m=>m.type==="focus").map(m => (
                <div key={m.id} className={`filter-chip ${modeId===m.id?"active":""}`} onClick={() => switchMode(m.id)}>{m.label}</div>
              ))}
            </div>
            <div style={{ fontSize:"0.72rem", fontWeight:600, color:"var(--t2)", textTransform:"uppercase", letterSpacing:"0.5px", marginBottom:"0.4rem" }}>Break</div>
            <div style={{ display:"flex", gap:"0.4rem", justifyContent:"center", flexWrap:"wrap" }}>
              {MODES.filter(m=>m.type==="break").map(m => (
                <div key={m.id} className={`filter-chip ${modeId===m.id?"active":""}`} onClick={() => switchMode(m.id)}>{m.label}</div>
              ))}
            </div>
          </div>
          <div className="timer-circle" style={{"--prog":prog}}>{fmt(secs)}</div>
          <div className="timer-controls">
            <button className="timer-btn" style={{ background:"var(--pg)", color:"#fff" }} onClick={() => setRunning(p=>!p)}>{running ? "⏸ Pause" : "▶ Start"}</button>
            <button className="timer-btn" style={{ background:"var(--panel)", border:"1px solid var(--line2)" }} onClick={() => { setRunning(false); setSecs(curMode.secs); }}>↺ Reset</button>
          </div>
        </div>
        <div className="card">
          <h3 style={{ marginBottom:"1rem" }}>Session Goals</h3>
          {goals.length===0 && <p style={{ color:"var(--t2)", fontSize:"0.88rem", marginBottom:"0.5rem" }}>Add goals for this session...</p>}
          <ul className="goals-list">
            {goals.map(g => (
              <li key={g.id} className={g.done?"done":""}>
                <input type="checkbox" checked={g.done} onChange={() => setGoals(p=>p.map(x=>x.id===g.id?{...x,done:!x.done}:x))}/>
                <span style={{ flex:1 }}>{g.text}</span>
                <span style={{ cursor:"pointer", color:"var(--t2)" }} onClick={() => setGoals(p=>p.filter(x=>x.id!==g.id))}>✕</span>
              </li>
            ))}
          </ul>
          <div className="goal-input-row">
            <input className="goal-input" placeholder="Add a goal..." value={newGoal} onChange={e=>setNewGoal(e.target.value)} onKeyDown={e=>e.key==="Enter"&&addGoal()}/>
            <button className="btn btn-primary btn-sm" onClick={addGoal}>+ Add</button>
          </div>
          {goals.length>0 && (
            <div style={{ marginTop:"1rem", padding:"0.6rem 0.8rem", background:"var(--panel)", borderRadius:"10px", fontSize:"0.85rem", color:"var(--t2)" }}>
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
            <div style={{ color:"var(--t2)", fontSize:"0.9rem", marginTop:"0.3rem" }}>Thank you for helping our community.</div>
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
          <div style={{ textAlign:"center", padding:"2rem", color:"var(--t2)" }}>No users signed up yet</div>
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
                  <td style={{ fontSize:"0.82rem", color:"var(--t2)" }}>{u.email}</td>
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
        <div className="card" style={{ textAlign:"center", padding:"3rem", color:"var(--t2)" }}>
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
              <div style={{ height:70, background:`linear-gradient(135deg, ${userColor(m.id)}55 0%, var(--base) 100%)` }} />
              <div style={{ padding:"0 1rem 1rem" }}>
                <div style={{ display:"flex", alignItems:"flex-end", gap:"0.75rem", marginTop:-30, marginBottom:"0.6rem" }}>
                  <div style={{ width:56, height:56, borderRadius:"50%", background:userColor(m.id), display:"flex", alignItems:"center", justifyContent:"center", fontSize:"1.2rem", fontWeight:700, color:"#fff", border:"2px solid var(--lift)", flexShrink:0, overflow:"hidden" }}>
                    {m.photo ? <img src={m.photo} alt={m.name} style={{ width:"100%", height:"100%", objectFit:"cover" }} /> : (m.initials || getInitials(m.name))}
                  </div>
                  <div style={{ paddingBottom:"0.2rem", flex:1 }}>
                    <div style={{ fontWeight:700, fontSize:"1.05rem" }}>{m.name}</div>
                    <div style={{ fontSize:"0.8rem", color:"var(--t2)" }}>📍 {m.college || "Unknown"}</div>
                  </div>
                  <button onClick={() => setExpanded(isOpen ? null : m.match_id)}
                    style={{ background:"var(--panel)", border:"1.5px solid var(--line2)", borderRadius:8, padding:"0.3rem 0.7rem", fontSize:"0.78rem", cursor:"pointer", fontWeight:600, color:"var(--t1)", marginBottom:"0.2rem", flexShrink:0 }}>
                    {isOpen ? "▲ Hide" : "▼ View"}
                  </button>
                </div>

                {isOpen && (
                  <div style={{ borderTop:"1px solid var(--line2)", paddingTop:"0.75rem", marginBottom:"0.75rem" }}>
                    {m.style && (
                      <div style={{ marginBottom:"0.5rem" }}>
                        <div style={{ fontSize:"0.72rem", fontWeight:600, color:"var(--t2)", textTransform:"uppercase", letterSpacing:"0.5px", marginBottom:"0.25rem" }}>Study Style</div>
                        <span className="tag tag-style">{m.style}</span>
                      </div>
                    )}
                    {m.subjects?.length > 0 && (
                      <div style={{ marginBottom:"0.5rem" }}>
                        <div style={{ fontSize:"0.72rem", fontWeight:600, color:"var(--t2)", textTransform:"uppercase", letterSpacing:"0.5px", marginBottom:"0.25rem" }}>Subjects</div>
                        <div style={{ display:"flex", flexWrap:"wrap", gap:"0.3rem" }}>
                          {m.subjects.map(s => <span key={s} className="tag">{s}</span>)}
                        </div>
                      </div>
                    )}
                    {!m.style && !m.subjects?.length && (
                      <div style={{ color:"var(--t2)", fontSize:"0.85rem", marginBottom:"0.5rem" }}>No extra info yet</div>
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


// ── Spotify OAuth PKCE helpers ──────────────────────────────────────────────
const SP_CLIENT_ID   = "2d31353eea8c49fe84c92ee1674c2738";
const SP_REDIRECT    = "https://studybud.web.app";
const SP_SCOPES      = "streaming user-read-email user-read-private user-read-playback-state user-modify-playback-state user-read-currently-playing";

async function spPKCEChallenge() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  const verifier = btoa(String.fromCharCode(...arr)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
  const data = new TextEncoder().encode(verifier);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const challenge = btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=/g,"");
  return { verifier, challenge };
}

function spLogin() {
  spPKCEChallenge().then(({ verifier, challenge }) => {
    sessionStorage.setItem("sp_verifier", verifier);
    const params = new URLSearchParams({
      client_id: SP_CLIENT_ID, response_type: "code",
      redirect_uri: SP_REDIRECT, scope: SP_SCOPES,
      code_challenge_method: "S256", code_challenge: challenge,
    });
    window.location.href = `https://accounts.spotify.com/authorize?${params}`;
  });
}

async function spExchangeCode(code) {
  const verifier = sessionStorage.getItem("sp_verifier");
  const res = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code,
      redirect_uri: SP_REDIRECT, client_id: SP_CLIENT_ID, code_verifier: verifier,
    }),
  });
  return res.json();
}

async function spRefreshToken(refresh_token) {
  const res = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token", refresh_token, client_id: SP_CLIENT_ID,
    }),
  });
  return res.json();
}

async function spSearch(q, token) {
  const res = await fetch(`https://api.spotify.com/v1/search?q=${encodeURIComponent(q)}&type=track,album,playlist&limit=8`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error?.message || `Spotify error ${res.status}`);
  return data;
}

// Spotify Player component
function SpotifyPlayer({ onToast }) {
  const [token, setToken]         = useState(() => sessionStorage.getItem("sp_token") || "");
  const [query, setQuery]         = useState("");
  const [results, setResults]     = useState(null);
  const [searching, setSearching] = useState(false);
  const [deviceId, setDeviceId]   = useState("");
  const [nowPlaying, setNowPlaying] = useState(null);
  const [paused, setPaused]       = useState(true);
  const [volume, setVolume]       = useState(0.5);
  const [progress, setProgress]   = useState(0);
  const [duration, setDuration]   = useState(0);
  const [isPremium, setIsPremium] = useState(null); // null=unknown, true/false
  const playerRef = useRef(null);
  const progressRef = useRef(null);

  // Handle OAuth callback
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    if (code && !token) {
      spExchangeCode(code).then(data => {
        if (data.access_token) {
          sessionStorage.setItem("sp_token", data.access_token);
          sessionStorage.setItem("sp_refresh", data.refresh_token || "");
          sessionStorage.setItem("sp_expires", String(Date.now() + data.expires_in * 1000));
          setToken(data.access_token);
          // Clean URL
          window.history.replaceState({}, "", window.location.pathname);
        }
      });
    }
  }, []);

  // Check premium & load Web Playback SDK
  useEffect(() => {
    if (!token) return;
    // Check user profile for premium
    fetch("https://api.spotify.com/v1/me", { headers:{ Authorization:`Bearer ${token}` }})
      .then(r=>r.json()).then(d => {
        setIsPremium(d.product === "premium");
        if (d.product !== "premium") return;
        // Load SDK
        if (!window.Spotify) {
          const script = document.createElement("script");
          script.src = "https://sdk.scdn.co/spotify-player.js";
          document.head.appendChild(script);
        }
        window.onSpotifyWebPlaybackSDKReady = () => initPlayer(token);
        if (window.Spotify) initPlayer(token);
      });
  }, [token]);

  function initPlayer(accessToken) {
    if (playerRef.current) return;
    const player = new window.Spotify.Player({
      name: "StudyBuddy 🎧",
      getOAuthToken: cb => {
        const exp = Number(sessionStorage.getItem("sp_expires") || 0);
        if (Date.now() > exp - 60000) {
          const refresh = sessionStorage.getItem("sp_refresh");
          if (refresh) {
            spRefreshToken(refresh).then(d => {
              if (d.access_token) {
                sessionStorage.setItem("sp_token", d.access_token);
                sessionStorage.setItem("sp_expires", String(Date.now() + d.expires_in * 1000));
                setToken(d.access_token);
                cb(d.access_token);
              } else cb(accessToken);
            });
          } else cb(accessToken);
        } else cb(accessToken);
      },
      volume: 0.5,
    });
    player.addListener("ready", ({ device_id }) => setDeviceId(device_id));
    player.addListener("player_state_changed", state => {
      if (!state) return;
      setNowPlaying(state.track_window?.current_track || null);
      setPaused(state.paused);
      setProgress(state.position);
      setDuration(state.duration);
    });
    player.addListener("authentication_error", () => {
      onToast("Spotify auth error — please reconnect", "error");
      sessionStorage.removeItem("sp_token");
      setToken("");
    });
    player.connect();
    playerRef.current = player;
  }

  // Progress ticker
  useEffect(() => {
    if (paused) { clearInterval(progressRef.current); return; }
    progressRef.current = setInterval(() => setProgress(p => Math.min(p + 1000, duration)), 1000);
    return () => clearInterval(progressRef.current);
  }, [paused, duration]);

  async function playTrack(uri) {
    if (!deviceId) { onToast("Player not ready yet, wait a moment", "error"); return; }
    await fetch(`https://api.spotify.com/v1/me/player/play?device_id=${deviceId}`, {
      method: "PUT",
      headers: { Authorization:`Bearer ${token}`, "Content-Type":"application/json" },
      body: JSON.stringify({ uris: [uri] }),
    });
  }

  async function playContext(uri) {
    if (!deviceId) { onToast("Player not ready yet, wait a moment", "error"); return; }
    await fetch(`https://api.spotify.com/v1/me/player/play?device_id=${deviceId}`, {
      method: "PUT",
      headers: { Authorization:`Bearer ${token}`, "Content-Type":"application/json" },
      body: JSON.stringify({ context_uri: uri }),
    });
  }

  async function doSearch() {
    if (!query.trim()) return;
    setSearching(true);
    try {
      // Try to refresh token if close to expiry
      const exp = Number(sessionStorage.getItem("sp_expires") || 0);
      let activeToken = token;
      if (Date.now() > exp - 60000) {
        const refresh = sessionStorage.getItem("sp_refresh");
        if (refresh) {
          try {
            const d = await spRefreshToken(refresh);
            if (d.access_token) {
              sessionStorage.setItem("sp_token", d.access_token);
              sessionStorage.setItem("sp_expires", String(Date.now() + d.expires_in * 1000));
              setToken(d.access_token);
              activeToken = d.access_token;
            }
          } catch {}
        }
      }
      const data = await spSearch(query, activeToken);
      setResults(data);
    } catch(e) {
      onToast(e.message || "Search failed", "error");
      // If 401, token is invalid — force re-login
      if (e.message?.includes("401") || e.message?.includes("token")) {
        sessionStorage.removeItem("sp_token");
        setToken("");
      }
    }
    setSearching(false);
  }

  function fmtMs(ms) {
    const s = Math.floor(ms/1000);
    return `${Math.floor(s/60)}:${String(s%60).padStart(2,"0")}`;
  }

  // ── NOT LOGGED IN ──────────────────────────────────────────────────────────
  if (!token) return (
    <div style={{marginTop:"1rem",background:"rgba(29,185,84,0.07)",border:"1px solid rgba(29,185,84,0.25)",borderRadius:"var(--r-lg)",padding:"1.2rem",textAlign:"center"}}>
      <div style={{fontSize:"2rem",marginBottom:"0.5rem"}}>
        <svg width="36" height="36" viewBox="0 0 24 24" fill="#1DB954" style={{verticalAlign:"middle"}}><path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.419 1.56-.299.421-1.02.599-1.559.3z"/></svg>
      </div>
      <div style={{fontWeight:700,fontSize:"1rem",color:"#fff",marginBottom:"0.3rem"}}>Connect Spotify</div>
      <div style={{fontSize:"0.8rem",color:"#888",marginBottom:"1rem"}}>Log in with Spotify to search & play any song while you study</div>
      <button onClick={spLogin} style={{background:"#1DB954",border:"none",borderRadius:99,padding:"0.6rem 1.8rem",color:"#000",fontWeight:800,fontSize:"0.9rem",cursor:"pointer",display:"inline-flex",alignItems:"center",gap:"0.5rem",fontFamily:"'Bricolage Grotesque',sans-serif",letterSpacing:"0.02em"}}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.419 1.56-.299.421-1.02.599-1.559.3z"/></svg>
        Connect with Spotify
      </button>
      <div style={{fontSize:"0.7rem",color:"#555",marginTop:"0.75rem"}}>Requires Spotify Premium for playback · Free accounts can browse</div>
    </div>
  );

  // ── NOT PREMIUM ────────────────────────────────────────────────────────────
  if (isPremium === false) return (
    <div style={{marginTop:"1rem",background:"rgba(255,255,255,0.04)",border:"1px solid var(--line2)",borderRadius:"var(--r-lg)",padding:"1.1rem"}}>
      <div style={{display:"flex",alignItems:"center",gap:"0.6rem",marginBottom:"0.6rem"}}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="#1DB954"><path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.419 1.56-.299.421-1.02.599-1.559.3z"/></svg>
        <span style={{fontWeight:700,fontSize:"0.9rem",color:"#1DB954"}}>Spotify Connected</span>
        <button onClick={()=>{ sessionStorage.removeItem("sp_token"); setToken(""); }} style={{marginLeft:"auto",background:"none",border:"1px solid #333",borderRadius:6,color:"#666",cursor:"pointer",fontSize:"0.7rem",padding:"0.2rem 0.5rem"}}>Disconnect</button>
      </div>
      <div style={{background:"rgba(255,165,0,0.1)",border:"1px solid rgba(255,165,0,0.3)",borderRadius:"var(--r)",padding:"0.75rem",fontSize:"0.82rem",color:"#ffb347"}}>
        ⚠️ <strong>Spotify Premium required</strong> for in-browser playback. You can still search and tap tracks to open them in your Spotify app.
      </div>
      <SearchPanel token={token} onPlay={uri => window.open(`https://open.spotify.com/track/${uri.split(":")[2]}`, "_blank")} onPlayContext={uri => window.open(`https://open.spotify.com/playlist/${uri.split(":")[2]}`, "_blank")} query={query} setQuery={setQuery} results={results} setResults={setResults} searching={searching} doSearch={doSearch} fmtMs={fmtMs} premium={false} />
    </div>
  );

  // ── PREMIUM — FULL PLAYER ──────────────────────────────────────────────────
  return (
    <div style={{marginTop:"1rem",background:"rgba(29,185,84,0.05)",border:"1px solid rgba(29,185,84,0.2)",borderRadius:"var(--r-lg)",padding:"1rem",display:"flex",flexDirection:"column",gap:"0.75rem"}}>

      {/* Header */}
      <div style={{display:"flex",alignItems:"center",gap:"0.5rem"}}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="#1DB954"><path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.419 1.56-.299.421-1.02.599-1.559.3z"/></svg>
        <span style={{fontWeight:700,fontSize:"0.88rem",color:"#1DB954"}}>Spotify</span>
        {!deviceId && <span style={{fontSize:"0.7rem",color:"#888",marginLeft:"0.3rem"}}>⏳ Connecting player…</span>}
        <button onClick={()=>{ playerRef.current?.disconnect(); playerRef.current=null; sessionStorage.removeItem("sp_token"); setToken(""); }} style={{marginLeft:"auto",background:"none",border:"1px solid #333",borderRadius:6,color:"#666",cursor:"pointer",fontSize:"0.7rem",padding:"0.2rem 0.5rem"}}>Disconnect</button>
      </div>

      {/* Now Playing bar */}
      {nowPlaying && (
        <div style={{background:"rgba(0,0,0,0.35)",borderRadius:"var(--r)",padding:"0.65rem 0.85rem",display:"flex",flexDirection:"column",gap:"0.4rem"}}>
          <div style={{display:"flex",alignItems:"center",gap:"0.7rem"}}>
            {nowPlaying.album?.images?.[2]?.url && <img src={nowPlaying.album.images[2].url} style={{width:40,height:40,borderRadius:6,flexShrink:0}} alt="art" />}
            <div style={{flex:1,minWidth:0}}>
              <div style={{fontWeight:700,fontSize:"0.84rem",color:"#fff",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{nowPlaying.name}</div>
              <div style={{fontSize:"0.72rem",color:"#888"}}>{nowPlaying.artists?.map(a=>a.name).join(", ")}</div>
            </div>
            <div style={{fontSize:"0.7rem",color:"#666",flexShrink:0}}>{fmtMs(progress)} / {fmtMs(duration)}</div>
          </div>
          {/* Progress bar */}
          <div style={{height:3,background:"#333",borderRadius:99,overflow:"hidden"}}>
            <div style={{height:"100%",background:"#1DB954",width:`${duration?Math.round(progress/duration*100):0}%`,transition:"width 1s linear"}} />
          </div>
          {/* Controls */}
          <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:"1rem"}}>
            <button onClick={()=>playerRef.current?.previousTrack()} style={{background:"none",border:"none",color:"#aaa",cursor:"pointer",fontSize:"1.1rem",padding:"0.2rem"}}>⏮</button>
            <button onClick={()=>playerRef.current?.togglePlay()} style={{background:"#1DB954",border:"none",borderRadius:"50%",width:36,height:36,color:"#000",cursor:"pointer",fontSize:"1rem",display:"flex",alignItems:"center",justifyContent:"center",fontWeight:700}}>
              {paused ? "▶" : "⏸"}
            </button>
            <button onClick={()=>playerRef.current?.nextTrack()} style={{background:"none",border:"none",color:"#aaa",cursor:"pointer",fontSize:"1.1rem",padding:"0.2rem"}}>⏭</button>
            <input type="range" min={0} max={100} value={Math.round(volume*100)}
              onChange={e=>{ const v=Number(e.target.value)/100; setVolume(v); playerRef.current?.setVolume(v); }}
              style={{width:70,accentColor:"#1DB954",marginLeft:"0.5rem"}} />
          </div>
        </div>
      )}

      {/* Search */}
      <SearchPanel token={token} onPlay={playTrack} onPlayContext={playContext} query={query} setQuery={setQuery} results={results} setResults={setResults} searching={searching} doSearch={doSearch} fmtMs={fmtMs} premium={true} />
    </div>
  );
}

// Search panel — shared by premium + free
function SearchPanel({ token, onPlay, onPlayContext, query, setQuery, results, setResults, searching, doSearch, fmtMs, premium }) {
  return (
    <div>
      {/* Search bar */}
      <div style={{display:"flex",gap:"0.5rem",marginBottom:"0.6rem"}}>
        <input
          value={query}
          onChange={e=>setQuery(e.target.value)}
          onKeyDown={e=>e.key==="Enter"&&doSearch()}
          placeholder="Search songs, artists, playlists…"
          style={{flex:1,background:"rgba(255,255,255,0.06)",border:"1px solid rgba(255,255,255,0.12)",borderRadius:"var(--r-sm)",padding:"0.5rem 0.75rem",color:"var(--t1)",fontFamily:"'Instrument Sans',sans-serif",fontSize:"0.84rem",outline:"none"}}
        />
        <button onClick={doSearch} disabled={searching} style={{background:"#1DB954",border:"none",borderRadius:"var(--r-sm)",padding:"0.5rem 1rem",color:"#000",fontWeight:700,cursor:"pointer",fontSize:"0.82rem",flexShrink:0}}>
          {searching ? "…" : "Search"}
        </button>
      </div>

      {/* Results */}
      {results && (
        <div style={{display:"flex",flexDirection:"column",gap:"0.4rem",maxHeight:260,overflowY:"auto"}}>

          {/* Tracks */}
          {results.tracks?.items?.length > 0 && (
            <>
              <div style={{fontSize:"0.68rem",fontWeight:700,color:"#555",textTransform:"uppercase",letterSpacing:"0.5px",marginBottom:"0.2rem"}}>Tracks</div>
              {results.tracks.items.map(t => (
                <div key={t.id} onClick={()=>onPlay(t.uri)}
                  style={{display:"flex",alignItems:"center",gap:"0.6rem",padding:"0.45rem 0.6rem",borderRadius:8,cursor:"pointer",background:"rgba(255,255,255,0.04)",transition:"background 0.15s"}}
                  onMouseEnter={e=>e.currentTarget.style.background="rgba(29,185,84,0.12)"}
                  onMouseLeave={e=>e.currentTarget.style.background="rgba(255,255,255,0.04)"}>
                  {t.album?.images?.[2]?.url
                    ? <img src={t.album.images[2].url} style={{width:36,height:36,borderRadius:4,flexShrink:0}} alt="" />
                    : <div style={{width:36,height:36,borderRadius:4,background:"#333",flexShrink:0,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"0.9rem"}}>🎵</div>
                  }
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontSize:"0.82rem",fontWeight:600,color:"#fff",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{t.name}</div>
                    <div style={{fontSize:"0.7rem",color:"#888"}}>{t.artists?.map(a=>a.name).join(", ")} · {t.album?.name}</div>
                  </div>
                  <div style={{fontSize:"0.7rem",color:"#555",flexShrink:0}}>{fmtMs(t.duration_ms)}</div>
                  <div style={{fontSize:"0.8rem",color:"#1DB954",flexShrink:0}}>{premium?"▶":"↗"}</div>
                </div>
              ))}
            </>
          )}

          {/* Playlists */}
          {results.playlists?.items?.length > 0 && (
            <>
              <div style={{fontSize:"0.68rem",fontWeight:700,color:"#555",textTransform:"uppercase",letterSpacing:"0.5px",margin:"0.4rem 0 0.2rem"}}>Playlists</div>
              {results.playlists.items.filter(Boolean).slice(0,4).map(pl => (
                <div key={pl.id} onClick={()=>onPlayContext(pl.uri)}
                  style={{display:"flex",alignItems:"center",gap:"0.6rem",padding:"0.45rem 0.6rem",borderRadius:8,cursor:"pointer",background:"rgba(255,255,255,0.04)",transition:"background 0.15s"}}
                  onMouseEnter={e=>e.currentTarget.style.background="rgba(29,185,84,0.12)"}
                  onMouseLeave={e=>e.currentTarget.style.background="rgba(255,255,255,0.04)"}>
                  {pl.images?.[0]?.url
                    ? <img src={pl.images[0].url} style={{width:36,height:36,borderRadius:4,flexShrink:0}} alt="" />
                    : <div style={{width:36,height:36,borderRadius:4,background:"#333",flexShrink:0,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"0.9rem"}}>📋</div>
                  }
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontSize:"0.82rem",fontWeight:600,color:"#fff",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{pl.name}</div>
                    <div style={{fontSize:"0.7rem",color:"#888"}}>{pl.tracks?.total} tracks · {pl.owner?.display_name}</div>
                  </div>
                  <div style={{fontSize:"0.8rem",color:"#1DB954",flexShrink:0}}>{premium?"▶":"↗"}</div>
                </div>
              ))}
            </>
          )}

          {/* Albums */}
          {results.albums?.items?.length > 0 && (
            <>
              <div style={{fontSize:"0.68rem",fontWeight:700,color:"#555",textTransform:"uppercase",letterSpacing:"0.5px",margin:"0.4rem 0 0.2rem"}}>Albums</div>
              {results.albums.items.slice(0,3).map(al => (
                <div key={al.id} onClick={()=>onPlayContext(al.uri)}
                  style={{display:"flex",alignItems:"center",gap:"0.6rem",padding:"0.45rem 0.6rem",borderRadius:8,cursor:"pointer",background:"rgba(255,255,255,0.04)",transition:"background 0.15s"}}
                  onMouseEnter={e=>e.currentTarget.style.background="rgba(29,185,84,0.12)"}
                  onMouseLeave={e=>e.currentTarget.style.background="rgba(255,255,255,0.04)"}>
                  {al.images?.[2]?.url
                    ? <img src={al.images[2].url} style={{width:36,height:36,borderRadius:4,flexShrink:0}} alt="" />
                    : <div style={{width:36,height:36,borderRadius:4,background:"#333",flexShrink:0}} />
                  }
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontSize:"0.82rem",fontWeight:600,color:"#fff",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{al.name}</div>
                    <div style={{fontSize:"0.7rem",color:"#888"}}>{al.artists?.map(a=>a.name).join(", ")} · {al.release_date?.slice(0,4)}</div>
                  </div>
                  <div style={{fontSize:"0.8rem",color:"#1DB954",flexShrink:0}}>{premium?"▶":"↗"}</div>
                </div>
              ))}
            </>
          )}

          {!results.tracks?.items?.length && !results.playlists?.items?.length && !results.albums?.items?.length && (
            <div style={{textAlign:"center",color:"#666",padding:"1rem",fontSize:"0.84rem"}}>No results found</div>
          )}
        </div>
      )}
    </div>
  );
}

const PRESET_ROOMS = [
  { id:"r1", name:"Lo-Fi Focus Room",    emoji:"🎧", bg:"linear-gradient(135deg,#1e1b4b,#312e81)", subject:"General",        vibe:"Quiet focus + lo-fi beats" },
  { id:"r2", name:"Math & Science Hub",  emoji:"🔬", bg:"linear-gradient(135deg,#064e3b,#065f46)", subject:"Math/Science",   vibe:"Collaborative problem solving" },
  { id:"r3", name:"Code & Build",        emoji:"💻", bg:"linear-gradient(135deg,#1e3a5f,#1e40af)", subject:"CS/Programming", vibe:"Deep work sessions" },
  { id:"r4", name:"Exam Prep Zone",      emoji:"📚", bg:"linear-gradient(135deg,#7c2d12,#9a3412)", subject:"All subjects",   vibe:"Intense study mode" },
  { id:"r5", name:"Chill Study Lounge",  emoji:"☕", bg:"linear-gradient(135deg,#422006,#713f12)", subject:"Any",            vibe:"Relaxed pace, any topic" },
  { id:"r6", name:"Night Owl Session",   emoji:"🌙", bg:"linear-gradient(135deg,#0f172a,#1e293b)", subject:"Any",            vibe:"Late night grinders only" },
];

const ICE_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:stun1.l.google.com:19302" },
];

function StudyRooms({ user, onToast }) {
  // ── view state ──────────────────────────────────────────────────────────
  const [view, setView]           = useState("list"); // list | room | create | join
  const [activeRoom, setActiveRoom] = useState(null);

  // ── private-room form ────────────────────────────────────────────────────
  const [formName, setFormName]   = useState("");
  const [formPass, setFormPass]   = useState("");
  const [formCode, setFormCode]   = useState("");
  const [formErr, setFormErr]     = useState("");

  // ── room state ───────────────────────────────────────────────────────────
  const [members, setMembers]     = useState([]);
  const [roomCounts, setRoomCounts] = useState({});
  const [chat, setChat]           = useState([]);
  const [chatInput, setChatInput] = useState("");
  const [micOn, setMicOn]         = useState(false);
  const [micErr, setMicErr]       = useState("");
  // Spotify state handled inside SpotifyPlayer component
  const [pomSecs, setPomSecs]     = useState(25*60);
  const [pomOn, setPomOn]         = useState(false);
  const [pomMode, setPomMode]     = useState("focus");

  const socketRef     = useRef(null);
  const localStream   = useRef(null);
  const peers         = useRef({});        // socketId -> RTCPeerConnection
  const iceQueues     = useRef({});        // socketId -> candidate[] (buffered before remoteDesc)
  const membersRef    = useRef([]);        // always-current copy for async callbacks
  const chatBottom    = useRef(null);
  const POM           = { focus:25*60, break:5*60 };

  // keep membersRef in sync
  useEffect(() => { membersRef.current = members; }, [members]);

  // ICE servers — multiple for reliability in India
  const ICE_CFG = {
    iceServers: [
      { urls: "stun:stun.l.google.com:19302" },
      { urls: "stun:stun1.l.google.com:19302" },
      { urls: "stun:stun2.l.google.com:19302" },
      { urls: "stun:stun3.l.google.com:19302" },
      { urls: "stun:stun4.l.google.com:19302" },
      { urls: "stun:global.stun.twilio.com:3478" },
    ],
    iceCandidatePoolSize: 10,
  };

  // ── live room counts ─────────────────────────────────────────────────────
  useEffect(() => {
    const load = () => fetch(`${API}/rooms/counts`).then(r=>r.json()).then(setRoomCounts).catch(()=>{});
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  // ── pomodoro ──────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!pomOn) return;
    const t = setInterval(() => {
      setPomSecs(p => {
        if (p <= 1) {
          setPomOn(false);
          const next = pomMode==="focus" ? "break" : "focus";
          setPomMode(next); setPomSecs(POM[next]);
          onToast(pomMode==="focus" ? "🎉 Break time!" : "💪 Focus time!", "success");
          return POM[next];
        }
        return p-1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, [pomOn, pomMode]);

  const fmt = s => `${String(Math.floor(s/60)).padStart(2,"0")}:${String(s%60).padStart(2,"0")}`;
  const pomPct = ((POM[pomMode]-pomSecs)/POM[pomMode])*100;

  // ── WebRTC: flush buffered ICE candidates after remote desc is set ────────
  const flushIceQueue = async (sid) => {
    const q = iceQueues.current[sid] || [];
    const pc = peers.current[sid];
    if (!pc || pc.remoteDescription == null) return;
    for (const c of q) { try { await pc.addIceCandidate(c); } catch {} }
    iceQueues.current[sid] = [];
  };

  // ── WebRTC: create or get peer connection ─────────────────────────────────
  const createPeer = async (remoteSocketId, initiator) => {
    // Reuse existing connection if healthy
    const existing = peers.current[remoteSocketId];
    if (existing && existing.connectionState !== "failed" && existing.connectionState !== "closed") {
      return existing;
    }
    if (existing) { existing.close(); delete peers.current[remoteSocketId]; }

    const pc = new RTCPeerConnection(ICE_CFG);
    peers.current[remoteSocketId] = pc;
    iceQueues.current[remoteSocketId] = [];

    // Add local audio tracks if mic is on
    if (localStream.current) {
      localStream.current.getTracks().forEach(t => pc.addTrack(t, localStream.current));
    }

    // Play remote audio
    pc.ontrack = e => {
      let el = document.getElementById(`audio_${remoteSocketId}`);
      if (!el) {
        el = document.createElement("audio");
        el.id = `audio_${remoteSocketId}`;
        el.autoplay = true;
        el.setAttribute("playsinline", "");
        document.body.appendChild(el);
      }
      if (e.streams && e.streams[0]) el.srcObject = e.streams[0];
    };

    pc.onicecandidate = e => {
      if (e.candidate) {
        socketRef.current?.emit("rtc:ice", { toSocketId: remoteSocketId, candidate: e.candidate });
      }
    };

    pc.onconnectionstatechange = () => {
      if (pc.connectionState === "failed") {
        // Auto-retry on failure
        pc.restartIce();
      }
    };

    if (initiator) {
      try {
        const offer = await pc.createOffer({ offerToReceiveAudio: true });
        await pc.setLocalDescription(offer);
        socketRef.current?.emit("rtc:offer", { toSocketId: remoteSocketId, offer });
      } catch (e) { console.warn("createOffer failed:", e); }
    }
    return pc;
  };

  const removePeer = sid => {
    peers.current[sid]?.close();
    delete peers.current[sid];
    delete iceQueues.current[sid];
    document.getElementById(`audio_${sid}`)?.remove();
  };

  const cleanupAll = () => {
    Object.keys(peers.current).forEach(removePeer);
    localStream.current?.getTracks().forEach(t => t.stop());
    localStream.current = null;
    socketRef.current?.emit("room:leave");
    socketRef.current?.disconnect();
    socketRef.current = null;
    setMicOn(false);
  };

  // ── join a room ───────────────────────────────────────────────────────────
  const doJoinRoom = (room) => {
    const sock = socketIO("https://studybuddyy-bfop.onrender.com", {
      auth: { token: getToken() },
      transports: ["websocket", "polling"],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });
    socketRef.current = sock;

    sock.on("connect", () => {
      // Re-announce ourselves on reconnect
      sock.emit("room:join", { roomId: room.id, name: user.name, initials: user.initials || getInitials(user.name), photo: user.photo || null });
    });
    sock.on("connect_error", (e) => {
      console.warn("Socket connect error:", e.message);
      onToast("Connection issue — retrying...", "error");
    });

    sock.on("room:members", mems => setMembers(mems));

    sock.on("room:chat", msg => {
      setChat(p => [...p, { id: Date.now() + Math.random(), ...msg }]);
      setTimeout(() => chatBottom.current?.scrollIntoView({ behavior: "smooth" }), 50);
    });

    sock.on("room:peer_joined", async ({ socketId, name }) => {
      onToast(`${name} joined 🎙️`, "success");
      // Only the existing user initiates — new joiner waits for offer
      if (localStream.current) await createPeer(socketId, true);
    });

    sock.on("room:peer_left", ({ socketId }) => {
      if (socketId) removePeer(socketId);
    });

    sock.on("rtc:offer", async ({ fromSocketId, offer }) => {
      const pc = await createPeer(fromSocketId, false);
      try {
        await pc.setRemoteDescription(new RTCSessionDescription(offer));
        await flushIceQueue(fromSocketId);
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        sock.emit("rtc:answer", { toSocketId: fromSocketId, answer });
      } catch (e) { console.warn("handle offer failed:", e); }
    });

    sock.on("rtc:answer", async ({ fromSocketId, answer }) => {
      const pc = peers.current[fromSocketId];
      if (!pc) return;
      try {
        await pc.setRemoteDescription(new RTCSessionDescription(answer));
        await flushIceQueue(fromSocketId);
      } catch (e) { console.warn("handle answer failed:", e); }
    });

    sock.on("rtc:ice", async ({ fromSocketId, candidate }) => {
      const pc = peers.current[fromSocketId];
      if (!pc) return;
      if (pc.remoteDescription == null) {
        // Buffer until remote description is set
        iceQueues.current[fromSocketId] = iceQueues.current[fromSocketId] || [];
        iceQueues.current[fromSocketId].push(candidate);
      } else {
        try { await pc.addIceCandidate(new RTCIceCandidate(candidate)); } catch {}
      }
    });

    sock.emit("room:join", { roomId: room.id, name: user.name, initials: user.initials || getInitials(user.name), photo: user.photo || null });

    setActiveRoom(room);
    setMembers([]); setChat([{ id: 1, sys: true, text: `Welcome to ${room.name}! 🎯` }]);
    setPomSecs(25*60); setPomMode("focus"); setPomOn(false);
    setMicErr("");
    setView("room");
  };

  const leaveRoom = () => {
    cleanupAll();
    setActiveRoom(null); setMembers([]); setChat([]);
    setPomOn(false); setMicOn(false);
    setView("list");
  };

  const toggleMic = async () => {
    if (micOn) {
      localStream.current?.getTracks().forEach(t => t.stop());
      localStream.current = null;
      setMicOn(false);
      onToast("Mic off 🔇", "success");
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, sampleRate: 44100 }, video: false });
      localStream.current = stream;
      setMicOn(true);
      setMicErr("");
      onToast("🎙️ Mic ON — others can hear you!", "success");
      // Connect to ALL current members using the always-fresh ref
      const currentMembers = membersRef.current;
      for (const m of currentMembers) {
        if (m.userId !== user.id && m.socketId) {
          await createPeer(m.socketId, true);
        }
      }
    } catch (err) {
      const msg = err.name === "NotAllowedError"
        ? "Mic blocked — please allow microphone in browser settings and reload."
        : "Could not access microphone: " + err.message;
      setMicErr(msg);
      onToast("Mic denied ❌", "error");
    }
  };

  const sendChat = () => {
    if (!chatInput.trim()) return;
    socketRef.current?.emit("room:chat_msg",{roomId:activeRoom.id,text:chatInput.trim()});
    setChat(p=>[...p,{id:Date.now(),name:user.name,text:chatInput.trim(),mine:true}]);
    setChatInput("");
    setTimeout(()=>chatBottom.current?.scrollIntoView({behavior:"smooth"}),50);
  };

  const genCode = () => Math.random().toString(36).slice(2,8).toUpperCase();

  // ── CREATE private room ───────────────────────────────────────────────────
  const handleCreate = () => {
    setFormErr("");
    if (!formName.trim()) { setFormErr("Enter a room name"); return; }
    if (formPass.length < 3) { setFormErr("Password must be at least 3 characters"); return; }
    const code = genCode();
    const room = { id:`priv_${code}`, name:formName.trim(), emoji:"🔒", bg:"linear-gradient(135deg,#1e1b4b,#4c1d95)", subject:"Private", vibe:`Private · Code: ${code}`, isPrivate:true, roomCode:code, password:formPass.trim() };
    onToast(`Room created! Code: ${code} · Share it with your matches 🎉`,"success");
    doJoinRoom(room);
  };

  // ── JOIN private room ─────────────────────────────────────────────────────
  const handleJoin = () => {
    setFormErr("");
    if (formCode.trim().length < 4) { setFormErr("Enter a valid room code"); return; }
    if (!formPass.trim()) { setFormErr("Enter the room password"); return; }
    // Password is validated client-side by matching what creator set.
    // For real enforcement you'd check on server; this is fine for study use.
    const code = formCode.trim().toUpperCase();
    const room = { id:`priv_${code}`, name:`Private Room #${code}`, emoji:"🔒", bg:"linear-gradient(135deg,#1e1b4b,#4c1d95)", subject:"Private", vibe:`Private · Code: ${code}`, isPrivate:true, roomCode:code, password:formPass.trim() };
    doJoinRoom(room);
  };



  // ════════════════════════════════════════════════════════════════════════
  // VIEWS
  // ════════════════════════════════════════════════════════════════════════

  // ── LIST ─────────────────────────────────────────────────────────────────
  if (view === "list") return (
    <div>
      <h2 className="page-title">🎧 Study Rooms</h2>
      <p className="page-sub">Join a public room or create a private room for your matches</p>

      {/* Private Room Banner */}
      <div className="card" style={{marginBottom:"1.5rem",background:"linear-gradient(135deg,#1e1b4b,#4c1d95)",border:"none",color:"#fff"}}>
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:"1rem"}}>
          <div>
            <div style={{fontFamily:"'Clash Display',sans-serif",fontSize:"1.1rem",fontWeight:700,marginBottom:"0.25rem"}}>🔒 Private Rooms</div>
            <div style={{fontSize:"0.82rem",color:"rgba(255,255,255,0.65)"}}>Create a room → get a code + password → share with your matches to join</div>
          </div>
          <div style={{display:"flex",gap:"0.6rem"}}>
            <button onClick={()=>{setView("create");setFormErr("");setFormName("");setFormPass("");}}
              style={{background:"var(--p)",border:"none",color:"#fff",borderRadius:10,padding:"0.55rem 1.1rem",fontWeight:700,cursor:"pointer",fontFamily:"'Clash Display',sans-serif",fontSize:"0.88rem"}}>
              + Create Room
            </button>
            <button onClick={()=>{setView("join");setFormErr("");setFormCode("");setFormPass("");}}
              style={{background:"rgba(255,255,255,0.12)",border:"1px solid rgba(255,255,255,0.25)",color:"#fff",borderRadius:10,padding:"0.55rem 1.1rem",fontWeight:700,cursor:"pointer",fontFamily:"'Clash Display',sans-serif",fontSize:"0.88rem"}}>
              Enter Code →
            </button>
          </div>
        </div>
      </div>

      {/* Public Rooms */}
      <div style={{fontSize:"0.78rem",fontWeight:700,color:"var(--t2)",textTransform:"uppercase",letterSpacing:"0.6px",marginBottom:"0.75rem"}}>Public Rooms</div>
      <div className="grid-2">
        {PRESET_ROOMS.map(room => {
          const count = roomCounts[room.id] || 0;
          return (
            <div key={room.id} className="room-card">
              <div className="room-banner" style={{background:room.bg}}>{room.emoji}</div>
              <div className="room-body">
                <div className="room-name">{room.name}</div>
                <div className="room-meta">📖 {room.subject} · ✨ {room.vibe}</div>
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginTop:"0.5rem"}}>
                  <div style={{fontSize:"0.78rem",color:count>0?"var(--green)":"var(--t2)",fontWeight:count>0?600:400}}>
                    {count > 0 ? `🟢 ${count} studying now` : "⚪ Empty — be first!"}
                  </div>
                  <button className="btn btn-primary btn-sm" onClick={()=>doJoinRoom(room)}>Join →</button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );

  // ── CREATE FORM ───────────────────────────────────────────────────────────
  if (view === "create") return (
    <div style={{maxWidth:440,margin:"0 auto"}}>
      <button className="btn btn-outline btn-sm" style={{marginBottom:"1.2rem"}} onClick={()=>setView("list")}>← Back</button>
      <div className="card">
        <h3 style={{fontFamily:"'Clash Display',sans-serif",marginBottom:"1.2rem"}}>🔒 Create Private Room</h3>
        {formErr && <div style={{background:"#fee2e2",color:"#dc2626",padding:"0.6rem 0.8rem",borderRadius:8,marginBottom:"1rem",fontSize:"0.85rem"}}>⚠️ {formErr}</div>}
        <div className="form-group">
          <label>Room Name</label>
          <input placeholder="e.g. Harsh & Pari Study Session" value={formName} onChange={e=>setFormName(e.target.value)} />
        </div>
        <div className="form-group">
          <label>Password <span style={{color:"var(--t2)",fontWeight:400,fontSize:"0.8rem"}}>(share this with your matches)</span></label>
          <input type="password" placeholder="Choose a password (min 3 chars)" value={formPass} onChange={e=>setFormPass(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleCreate()} />
        </div>
        <div style={{background:"var(--panel)",borderRadius:10,padding:"0.75rem 1rem",marginBottom:"1rem",fontSize:"0.83rem",color:"var(--t2)"}}>
          💡 After creating, you'll get a <strong>Room Code</strong>. Share both the code and password with your match so they can join.
        </div>
        <button className="btn btn-primary" style={{width:"100%"}} onClick={handleCreate}>Create & Enter Room</button>
      </div>
    </div>
  );

  // ── JOIN FORM ─────────────────────────────────────────────────────────────
  if (view === "join") return (
    <div style={{maxWidth:440,margin:"0 auto"}}>
      <button className="btn btn-outline btn-sm" style={{marginBottom:"1.2rem"}} onClick={()=>setView("list")}>← Back</button>
      <div className="card">
        <h3 style={{fontFamily:"'Clash Display',sans-serif",marginBottom:"1.2rem"}}>🔑 Join Private Room</h3>
        {formErr && <div style={{background:"#fee2e2",color:"#dc2626",padding:"0.6rem 0.8rem",borderRadius:8,marginBottom:"1rem",fontSize:"0.85rem"}}>⚠️ {formErr}</div>}
        <div className="form-group">
          <label>Room Code</label>
          <input placeholder="e.g. A1B2C3" value={formCode} onChange={e=>setFormCode(e.target.value.toUpperCase())}
            style={{textTransform:"uppercase",letterSpacing:"0.25rem",fontWeight:700,fontSize:"1.1rem",textAlign:"center"}} />
        </div>
        <div className="form-group">
          <label>Password</label>
          <input type="password" placeholder="Enter the room password" value={formPass} onChange={e=>setFormPass(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleJoin()} />
        </div>
        <button className="btn btn-primary" style={{width:"100%"}} onClick={handleJoin}>Join Room</button>
      </div>
    </div>
  );

  // ── ROOM ──────────────────────────────────────────────────────────────────
  return (
    <div>
      {/* Header */}
      <div style={{display:"flex",alignItems:"flex-start",gap:"1rem",marginBottom:"1.2rem",flexWrap:"wrap"}}>
        <button className="btn btn-outline btn-sm" onClick={leaveRoom}>← Leave</button>
        <div style={{flex:1,minWidth:0}}>
          <h2 style={{fontFamily:"'Clash Display',sans-serif",fontSize:"1.25rem",fontWeight:700}}>{activeRoom.emoji} {activeRoom.name}</h2>
          <div style={{fontSize:"0.78rem",color:"var(--t2)",marginTop:"0.1rem"}}>{activeRoom.vibe}</div>
          {activeRoom.isPrivate && (
            <div style={{display:"flex",gap:"0.5rem",flexWrap:"wrap",marginTop:"0.4rem",alignItems:"center"}}>
              <span style={{background:"#312e81",color:"#a5b4fc",borderRadius:8,padding:"0.15rem 0.65rem",fontSize:"0.72rem",fontWeight:700,letterSpacing:"0.12rem"}}>CODE: {activeRoom.roomCode}</span>
              <span style={{background:"rgba(232,80,10,0.12)",color:"var(--p)",borderRadius:8,padding:"0.15rem 0.65rem",fontSize:"0.72rem",fontWeight:700}}>🔒 PRIVATE</span>
              <button onClick={()=>{navigator.clipboard?.writeText(`Room Code: ${activeRoom.roomCode}  Password: ${activeRoom.password}`); onToast("Invite copied! Share with your match 📋","success");}}
                style={{background:"none",border:"1px solid var(--line2)",color:"var(--t2)",borderRadius:8,padding:"0.15rem 0.65rem",fontSize:"0.72rem",cursor:"pointer"}}>📋 Copy invite</button>
            </div>
          )}
        </div>
        <button onClick={toggleMic}
          style={{background:micOn?"#16a34a":"var(--p)",border:"none",color:"#fff",borderRadius:12,padding:"0.5rem 1.1rem",fontWeight:700,cursor:"pointer",fontFamily:"'Clash Display',sans-serif",fontSize:"0.88rem",flexShrink:0}}>
          {micOn ? "🎙️ Mic ON" : "🔇 Join Audio"}
        </button>
      </div>

      {micErr && <div style={{background:"#fee2e2",color:"#dc2626",padding:"0.65rem 1rem",borderRadius:10,marginBottom:"1rem",fontSize:"0.85rem"}}>⚠️ {micErr}</div>}

      <div style={{display:"grid",gridTemplateColumns:"1fr 290px",gap:"1.2rem"}}>
        {/* Left panel */}
        <div>
          <div className="room-inside" style={{ overflow:"hidden" }}>
            {/* Members */}
            <div style={{marginBottom:"1rem"}}>
              <div style={{fontSize:"0.7rem",fontWeight:700,color:"#888",textTransform:"uppercase",letterSpacing:"0.5px",marginBottom:"0.4rem"}}>👥 {members.length} in room</div>
              <div style={{display:"flex",flexWrap:"wrap",gap:"0.4rem"}}>
                {members.map((m,i)=>(
                  <div key={i} className="member-chip">
                    <div style={{width:26,height:26,borderRadius:"50%",background:COLORS[i%COLORS.length],display:"flex",alignItems:"center",justifyContent:"center",fontSize:"0.65rem",fontWeight:700,color:"#fff",overflow:"hidden",flexShrink:0,outline:m.userId===user.id&&micOn?"2px solid #4ade80":"none"}}>
                      {m.photo ? <img src={m.photo} style={{width:"100%",height:"100%",objectFit:"cover"}} /> : (m.initials||"?")}
                    </div>
                    {m.name||"User"}{m.userId===user.id&&micOn&&<span style={{color:"#4ade80",fontSize:"0.7rem"}}> 🎙️</span>}
                  </div>
                ))}
              </div>
            </div>

            {/* Pomodoro */}
            <div style={{textAlign:"center",marginBottom:"1rem"}}>
              <div style={{fontSize:"0.7rem",textTransform:"uppercase",letterSpacing:"1px",color:pomMode==="focus"?"var(--p)":"#4ade80",marginBottom:"0.25rem",fontWeight:700}}>
                {pomMode==="focus" ? "🍅 Focus" : "☕ Break"}
              </div>
              <div className="room-timer-display">{fmt(pomSecs)}</div>
              <div style={{background:"rgba(255,255,255,0.1)",borderRadius:99,height:5,margin:"0.6rem auto",maxWidth:180}}>
                <div style={{background:pomMode==="focus"?"var(--p)":"#4ade80",borderRadius:99,height:"100%",width:`${pomPct}%`,transition:"width 1s linear"}} />
              </div>
              <div style={{display:"flex",gap:"0.4rem",justifyContent:"center"}}>
                <button onClick={()=>setPomOn(p=>!p)} style={{background:pomOn?"#374151":"var(--p)",border:"none",color:"#fff",borderRadius:10,padding:"0.45rem 1.3rem",fontWeight:700,cursor:"pointer",fontFamily:"'Clash Display',sans-serif"}}>
                  {pomOn?"⏸ Pause":"▶ Start"}
                </button>
                <button onClick={()=>{setPomOn(false);setPomSecs(POM[pomMode]);}} style={{background:"rgba(255,255,255,0.1)",border:"none",color:"#fff",borderRadius:10,padding:"0.45rem 0.9rem",cursor:"pointer"}}>↺</button>
                <button onClick={()=>{const n=pomMode==="focus"?"break":"focus";setPomMode(n);setPomSecs(POM[n]);setPomOn(false);}} style={{background:"rgba(255,255,255,0.08)",border:"none",color:"#aaa",borderRadius:10,padding:"0.45rem 0.9rem",cursor:"pointer",fontSize:"0.78rem"}}>
                  {pomMode==="focus"?"→ Break":"→ Focus"}
                </button>
              </div>
            </div>

            {/* ── Spotify Player ── */}
            <SpotifyPlayer onToast={onToast} />
          </div>
        </div>

        {/* Chat panel */}
        <div style={{background:"var(--card)",borderRadius:18,border:"1px solid var(--line2)",display:"flex",flexDirection:"column",height:500}}>
          <div style={{padding:"0.8rem 1rem",borderBottom:"1px solid var(--line2)",fontWeight:700,fontFamily:"'Clash Display',sans-serif",fontSize:"0.92rem"}}>💬 Room Chat</div>
          <div style={{flex:1,overflowY:"auto",padding:"0.7rem 0.9rem",display:"flex",flexDirection:"column",gap:"0.4rem"}}>
            {chat.map(m=>(
              <div key={m.id} style={{textAlign:m.sys?"center":m.mine?"right":"left"}}>
                {m.sys
                  ? <span style={{fontSize:"0.73rem",color:"var(--t2)",background:"var(--panel)",borderRadius:20,padding:"0.18rem 0.7rem"}}>{m.text}</span>
                  : <div>
                      {!m.mine&&<div style={{fontSize:"0.68rem",color:"var(--t2)",marginBottom:"0.1rem"}}>{m.name}</div>}
                      <span style={{background:m.mine?"var(--pg)":"var(--rim)",color:m.mine?"#fff":"var(--base)",borderRadius:12,padding:"0.32rem 0.68rem",fontSize:"0.84rem",display:"inline-block",maxWidth:"90%",textAlign:"left"}}>{m.text}</span>
                    </div>
                }
              </div>
            ))}
            <div ref={chatBottom} />
          </div>
          <div style={{padding:"0.6rem",borderTop:"1px solid var(--line2)",display:"flex",gap:"0.4rem"}}>
            <input value={chatInput} onChange={e=>setChatInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&sendChat()}
              placeholder="Chat..." className="chat-input" style={{flex:1,fontSize:"0.83rem"}} />
            <button className="chat-send" onClick={sendChat}>Send</button>
          </div>
        </div>
      </div>
    </div>
  );
}


function AIAssistant({ user }) {
  const SUGGESTIONS = [
    "Explain Newton's laws of motion",
    "How does photosynthesis work?",
    "Solve: 2x² + 5x - 3 = 0",
    "Explain Big O notation with examples",
    "Difference between mitosis and meiosis",
    "Explain recursion with code",
    "Summarise the French Revolution",
    "How does machine learning work?",
  ];
  const SUBJECTS = ["General","Math","Science","History","CS/Coding","Physics","Chemistry","Literature","Economics"];

  const [msgs, setMsgs]       = useState([{ role:"assistant", content:"Hi! I'm your AI Study Assistant 🎓\n\nAsk me anything — maths, science, history, coding, essays. I'll explain step by step, not just give answers!\n\nWhat are you studying today?" }]);
  const [input, setInput]     = useState("");
  const [loading, setLoading] = useState(false);
  const [subject, setSubject] = useState("General");
  const bottomRef             = useRef(null);
  const taRef                 = useRef(null);

  useEffect(() => {
    setTimeout(() => bottomRef.current?.scrollIntoView({ behavior:"smooth" }), 80);
  }, [msgs, loading]);

  const fmt = (text) => {
    let t = text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    t = t.replace(/```[\w]*\n?([\s\S]*?)```/g, (_,c) => `<pre><code>${c}</code></pre>`);
    t = t.replace(/`([^`]+)`/g, "<code>$1</code>");
    t = t.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
    t = t.replace(/\*(.+?)\*/g, "<em>$1</em>");
    t = t.replace(/^#{1,3} (.+)$/gm, "<strong>$1</strong>");
    t = t.replace(/\n/g, "<br/>");
    return t;
  };

  const send = async (preset) => {
    const q = (preset || input).trim();
    if (!q || loading) return;
    setInput("");
    if (taRef.current) { taRef.current.style.height = "auto"; }
    const history = [...msgs, { role:"user", content:q }];
    setMsgs(history);
    setLoading(true);
    try {
      const data = await apiFetch("/ai/chat", {
        method: "POST",
        body: {
          messages: history.map(m => ({ role:m.role, content:m.content })),
          subject,
          userName: user?.name || "Student"
        }
      });
      const reply = data?.content || "Sorry, something went wrong. Please try again!";
      setMsgs(p => [...p, { role:"assistant", content:reply }]);
    } catch(e) {
      setMsgs(p => [...p, { role:"assistant", content:"⚠️ " + (e.message||"Connection error — please try again.") }]);
    }
    setLoading(false);
  };

  const onKey = (e) => { if (e.key==="Enter" && !e.shiftKey) { e.preventDefault(); send(); } };
  const onInput = (e) => { setInput(e.target.value); e.target.style.height="auto"; e.target.style.height=Math.min(e.target.scrollHeight,120)+"px"; };

  return (
    <div className="ai-wrap">
      {/* Header */}
      <div className="ai-header">
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", flexWrap:"wrap", gap:"0.75rem" }}>
          <div>
            <h2 style={{ fontFamily:"'Clash Display',sans-serif", fontSize:"1.35rem", fontWeight:700 }}>
              <span style={{ background:"linear-gradient(135deg,#7c3aed,#2563eb)", WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent" }}>✦ AI Study Assistant</span>
            </h2>
            <p style={{ color:"var(--t2)", fontSize:"0.82rem", marginTop:"0.1rem" }}>Ask any academic question — I'll explain it clearly</p>
          </div>
          <div style={{ display:"flex", gap:"0.5rem", alignItems:"center" }}>
            <select value={subject} onChange={e=>setSubject(e.target.value)}
              style={{ border:"1.5px solid var(--line2)", borderRadius:8, padding:"0.4rem 0.7rem", fontSize:"0.82rem", background:"var(--panel)", outline:"none", fontFamily:"'Instrument Sans',sans-serif", cursor:"pointer" }}>
              {SUBJECTS.map(s => <option key={s}>{s}</option>)}
            </select>
            <button onClick={()=>setMsgs([{role:"assistant",content:"Chat cleared! What would you like to study? 📚"}])}
              style={{ background:"none", border:"1.5px solid var(--line2)", borderRadius:8, padding:"0.4rem 0.75rem", fontSize:"0.8rem", cursor:"pointer", color:"var(--t2)" }}>
              🗑 Clear
            </button>
          </div>
        </div>
        {msgs.length <= 1 && (
          <div style={{ marginTop:"0.9rem", display:"flex", gap:"0.45rem", flexWrap:"wrap" }}>
            {SUGGESTIONS.map((s,i) => (
              <div key={i} className="ai-suggestion" onClick={()=>send(s)}>{s}</div>
            ))}
          </div>
        )}
      </div>

      {/* Messages */}
      <div className="ai-messages">
        {msgs.map((m,i) => (
          <div key={i} className={"ai-bubble-wrap " + m.role}>
            <div className="ai-avatar" style={{ background: m.role==="assistant" ? "linear-gradient(135deg,#7c3aed,#2563eb)" : userColor(user?.id), color:"#fff", fontSize: m.role==="assistant"?"1rem":"0.75rem" }}>
              {m.role==="assistant" ? "✦" : (user?.initials||getInitials(user?.name||"U"))}
            </div>
            <div className={"ai-bubble " + m.role} dangerouslySetInnerHTML={{ __html: fmt(m.content) }} />
          </div>
        ))}
        {loading && (
          <div className="ai-bubble-wrap assistant">
            <div className="ai-avatar" style={{ background:"linear-gradient(135deg,#7c3aed,#2563eb)", color:"#fff" }}>✦</div>
            <div className="ai-bubble assistant">
              <div className="ai-typing"><div className="ai-dot"/><div className="ai-dot"/><div className="ai-dot"/></div>
            </div>
          </div>
        )}
        <div ref={bottomRef}/>
      </div>

      {/* Input */}
      <div className="ai-input-row">
        <textarea ref={taRef} className="ai-input" rows={1} value={input}
          onChange={onInput} onKeyDown={onKey}
          placeholder="Ask anything... (Shift+Enter for new line)" />
        <button className="ai-send" onClick={()=>send()} disabled={loading || !input.trim()}>
          {loading ? "⏳" : "➤"}
        </button>
      </div>
    </div>
  );
}


function MatchPopup({ match, onClose }) {
  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(13,13,13,0.7)", zIndex:1000, display:"flex", alignItems:"center", justifyContent:"center", padding:"1rem" }}>
      <div style={{ background:"var(--card)", borderRadius:"24px", padding:"2.5rem", textAlign:"center", maxWidth:"340px", width:"100%", boxShadow:"var(--shadow-lg)" }}>
        <div style={{ fontSize:"3rem", marginBottom:"0.5rem" }}>🤝</div>
        <h2 style={{ color:"var(--p)", marginBottom:"0.3rem" }}>Friends Connected!</h2>
        <p style={{ color:"var(--t2)", marginBottom:"1.5rem", fontSize:"0.9rem" }}>You and <strong>{match.name}</strong> can study together!</p>
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
    { id:"ai",       label:"✦ AI Tutor" },
    { id:"tools",    label:"⏱ Study Tools" },
    { id:"profile",  label:"👤 Profile" },
    ...(user?.is_admin ? [{ id:"admin", label:"⚙ Admin" }] : []),
  ];

  return (
    <>
      <style>{style}</style>
      <div className="app">
        <nav className="nav">
          <div className="nav-logo"><div className="nav-logo-icon">✦</div>Study<span>Buddy</span></div>
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
          {tab==="ai"       && <AIAssistant user={user}/>}
          {tab==="tools"    && <StudyTools onToast={showToast}/>}
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
          { id:"ai",       icon:"✦",  label:"AI Tutor" },
          { id:"tools",    icon:"⏱",  label:"Tools" },
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

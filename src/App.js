import { useState, useEffect } from "react";

// ─── THEME & CONSTANTS ───────────────────────────────────────────────────────
const BREACHED_PASSWORDS = new Set([
  "password","123456","password123","admin","letmein","qwerty","abc123",
  "monkey","1234567890","dragon","master","sunshine","princess","welcome",
  "shadow","superman","iloveyou","trustno1","hello","charlie","donald",
  "password1","qwerty123","football","baseball","soccer","batman","starwars",
  "pass","test","test123","user","login","access","secret","123","1234",
  "12345","654321","111111","000000","123321","654321","121212"
]);

const COMMON_PATTERNS = [
  { re: /^(.)\1+$/, label: "All same character" },
  { re: /^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i, label: "Sequential pattern" },
  { re: /^(qwerty|asdf|zxcv)/i, label: "Keyboard walk" },
  { re: /^\d+$/, label: "Numbers only" },
  { re: /^[a-z]+$/i, label: "Letters only" },
];

const PHISHING_SIGNALS = [
  { key: "ipUrl", label: "IP-based URL", weight: 25 },
  { key: "longUrl", label: "Unusually long URL", weight: 10 },
  { key: "atSymbol", label: "@ symbol in URL", weight: 20 },
  { key: "doubleSlash", label: "Double slash redirect", weight: 15 },
  { key: "prefixSuffix", label: "Dash in domain (prefix-suffix)", weight: 15 },
  { key: "subdomains", label: "Excessive subdomains", weight: 10 },
  { key: "suspiciousWords", label: "Suspicious keywords", weight: 30 },
  { key: "httpOnly", label: "HTTP (no HTTPS)", weight: 20 },
  { key: "shortUrl", label: "URL shortener", weight: 15 },
  { key: "fakeHttps", label: "'https' in path (not protocol)", weight: 20 },
];

const SENSITIVE_PATTERNS = [
  { id: "email", label: "Email Address", icon: "✉️", re: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: "medium" },
  { id: "phone", label: "Phone Number", icon: "📞", re: /(\+?[\d\s\-().]{7,15}\d)/g, severity: "medium" },
  { id: "ssn", label: "SSN / Tax ID", icon: "🪪", re: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, severity: "critical" },
  { id: "creditcard", label: "Credit Card Number", icon: "💳", re: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, severity: "critical" },
  { id: "password_text", label: "Password in Text", icon: "🔑", re: /\b(password|passwd|pwd)\s*[:=]\s*\S+/gi, severity: "critical" },
  { id: "apikey", label: "API Key / Token", icon: "🗝️", re: /\b(api[_-]?key|token|bearer|secret)\s*[:=]\s*[A-Za-z0-9_\-\.]{8,}/gi, severity: "critical" },
  { id: "ip", label: "IP Address", icon: "🌐", re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, severity: "low" },
  { id: "iban", label: "Bank / IBAN", icon: "🏦", re: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}/g, severity: "critical" },
  { id: "dob", label: "Date of Birth", icon: "🎂", re: /\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-]\d{2,4}\b/g, severity: "medium" },
];

// ─── UTILITY FUNCTIONS ───────────────────────────────────────────────────────
function analyzePassword(pwd) {
  if (!pwd) return null;
  const lower = pwd.toLowerCase();
  const isBreached = BREACHED_PASSWORDS.has(lower);
  const len = pwd.length;

  const checks = {
    length: len >= 12,
    uppercase: /[A-Z]/.test(pwd),
    lowercase: /[a-z]/.test(pwd),
    numbers: /\d/.test(pwd),
    symbols: /[^A-Za-z0-9]/.test(pwd),
    noBreached: !isBreached,
    noCommon: !COMMON_PATTERNS.some(p => p.re.test(pwd)),
  };

  const score = Object.values(checks).filter(Boolean).length;
  const patterns = COMMON_PATTERNS.filter(p => p.re.test(pwd)).map(p => p.label);
  const entropy = calculateEntropy(pwd);

  let strength, color;
  if (isBreached) { strength = "BREACHED"; color = "#ff1744"; }
  else if (score <= 2) { strength = "CRITICAL"; color = "#ff5722"; }
  else if (score <= 3) { strength = "WEAK"; color = "#ff9800"; }
  else if (score <= 5) { strength = "FAIR"; color = "#ffc107"; }
  else if (score <= 6) { strength = "GOOD"; color = "#8bc34a"; }
  else { strength = "STRONG"; color = "#00e676"; }

  const crackTime = estimateCrackTime(entropy);
  return { checks, score, patterns, entropy, strength, color, isBreached, crackTime };
}

function calculateEntropy(pwd) {
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/\d/.test(pwd)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pwd)) pool += 32;
  return pool > 0 ? Math.log2(Math.pow(pool, pwd.length)) : 0;
}

function estimateCrackTime(entropy) {
  const guesses = Math.pow(2, entropy);
  const gps = 1e10; // 10 billion guesses/sec
  const seconds = guesses / gps;
  if (seconds < 1) return "Instantly";
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds/60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds/3600)} hours`;
  if (seconds < 31536000) return `${Math.round(seconds/86400)} days`;
  if (seconds < 3.15e9) return `${Math.round(seconds/31536000)} years`;
  return "Centuries+";
}

function generateStrongPassword() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*";
  let pwd = "";
  for (let i = 0; i < 16; i++) pwd += chars[Math.floor(Math.random() * chars.length)];
  return pwd;
}

function analyzeUrl(url) {
  if (!url) return null;
  const signals = {};
  const lower = url.toLowerCase();

  signals.ipUrl = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url);
  signals.longUrl = url.length > 75;
  signals.atSymbol = url.includes("@");
  signals.doubleSlash = /[^:]\/\//.test(url.replace(/^https?:\/\//, ""));
  signals.prefixSuffix = /-/.test(url.replace(/^https?:\/\//, "").split("/")[0]);
  const dots = (url.replace(/^https?:\/\//, "").split("/")[0].match(/\./g) || []).length;
  signals.subdomains = dots > 2;
  signals.suspiciousWords = /login|verify|account|update|secure|banking|paypal|ebay|amazon|confirm|suspended|unusual|click|free|prize|winner|urgent/i.test(url);
  signals.httpOnly = url.startsWith("http://");
  signals.shortUrl = /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|buff\.ly|rb\.gy/i.test(url);
  signals.fakeHttps = lower.includes("https") && !lower.startsWith("https://");

  let riskScore = 0;
  PHISHING_SIGNALS.forEach(s => { if (signals[s.key]) riskScore += s.weight; });
  const maxScore = PHISHING_SIGNALS.reduce((a, s) => a + s.weight, 0);
  const pct = Math.min((riskScore / maxScore) * 100, 100);

  let verdict, color;
  if (pct < 15) { verdict = "SAFE"; color = "#00e676"; }
  else if (pct < 35) { verdict = "SUSPICIOUS"; color = "#ffc107"; }
  else if (pct < 55) { verdict = "LIKELY PHISHING"; color = "#ff9800"; }
  else { verdict = "PHISHING"; color = "#ff1744"; }

  const triggered = PHISHING_SIGNALS.filter(s => signals[s.key]);
  return { signals, riskScore, pct, verdict, color, triggered };
}

function scanText(text) {
  if (!text) return [];
  const findings = [];
  SENSITIVE_PATTERNS.forEach(pat => {
    const matches = [...new Set(text.match(pat.re) || [])];
    if (matches.length > 0) findings.push({ ...pat, matches, count: matches.length });
  });
  return findings;
}

function maskValue(val) {
  if (val.length <= 4) return "****";
  return val.slice(0, 2) + "*".repeat(val.length - 4) + val.slice(-2);
}

// ─── COMPONENTS ──────────────────────────────────────────────────────────────
const Scanline = () => (
  <div style={{
    position:"fixed", inset:0, pointerEvents:"none", zIndex:9999,
    background:"repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,180,0.015) 2px,rgba(0,255,180,0.015) 4px)",
    animation:"scanline 8s linear infinite"
  }}/>
);

const GlitchText = ({ text, style = {} }) => {
  return (
    <span style={{ position:"relative", display:"inline-block", ...style }}
      data-text={text}>
      {text}
    </span>
  );
};

const TerminalLine = ({ children, delay = 0, color = "#00ffb3" }) => {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), delay);
    return () => clearTimeout(t);
  }, [delay]);
  return (
    <div style={{
      fontFamily:"'Courier New', monospace", fontSize:"0.78rem", color,
      opacity: visible ? 1 : 0, transition:"opacity 0.3s",
      marginBottom:"2px", letterSpacing:"0.05em"
    }}>
      {children}
    </div>
  );
};

const NavTab = ({ id, label, icon, active, onClick }) => (
  <button onClick={() => onClick(id)} style={{
    background: active ? "rgba(0,255,179,0.12)" : "transparent",
    border: active ? "1px solid rgba(0,255,179,0.5)" : "1px solid rgba(255,255,255,0.07)",
    borderRadius:"10px", padding:"10px 18px", cursor:"pointer",
    color: active ? "#00ffb3" : "#7a8fa6",
    fontFamily:"'Courier New',monospace", fontSize:"0.78rem",
    letterSpacing:"0.08em", textTransform:"uppercase",
    transition:"all 0.2s", display:"flex", alignItems:"center", gap:"8px",
    boxShadow: active ? "0 0 20px rgba(0,255,179,0.15), inset 0 0 20px rgba(0,255,179,0.05)" : "none",
  }}>
    <span style={{fontSize:"1rem"}}>{icon}</span>{label}
  </button>
);

const Panel = ({ children, style = {} }) => (
  <div style={{
    background:"rgba(6,12,22,0.95)",
    border:"1px solid rgba(0,255,179,0.15)",
    borderRadius:"16px", padding:"28px",
    boxShadow:"0 0 40px rgba(0,255,179,0.05), inset 0 1px 0 rgba(255,255,255,0.04)",
    ...style
  }}>
    {children}
  </div>
);

const Badge = ({ label, color }) => (
  <span style={{
    background:`${color}22`, border:`1px solid ${color}66`,
    color, borderRadius:"6px", padding:"3px 10px",
    fontFamily:"'Courier New',monospace", fontSize:"0.7rem",
    letterSpacing:"0.12em", fontWeight:"700"
  }}>{label}</span>
);

const CheckRow = ({ label, ok, warn }) => (
  <div style={{
    display:"flex", alignItems:"center", gap:"10px",
    padding:"7px 12px", borderRadius:"8px",
    background: ok ? "rgba(0,230,118,0.06)" : warn ? "rgba(255,193,7,0.06)" : "rgba(255,87,34,0.06)",
    border: `1px solid ${ok ? "rgba(0,230,118,0.2)" : warn ? "rgba(255,193,7,0.2)" : "rgba(255,87,34,0.15)"}`,
    marginBottom:"6px"
  }}>
    <span style={{fontSize:"0.85rem"}}>{ok ? "✅" : warn ? "⚠️" : "❌"}</span>
    <span style={{fontFamily:"'Courier New',monospace", fontSize:"0.78rem",
      color: ok ? "#a8ffda" : warn ? "#ffe082" : "#ff8a65"}}>
      {label}
    </span>
  </div>
);

// ─── TOOL 1: PASSWORD ─────────────────────────────────────────────────────────
function PasswordTool() {
  const [pwd, setPwd] = useState("");
  const [show, setShow] = useState(false);
  const [result, setResult] = useState(null);
  const [generated, setGenerated] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setResult(analyzePassword(pwd)), 100);
    return () => clearTimeout(t);
  }, [pwd]);

  const handleGenerate = () => {
    const g = generateStrongPassword();
    setGenerated(g);
    setPwd(g);
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  const scoreWidth = result ? `${(result.score / 7) * 100}%` : "0%";

  return (
    <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:"20px"}}>
      {/* Left */}
      <Panel>
        <div style={{marginBottom:"20px"}}>
          <div style={{fontFamily:"'Courier New',monospace", color:"#00ffb3",
            fontSize:"0.7rem", letterSpacing:"0.15em", marginBottom:"8px"}}>
            // ENTER_PASSWORD
          </div>
          <div style={{position:"relative"}}>
            <input
              type={show ? "text" : "password"}
              value={pwd}
              onChange={e => setPwd(e.target.value)}
              placeholder="type your password..."
              style={{
                width:"100%", padding:"14px 50px 14px 16px",
                background:"rgba(0,255,179,0.04)", border:"1px solid rgba(0,255,179,0.2)",
                borderRadius:"10px", color:"#e0f7f0",
                fontFamily:"'Courier New',monospace", fontSize:"1rem",
                outline:"none", boxSizing:"border-box",
                transition:"border-color 0.2s",
                boxShadow:"inset 0 0 20px rgba(0,0,0,0.3)"
              }}
              onFocus={e => e.target.style.borderColor="rgba(0,255,179,0.5)"}
              onBlur={e => e.target.style.borderColor="rgba(0,255,179,0.2)"}
            />
            <button onClick={() => setShow(!show)} style={{
              position:"absolute", right:"12px", top:"50%", transform:"translateY(-50%)",
              background:"none", border:"none", cursor:"pointer", color:"#7a8fa6",
              fontSize:"1rem"
            }}>{show ? "🙈" : "👁️"}</button>
          </div>
        </div>

        {result && (
          <>
            <div style={{marginBottom:"16px"}}>
              <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"8px"}}>
                <span style={{fontFamily:"'Courier New',monospace", fontSize:"0.72rem", color:"#7a8fa6", letterSpacing:"0.1em"}}>STRENGTH_SCORE</span>
                <Badge label={result.strength} color={result.color} />
              </div>
              <div style={{height:"6px", background:"rgba(255,255,255,0.06)", borderRadius:"3px", overflow:"hidden"}}>
                <div style={{
                  height:"100%", width: scoreWidth,
                  background:`linear-gradient(90deg, ${result.color}88, ${result.color})`,
                  borderRadius:"3px", transition:"width 0.5s cubic-bezier(.4,0,.2,1)",
                  boxShadow:`0 0 12px ${result.color}88`
                }}/>
              </div>
              <div style={{display:"flex", justifyContent:"space-between", marginTop:"4px"}}>
                <span style={{fontFamily:"'Courier New',monospace", fontSize:"0.65rem", color:"#4a5f72"}}>1</span>
                <span style={{fontFamily:"'Courier New',monospace", fontSize:"0.65rem", color:"#4a5f72"}}>7</span>
              </div>
            </div>

            <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:"8px", marginBottom:"16px"}}>
              {[
                ["Entropy", `${result.entropy.toFixed(1)} bits`],
                ["Crack Time", result.crackTime],
                ["Length", `${pwd.length} chars`],
                ["Score", `${result.score}/7`],
              ].map(([k, v]) => (
                <div key={k} style={{
                  background:"rgba(255,255,255,0.03)", borderRadius:"8px",
                  padding:"10px 14px", border:"1px solid rgba(255,255,255,0.06)"
                }}>
                  <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.62rem",
                    color:"#4a5f72", letterSpacing:"0.1em", marginBottom:"3px"}}>{k.toUpperCase()}</div>
                  <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.85rem", color:"#cde8f0", fontWeight:"700"}}>{v}</div>
                </div>
              ))}
            </div>

            {result.isBreached && (
              <div style={{
                background:"rgba(255,23,68,0.1)", border:"1px solid rgba(255,23,68,0.4)",
                borderRadius:"10px", padding:"12px 16px", marginBottom:"16px",
                display:"flex", alignItems:"center", gap:"10px"
              }}>
                <span style={{fontSize:"1.2rem"}}>🚨</span>
                <div>
                  <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.75rem",
                    color:"#ff5252", fontWeight:"700", letterSpacing:"0.1em"}}>BREACH DETECTED</div>
                  <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.68rem",
                    color:"#ff8a80", marginTop:"2px"}}>This password appears in known data breach lists.</div>
                </div>
              </div>
            )}

            {result.patterns.length > 0 && (
              <div style={{marginBottom:"12px"}}>
                <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.68rem",
                  color:"#ff9800", letterSpacing:"0.1em", marginBottom:"6px"}}>⚠ PATTERNS DETECTED</div>
                {result.patterns.map(p => (
                  <div key={p} style={{fontFamily:"'Courier New',monospace", fontSize:"0.72rem",
                    color:"#ffcc80", padding:"4px 0"}}>› {p}</div>
                ))}
              </div>
            )}
          </>
        )}

        <button onClick={handleGenerate} style={{
          width:"100%", padding:"12px",
          background:"linear-gradient(135deg, rgba(0,255,179,0.15), rgba(0,200,255,0.1))",
          border:"1px solid rgba(0,255,179,0.3)", borderRadius:"10px",
          color:"#00ffb3", fontFamily:"'Courier New',monospace",
          fontSize:"0.78rem", letterSpacing:"0.1em", cursor:"pointer",
          transition:"all 0.2s", textTransform:"uppercase"
        }}>⚡ Generate Strong Password</button>

        {generated && (
          <div style={{
            marginTop:"12px", padding:"12px 16px",
            background:"rgba(0,255,179,0.05)", border:"1px solid rgba(0,255,179,0.2)",
            borderRadius:"10px", display:"flex", justifyContent:"space-between", alignItems:"center"
          }}>
            <code style={{fontFamily:"'Courier New',monospace", fontSize:"0.8rem",
              color:"#00ffb3", letterSpacing:"0.05em"}}>{generated}</code>
            <button onClick={() => handleCopy(generated)} style={{
              background:"none", border:"none", cursor:"pointer",
              color: copied ? "#00e676" : "#7a8fa6", fontSize:"0.85rem"
            }}>{copied ? "✓" : "📋"}</button>
          </div>
        )}
      </Panel>

      {/* Right */}
      <Panel>
        <div style={{fontFamily:"'Courier New',monospace", color:"#00ffb3",
          fontSize:"0.7rem", letterSpacing:"0.15em", marginBottom:"16px"}}>
          // SECURITY_CHECKS
        </div>
        {result ? (
          <div>
            <CheckRow label="Minimum 12 characters" ok={result.checks.length} />
            <CheckRow label="Uppercase letters (A-Z)" ok={result.checks.uppercase} />
            <CheckRow label="Lowercase letters (a-z)" ok={result.checks.lowercase} />
            <CheckRow label="Numeric digits (0-9)" ok={result.checks.numbers} />
            <CheckRow label="Special symbols (!@#...)" ok={result.checks.symbols} />
            <CheckRow label="Not in breach database" ok={result.checks.noBreached} />
            <CheckRow label="No common patterns" ok={result.checks.noCommon} />

            <div style={{marginTop:"20px", padding:"14px",
              background:"rgba(0,0,0,0.3)", borderRadius:"10px",
              border:"1px solid rgba(255,255,255,0.06)"}}>
              <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.68rem",
                color:"#4a5f72", letterSpacing:"0.1em", marginBottom:"8px"}}>RECOMMENDATIONS</div>
              {!result.checks.length && <TerminalLine color="#ff8a65">› Use at least 12 characters</TerminalLine>}
              {!result.checks.uppercase && <TerminalLine color="#ff8a65" delay={80}>› Add uppercase letters</TerminalLine>}
              {!result.checks.numbers && <TerminalLine color="#ff8a65" delay={160}>› Include numbers</TerminalLine>}
              {!result.checks.symbols && <TerminalLine color="#ff8a65" delay={240}>› Add special symbols</TerminalLine>}
              {result.checks.length && result.checks.uppercase && result.checks.numbers && result.checks.symbols && result.checks.noBreached && result.checks.noCommon
                ? <TerminalLine color="#00e676">› Password meets all criteria ✓</TerminalLine>
                : null}
            </div>

            <div style={{marginTop:"16px", padding:"14px",
              background:"rgba(0,0,0,0.2)", borderRadius:"10px",
              border:"1px solid rgba(255,255,255,0.04)"}}>
              <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.65rem",
                color:"#4a5f72", letterSpacing:"0.1em", marginBottom:"6px"}}>HOW IT WORKS</div>
              <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.68rem", color:"#4a5f72", lineHeight:1.7}}>
                Entropy calculated from character pool size × length. Breach check uses offline known-password list. Pattern recognition flags keyboard walks, sequences, repetition.
              </div>
            </div>
          </div>
        ) : (
          <div style={{color:"#2a3f52", fontFamily:"'Courier New',monospace",
            fontSize:"0.78rem", textAlign:"center", paddingTop:"40px"}}>
            Awaiting password input...
          </div>
        )}
      </Panel>
    </div>
  );
}

// ─── TOOL 2: PHISHING ─────────────────────────────────────────────────────────
function PhishingTool() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const handleScan = () => {
    if (!url.trim()) return;
    setScanning(true);
    setResult(null);
    setTimeout(() => {
      setResult(analyzeUrl(url.trim()));
      setScanning(false);
    }, 1200);
  };

  const examples = [
    { label: "Safe URL", url: "https://www.google.com/search?q=weather" },
    { label: "Phishing", url: "http://paypal-account-verify.suspicious-login.com/update?user=@admin" },
    { label: "Shortened", url: "http://bit.ly/3xFakeLink" },
    { label: "IP-based", url: "http://192.168.1.1/login/verify/account" },
  ];

  return (
    <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:"20px"}}>
      <Panel>
        <div style={{fontFamily:"'Courier New',monospace", color:"#00ffb3",
          fontSize:"0.7rem", letterSpacing:"0.15em", marginBottom:"16px"}}>
          // URL_ANALYSIS_ENGINE
        </div>

        <div style={{marginBottom:"12px"}}>
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleScan()}
            placeholder="https://example.com/path?param=value"
            style={{
              width:"100%", padding:"14px 16px",
              background:"rgba(0,255,179,0.04)", border:"1px solid rgba(0,255,179,0.2)",
              borderRadius:"10px", color:"#e0f7f0",
              fontFamily:"'Courier New',monospace", fontSize:"0.82rem",
              outline:"none", boxSizing:"border-box"
            }}
          />
        </div>

        <button onClick={handleScan} disabled={scanning || !url.trim()} style={{
          width:"100%", padding:"13px",
          background: scanning ? "rgba(0,255,179,0.05)" : "linear-gradient(135deg,rgba(0,255,179,0.18),rgba(0,200,255,0.12))",
          border:`1px solid ${scanning ? "rgba(0,255,179,0.15)" : "rgba(0,255,179,0.4)"}`,
          borderRadius:"10px", color: scanning ? "#4a7a6a" : "#00ffb3",
          fontFamily:"'Courier New',monospace", fontSize:"0.8rem",
          letterSpacing:"0.1em", cursor: scanning ? "default" : "pointer",
          textTransform:"uppercase", marginBottom:"16px"
        }}>
          {scanning ? "🔍 SCANNING..." : "🔍 ANALYZE URL"}
        </button>

        <div style={{marginBottom:"16px"}}>
          <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.65rem",
            color:"#4a5f72", letterSpacing:"0.12em", marginBottom:"8px"}}>QUICK EXAMPLES</div>
          <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:"6px"}}>
            {examples.map(ex => (
              <button key={ex.label} onClick={() => setUrl(ex.url)} style={{
                background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.07)",
                borderRadius:"7px", padding:"7px 10px", cursor:"pointer",
                color:"#7a8fa6", fontFamily:"'Courier New',monospace",
                fontSize:"0.68rem", textAlign:"left", transition:"all 0.15s"
              }}>{ex.label}</button>
            ))}
          </div>
        </div>

        {result && (
          <div style={{
            padding:"20px", borderRadius:"14px", textAlign:"center",
            background:`rgba(${result.verdict==="SAFE"?"0,230,118":result.verdict==="PHISHING"?"255,23,68":"255,152,0"},0.07)`,
            border:`1px solid ${result.color}44`
          }}>
            <div style={{fontSize:"2.5rem", marginBottom:"8px"}}>
              {result.verdict==="SAFE" ? "🛡️" : result.verdict==="PHISHING" ? "🎣" : "⚠️"}
            </div>
            <Badge label={result.verdict} color={result.color} />
            <div style={{marginTop:"14px"}}>
              <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.65rem",
                color:"#4a5f72", letterSpacing:"0.1em", marginBottom:"4px"}}>RISK SCORE</div>
              <div style={{height:"8px", background:"rgba(255,255,255,0.06)", borderRadius:"4px", overflow:"hidden"}}>
                <div style={{
                  height:"100%", width:`${result.pct}%`,
                  background:`linear-gradient(90deg,${result.color}66,${result.color})`,
                  borderRadius:"4px", boxShadow:`0 0 10px ${result.color}88`,
                  transition:"width 0.8s cubic-bezier(.4,0,.2,1)"
                }}/>
              </div>
              <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.78rem",
                color:result.color, marginTop:"6px", fontWeight:"700"}}>{result.pct.toFixed(0)}% Risk</div>
            </div>
          </div>
        )}
      </Panel>

      <Panel>
        <div style={{fontFamily:"'Courier New',monospace", color:"#00ffb3",
          fontSize:"0.7rem", letterSpacing:"0.15em", marginBottom:"16px"}}>
          // SIGNAL_ANALYSIS
        </div>

        {result ? (
          <>
            <div style={{marginBottom:"16px"}}>
              {PHISHING_SIGNALS.map(s => {
                const active = result.signals[s.key];
                return (
                  <div key={s.key} style={{
                    display:"flex", justifyContent:"space-between", alignItems:"center",
                    padding:"7px 12px", borderRadius:"7px", marginBottom:"5px",
                    background: active ? "rgba(255,87,34,0.07)" : "rgba(255,255,255,0.02)",
                    border:`1px solid ${active ? "rgba(255,87,34,0.25)" : "rgba(255,255,255,0.04)"}`
                  }}>
                    <div style={{display:"flex", alignItems:"center", gap:"8px"}}>
                      <span style={{fontSize:"0.75rem"}}>{active ? "🔴" : "🟢"}</span>
                      <span style={{fontFamily:"'Courier New',monospace", fontSize:"0.72rem",
                        color: active ? "#ff8a65" : "#4a5f72"}}>{s.label}</span>
                    </div>
                    <span style={{fontFamily:"'Courier New',monospace", fontSize:"0.65rem",
                      color: active ? "#ff5722" : "#2a3f52"}}>+{s.weight}</span>
                  </div>
                );
              })}
            </div>

            <div style={{padding:"12px", background:"rgba(0,0,0,0.3)",
              borderRadius:"10px", border:"1px solid rgba(255,255,255,0.04)"}}>
              <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.65rem",
                color:"#4a5f72", letterSpacing:"0.1em", marginBottom:"6px"}}>HOW IT WORKS</div>
              <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.67rem",
                color:"#4a5f72", lineHeight:1.7}}>
                Weighted signal scoring across 10 URL features. IP addresses, suspicious keywords, missing HTTPS, URL shorteners, and excessive subdomains each contribute risk points.
              </div>
            </div>
          </>
        ) : (
          <div style={{color:"#2a3f52", fontFamily:"'Courier New',monospace",
            fontSize:"0.78rem", textAlign:"center", paddingTop:"40px"}}>
            {scanning ? (
              <div>
                {["Parsing URL structure...", "Checking domain patterns...", "Scoring risk signals...", "Finalizing analysis..."].map((msg, i) => (
                  <TerminalLine key={msg} color="#00ffb3" delay={i * 250}>&gt; {msg}</TerminalLine>
                ))}
              </div>
            ) : "Enter a URL and click Analyze."}
          </div>
        )}
      </Panel>
    </div>
  );
}

// ─── TOOL 3: DATA LEAK ────────────────────────────────────────────────────────
function DataLeakTool() {
  const [text, setText] = useState("");
  const [findings, setFindings] = useState([]);
  const [mask, setMask] = useState(true);
  const [scanned, setScanned] = useState(false);

  const handleScan = () => {
    setFindings(scanText(text));
    setScanned(true);
  };

  const severityColor = { critical: "#ff1744", medium: "#ff9800", low: "#ffc107" };
  const totalRisk = findings.reduce((a, f) => a + (f.severity === "critical" ? 3 : f.severity === "medium" ? 2 : 1) * f.count, 0);

  const sampleText = `Hi team, please find my details:
Email: john.smith@company.com
Phone: +91-9876543210
SSN: 123-45-6789
Credit Card: 4532 1234 5678 9012
API_KEY: sk-live-abc123XYZ789secret
DOB: 15/03/1990
IBAN: GB29NWBK60161331926819
Password: hunter2
Server IP: 192.168.0.101`;

  return (
    <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:"20px"}}>
      <Panel>
        <div style={{fontFamily:"'Courier New',monospace", color:"#00ffb3",
          fontSize:"0.7rem", letterSpacing:"0.15em", marginBottom:"16px"}}>
          // PASTE_TEXT_FOR_SCANNING
        </div>

        <textarea
          value={text}
          onChange={e => { setText(e.target.value); setScanned(false); }}
          placeholder="Paste any text, document content, email, message, or configuration file here..."
          rows={10}
          style={{
            width:"100%", padding:"14px",
            background:"rgba(0,255,179,0.03)", border:"1px solid rgba(0,255,179,0.15)",
            borderRadius:"10px", color:"#cde8f0",
            fontFamily:"'Courier New',monospace", fontSize:"0.78rem", lineHeight:1.7,
            outline:"none", resize:"vertical", boxSizing:"border-box",
            boxShadow:"inset 0 0 30px rgba(0,0,0,0.3)"
          }}
        />

        <div style={{display:"flex", gap:"8px", marginTop:"12px"}}>
          <button onClick={handleScan} disabled={!text.trim()} style={{
            flex:1, padding:"12px",
            background:"linear-gradient(135deg,rgba(0,255,179,0.18),rgba(0,200,255,0.12))",
            border:"1px solid rgba(0,255,179,0.4)", borderRadius:"10px",
            color:"#00ffb3", fontFamily:"'Courier New',monospace",
            fontSize:"0.78rem", letterSpacing:"0.1em", cursor:"pointer",
            textTransform:"uppercase"
          }}>🔎 Scan for Leaks</button>

          <button onClick={() => setText(sampleText)} style={{
            padding:"12px 16px",
            background:"rgba(255,255,255,0.03)", border:"1px solid rgba(255,255,255,0.08)",
            borderRadius:"10px", color:"#7a8fa6",
            fontFamily:"'Courier New',monospace", fontSize:"0.72rem",
            cursor:"pointer"
          }}>Load Sample</button>

          <button onClick={() => { setText(""); setFindings([]); setScanned(false); }} style={{
            padding:"12px 16px",
            background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.06)",
            borderRadius:"10px", color:"#4a5f72",
            fontFamily:"'Courier New',monospace", fontSize:"0.72rem",
            cursor:"pointer"
          }}>Clear</button>
        </div>

        {scanned && (
          <div style={{
            marginTop:"16px", padding:"16px", borderRadius:"12px",
            background: findings.length ? "rgba(255,23,68,0.08)" : "rgba(0,230,118,0.08)",
            border:`1px solid ${findings.length ? "rgba(255,23,68,0.3)" : "rgba(0,230,118,0.3)"}`
          }}>
            <div style={{display:"flex", justifyContent:"space-between", alignItems:"center"}}>
              <div>
                <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.75rem",
                  color: findings.length ? "#ff5252" : "#00e676", fontWeight:"700",
                  letterSpacing:"0.1em"}}>
                  {findings.length ? `${findings.length} LEAK TYPE${findings.length>1?"S":""} DETECTED` : "NO SENSITIVE DATA FOUND"}
                </div>
                <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.67rem",
                  color:"#7a8fa6", marginTop:"3px"}}>
                  {text.split(/\s+/).length} words · {text.length} chars scanned
                </div>
              </div>
              {findings.length > 0 && (
                <div style={{textAlign:"right"}}>
                  <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.65rem",
                    color:"#4a5f72", letterSpacing:"0.1em"}}>RISK LEVEL</div>
                  <div style={{fontFamily:"'Courier New',monospace", fontSize:"1.1rem",
                    color: totalRisk > 10 ? "#ff1744" : totalRisk > 5 ? "#ff9800" : "#ffc107",
                    fontWeight:"700"}}>{totalRisk > 10 ? "CRITICAL" : totalRisk > 5 ? "HIGH" : "MEDIUM"}</div>
                </div>
              )}
            </div>
          </div>
        )}
      </Panel>

      <Panel>
        <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"16px"}}>
          <div style={{fontFamily:"'Courier New',monospace", color:"#00ffb3",
            fontSize:"0.7rem", letterSpacing:"0.15em"}}>
            // LEAK_REPORT
          </div>
          {findings.length > 0 && (
            <button onClick={() => setMask(!mask)} style={{
              background:"rgba(255,255,255,0.04)", border:"1px solid rgba(255,255,255,0.1)",
              borderRadius:"6px", padding:"4px 10px", cursor:"pointer",
              color:"#7a8fa6", fontFamily:"'Courier New',monospace", fontSize:"0.68rem"
            }}>{mask ? "👁 Reveal" : "🙈 Mask"}</button>
          )}
        </div>

        {findings.length > 0 ? (
          <div style={{maxHeight:"420px", overflowY:"auto",
            scrollbarWidth:"thin", scrollbarColor:"rgba(0,255,179,0.2) transparent"}}>
            {findings.map(f => (
              <div key={f.id} style={{
                marginBottom:"12px", borderRadius:"10px", overflow:"hidden",
                border:`1px solid ${severityColor[f.severity]}33`
              }}>
                <div style={{
                  padding:"10px 14px",
                  background:`rgba(${f.severity==="critical"?"255,23,68":f.severity==="medium"?"255,152,0":"255,193,7"},0.1)`,
                  display:"flex", justifyContent:"space-between", alignItems:"center"
                }}>
                  <div style={{display:"flex", alignItems:"center", gap:"8px"}}>
                    <span style={{fontSize:"1rem"}}>{f.icon}</span>
                    <span style={{fontFamily:"'Courier New',monospace", fontSize:"0.75rem",
                      color:"#cde8f0", letterSpacing:"0.08em"}}>{f.label}</span>
                  </div>
                  <div style={{display:"flex", alignItems:"center", gap:"8px"}}>
                    <Badge label={f.severity.toUpperCase()} color={severityColor[f.severity]} />
                    <span style={{fontFamily:"'Courier New',monospace", fontSize:"0.7rem",
                      color:"#4a5f72"}}>×{f.count}</span>
                  </div>
                </div>
                <div style={{padding:"10px 14px", background:"rgba(0,0,0,0.2)"}}>
                  {f.matches.slice(0, 3).map((m, i) => (
                    <div key={i} style={{fontFamily:"'Courier New',monospace", fontSize:"0.75rem",
                      color: severityColor[f.severity], padding:"2px 0",
                      wordBreak:"break-all"}}>
                      › {mask ? maskValue(m) : m}
                    </div>
                  ))}
                  {f.matches.length > 3 && (
                    <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.67rem",
                      color:"#4a5f72", marginTop:"4px"}}>
                      +{f.matches.length - 3} more instances
                    </div>
                  )}
                </div>
              </div>
            ))}

            <div style={{padding:"12px", background:"rgba(0,0,0,0.3)",
              borderRadius:"10px", border:"1px solid rgba(255,255,255,0.04)", marginTop:"8px"}}>
              <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.65rem",
                color:"#4a5f72", letterSpacing:"0.1em", marginBottom:"6px"}}>HOW IT WORKS</div>
              <div style={{fontFamily:"'Courier New',monospace", fontSize:"0.67rem",
                color:"#4a5f72", lineHeight:1.7}}>
                9 regex patterns scan for emails, phones, SSNs, credit cards, API keys, IBANs, IPs, passwords, and DOBs. Severity weighting helps prioritize remediation.
              </div>
            </div>
          </div>
        ) : (
          <div style={{color:"#2a3f52", fontFamily:"'Courier New',monospace",
            fontSize:"0.78rem", textAlign:"center", paddingTop:"40px"}}>
            {scanned ? (
              <>
                <div style={{fontSize:"2rem", marginBottom:"12px"}}>✅</div>
                <div style={{color:"#00e676"}}>No sensitive data patterns found.</div>
                <div style={{fontSize:"0.68rem", color:"#2a3f52", marginTop:"8px"}}>Text appears safe to share.</div>
              </>
            ) : (
              <>
                <div style={{fontSize:"2rem", marginBottom:"12px"}}>🔎</div>
                <div>Paste text and click scan to detect leaked data.</div>
                <div style={{fontSize:"0.68rem", color:"#2a3f52", marginTop:"8px"}}>Try the "Load Sample" button.</div>
              </>
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}

// ─── MAIN APP ────────────────────────────────────────────────────────────────
export default function App() {
  const [tab, setTab] = useState("password");
  const [booted, setBooted] = useState(false);

  useEffect(() => {
    setTimeout(() => setBooted(true), 600);
  }, []);

  const tools = [
    { id:"password", icon:"🔐", label:"Password Analyzer" },
    { id:"phishing", icon:"🎣", label:"Phishing Detector" },
    { id:"dataleak", icon:"🔏", label:"Data Leak Scanner" },
  ];

  return (
    <div style={{
      minHeight:"100vh", background:"#020810",
      backgroundImage:"radial-gradient(ellipse at 20% 20%, rgba(0,255,179,0.04) 0%, transparent 50%), radial-gradient(ellipse at 80% 80%, rgba(0,100,255,0.04) 0%, transparent 50%)",
      fontFamily:"'Courier New',monospace",
      opacity: booted ? 1 : 0, transition:"opacity 0.5s"
    }}>
      <Scanline />
      <style>{`
        @keyframes scanline { 0% { backgroundPosition: 0 0; } 100% { backgroundPosition: 0 100vh; } }
        @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.4; } }
        @keyframes glow { 0%,100% { textShadow: 0 0 10px rgba(0,255,179,0.3); } 50% { textShadow: 0 0 20px rgba(0,255,179,0.7), 0 0 40px rgba(0,255,179,0.3); } }
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: transparent; } ::-webkit-scrollbar-thumb { background: rgba(0,255,179,0.2); border-radius: 2px; }
        input::placeholder, textarea::placeholder { color: #2a3f52; }
        * { box-sizing: border-box; }
      `}</style>

      <div style={{maxWidth:"1080px", margin:"0 auto", padding:"32px 20px"}}>
        {/* Header */}
        <div style={{marginBottom:"36px", borderBottom:"1px solid rgba(0,255,179,0.08)", paddingBottom:"28px"}}>
          <div style={{display:"flex", alignItems:"flex-start", justifyContent:"space-between", flexWrap:"wrap", gap:"16px"}}>
            <div>
              <div style={{fontSize:"0.65rem", letterSpacing:"0.25em", color:"#00ffb3",
                marginBottom:"6px", animation:"pulse 2s infinite"}}>
                ◉ SYSTEM ACTIVE 
              </div>
              <h1 style={{
                margin:0, fontSize:"clamp(1.4rem,3vw,2rem)",
                fontWeight:"700", letterSpacing:"0.05em",
                background:"linear-gradient(135deg,#00ffb3,#00c8ff,#7c4dff)",
                WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent",
                animation:"glow 3s ease-in-out infinite"
              }}>
                SMART USER PROTECTION SUITE
              </h1>
              <div style={{fontSize:"0.72rem", color:"#4a5f72", letterSpacing:"0.1em", marginTop:"4px"}}>
                 CYBERSECURITY · v2.0 · 3 PROTECTION MODULES
              </div>
            </div>
            <div style={{display:"flex", gap:"6px", flexWrap:"wrap"}}>
              {["ML", "AI", "SECURE", "PRIVACY"].map(tag => (
                <span key={tag} style={{
                  background:"rgba(0,255,179,0.06)", border:"1px solid rgba(0,255,179,0.15)",
                  borderRadius:"4px", padding:"3px 8px", fontSize:"0.6rem",
                  color:"#00ffb3", letterSpacing:"0.12em"
                }}>{tag}</span>
              ))}
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div style={{display:"flex", gap:"10px", marginBottom:"24px", flexWrap:"wrap"}}>
          {tools.map(t => (
            <NavTab key={t.id} {...t} active={tab === t.id} onClick={setTab} />
          ))}
        </div>

        {/* Tool Area */}
        <div style={{animation:"fadeIn 0.3s ease"}}>
          {tab === "password" && <PasswordTool />}
          {tab === "phishing" && <PhishingTool />}
          {tab === "dataleak" && <DataLeakTool />}
        </div>

        {/* Footer */}
        <div style={{marginTop:"32px", paddingTop:"20px",
          borderTop:"1px solid rgba(0,255,179,0.06)",
          display:"flex", justifyContent:"space-between", alignItems:"center",
          flexWrap:"wrap", gap:"12px"}}>
          <div style={{fontSize:"0.62rem", color:"#2a3f52", letterSpacing:"0.1em"}}>
            ALL ANALYSIS IS PERFORMED CLIENT-SIDE · NO DATA TRANSMITTED · PRIVACY-FIRST DESIGN
          </div>
          <div style={{fontSize:"0.62rem", color:"#2a3f52", letterSpacing:"0.1em"}}>
            SMART PROTECTION SUITE © 2025
          </div>
        </div>
      </div>
    </div>
  );
}

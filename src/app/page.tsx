"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useSession, signOut } from "next-auth/react";
import WebShieldLogo from "@/components/WebShieldLogo";
import { useTheme } from "@/components/ThemeProvider";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Search,
  ChevronRight,
  LogOut,
  User,
  Globe,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Code,
  FileText,
  Lock,
  Copy,
  Check,
  Sun,
  Moon,
  Flame,
  AlertOctagon,
  LayoutDashboard,
  ScanLine,
  BarChart2,
  Settings,
  ExternalLink,
  Activity,
  TrendingUp,
  Download,
  Eye,
  EyeOff,
  Save,
  Bell,
  Zap,
  CircleDot,
  CheckCircle,
  XCircle,
  Clock,
  Key,
  Mail,
  UserCircle,
  ChevronDown,
  Menu,
  X,
  Sparkles,
  Laptop,
  Smartphone,
  Monitor,
} from "lucide-react";

interface Vulnerability {
  title: string;
  severity: string;
  category?: string;
  cvss?: string;
  description: string;
  impact?: string;
}

interface ScanResultData {
  score: number;
  grade: string;
  threatLevel?: string;
  fatalFindingsCount?: number;
  summary: string;
  vulnerabilities: Vulnerability[];
  recommendations?: string[];
}

interface ScanItem {
  id: string;
  targetUrl: string;
  score: number;
  grade: string;
  results: ScanResultData;
  createdAt: string;
}

interface UserProfile {
  name?: string | null;
  email?: string | null;
  image?: string | null;
}

type NavId = "dashboard" | "scans" | "reports" | "settings";

const SCAN_STEPS = [
  "Resolving DNS & probing TLS…",
  "Auditing HTTP headers & security policies…",
  "Scanning RCE, SQLi, SSRF attack surface…",
  "Checking exposed keys & endpoints…",
  "Generating vulnerability report…",
];

const NAV_ITEMS: { icon: React.ElementType; label: string; id: NavId }[] = [
  { icon: LayoutDashboard, label: "Dashboard", id: "dashboard" },
  { icon: ScanLine,        label: "Scans",     id: "scans"     },
  { icon: BarChart2,       label: "Reports",   id: "reports"   },
  { icon: Settings,        label: "Settings",  id: "settings"  },
];

const PRESET_TARGETS = [
  "http://testphp.vulnweb.com",
  "https://juice-shop.herokuapp.com",
  "https://ginandjuice.shop",
];

function gradeColor(score: number) {
  if (score >= 80) return "text-emerald-500";
  if (score >= 50) return "text-amber-500";
  return "text-rose-500";
}

function riskBadge(score: number, isDark: boolean) {
  if (score >= 80) return isDark
    ? "text-emerald-400 bg-emerald-950/50 border-emerald-800"
    : "text-emerald-700 bg-emerald-50 border-emerald-200";
  if (score >= 60) return isDark
    ? "text-amber-400 bg-amber-950/50 border-amber-800"
    : "text-amber-700 bg-amber-50 border-amber-200";
  if (score >= 40) return isDark
    ? "text-orange-400 bg-orange-950/50 border-orange-800"
    : "text-orange-700 bg-orange-50 border-orange-200";
  return isDark
    ? "text-rose-400 bg-rose-950/50 border-rose-800"
    : "text-rose-700 bg-rose-50 border-rose-200";
}

function riskLabel(score: number) {
  if (score >= 80) return "Low";
  if (score >= 60) return "Medium";
  if (score >= 40) return "High";
  return "Critical";
}

function severityBadge(s: string, isDark: boolean) {
  const l = s.toLowerCase();
  if (l.includes("kritis") || l.includes("crit") || l.includes("fatal"))
    return {
      label: "Critical",
      badge: isDark ? "text-rose-300 bg-rose-950/70 border-rose-800" : "text-rose-700 bg-rose-100 border-rose-300",
      fatal: true,
    };
  if (l.includes("tinggi") || l.includes("high"))
    return {
      label: "High",
      badge: isDark ? "text-amber-300 bg-amber-950/60 border-amber-800" : "text-amber-700 bg-amber-100 border-amber-300",
      fatal: false,
    };
  if (l.includes("sedang") || l.includes("med"))
    return {
      label: "Medium",
      badge: isDark ? "text-yellow-300 bg-yellow-950/40 border-yellow-800" : "text-yellow-700 bg-yellow-100 border-yellow-300",
      fatal: false,
    };
  return {
    label: "Low",
    badge: isDark ? "text-slate-400 bg-slate-800/60 border-slate-700" : "text-slate-600 bg-slate-100 border-slate-300",
    fatal: false,
  };
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-GB", {
    day: "2-digit", month: "short", year: "numeric",
  });
}

function getCritCount(item: ScanItem) {
  return item.results?.fatalFindingsCount ??
    item.results?.vulnerabilities?.filter(v => {
      const s = v.severity.toLowerCase();
      return s.includes("kritis") || s.includes("crit") || s.includes("fatal");
    }).length ?? 0;
}

function Toggle({
  checked, onChange, isDark,
}: { checked: boolean; onChange: (v: boolean) => void; isDark: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex w-9 h-5 rounded-full border transition-colors duration-200 focus:outline-none ${
        checked
          ? "bg-cyan-600 border-cyan-500"
          : isDark ? "bg-slate-700 border-slate-600" : "bg-slate-200 border-slate-300"
      }`}
    >
      <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow-sm transition-transform duration-200 ${
        checked ? "translate-x-4" : "translate-x-0"
      }`} />
    </button>
  );
}

export default function DashboardPage() {
  const { data: session, status } = useSession();
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";

    const [activeNav, setActiveNav]       = useState<NavId>("dashboard");
  const [user, setUser]                 = useState<UserProfile | null>(null);
  const [history, setHistory]           = useState<ScanItem[]>([]);

    const [targetUrl, setTargetUrl]       = useState("");
  const [loading, setLoading]           = useState(false);
  const [loadingStep, setLoadingStep]   = useState(0);
  const [scanResult, setScanResult]     = useState<ScanResultData | null>(null);
  const [scanError, setScanError]       = useState("");
  const [selectedScan, setSelectedScan] = useState<ScanItem | null>(null);
  const [activeTab, setActiveTab]       = useState<"analysis" | "json">("analysis");
  const [copied, setCopied]             = useState(false);

    const [settingsName, setSettingsName]           = useState("");
  const [settingsEmail, setSettingsEmail]         = useState("");
  const [apiKey, setApiKey]                       = useState("");
  const [showApiKey, setShowApiKey]               = useState(false);
  const [emailNotif, setEmailNotif]               = useState(true);
  const [deepScan, setDeepScan]                   = useState(false);
  const [settingsSaved, setSettingsSaved]         = useState(false);
  const [sidebarOpen, setSidebarOpen]             = useState(true);

    useEffect(() => {
    if (typeof window !== "undefined" && window.innerWidth < 1024) {
      setSidebarOpen(false);
    }
  }, []);

    const [installModalOpen, setInstallModalOpen]   = useState(false);
  const [activePlatformTab, setActivePlatformTab] = useState<"desktop" | "ios" | "android">("desktop");
  const [deferredPrompt, setDeferredPrompt]       = useState<any>(null);
  const [isAppInstalled, setIsAppInstalled]       = useState(false);

  const handleApiKeyChange = (val: string) => {
    setApiKey(val);
    try {
      localStorage.setItem("webshield_gemini_api_key", val);
    } catch {}
  };

    const [scansTarget, setScansTarget]   = useState("");
  const [scanProtocol, setScanProtocol] = useState<"https" | "http">("https");

  const router = useRouter();

    const fetchHistory = useCallback(async () => {
    try {
      const res  = await fetch("/api/history");
      const data = await res.json();
      if (data.success && Array.isArray(data.data)) setHistory(data.data);
    } catch {}
  }, []);

    useEffect(() => {
    if (typeof window !== "undefined") {
      const storedInstalled = localStorage.getItem("pwa_installed");
      if (storedInstalled === "true" || window.matchMedia("(display-mode: standalone)").matches || (window.navigator as any).standalone) {
        setIsAppInstalled(true);
      }

      const handleBeforeInstall = (e: Event) => {
        e.preventDefault();
        setDeferredPrompt(e);
      };

      const handleAppInstalled = () => {
        setIsAppInstalled(true);
        setDeferredPrompt(null);
        try {
          localStorage.setItem("pwa_installed", "true");
        } catch {}
      };

      window.addEventListener("beforeinstallprompt", handleBeforeInstall);
      window.addEventListener("appinstalled", handleAppInstalled);

      return () => {
        window.removeEventListener("beforeinstallprompt", handleBeforeInstall);
        window.removeEventListener("appinstalled", handleAppInstalled);
      };
    }
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setInstallModalOpen(false);
      }
    };
    if (installModalOpen) {
      window.addEventListener("keydown", handleKeyDown);
    }
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [installModalOpen]);

  const handleInstallClick = () => {
    setInstallModalOpen(true);
  };

  const handleNativeInstall = async () => {
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    const choice = await deferredPrompt.userChoice;
    if (choice?.outcome === "accepted") {
      setIsAppInstalled(true);
      setDeferredPrompt(null);
      setInstallModalOpen(false);
      try {
        localStorage.setItem("pwa_installed", "true");
      } catch {}
    }
  };

    useEffect(() => {
    const storedApiKey = localStorage.getItem("webshield_gemini_api_key");
    if (storedApiKey) {
      setApiKey(storedApiKey);
    }

    const saved = localStorage.getItem("user");
    if (saved) {
      try {
        const u = JSON.parse(saved);
        setUser(u);
        setSettingsName(u.name || "");
        setSettingsEmail(u.email || "");
      } catch {}
      fetchHistory();
      return;
    }
    if (status === "authenticated" && session?.user) {
      const p = { name: session.user.name, email: session.user.email, image: session.user.image };
      setUser(p);
      setSettingsName(p.name || "");
      setSettingsEmail(p.email || "");
      localStorage.setItem("user", JSON.stringify(p));
      fetchHistory();
      return;
    }
    if (status === "unauthenticated" && !saved) router.replace("/login");
  }, [session, status, router, fetchHistory]);

    useEffect(() => {
    if (!loading) return;
    const t = setInterval(() => setLoadingStep(p => (p + 1) % SCAN_STEPS.length), 700);
    return () => clearInterval(t);
  }, [loading]);

    const runScan = useCallback(async (url: string) => {
    if (!url) return;
    setLoading(true);
    setLoadingStep(0);
    setScanResult(null);
    setScanError("");
    setSelectedScan(null);
    setActiveNav("dashboard");
    try {
      const res  = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targetUrl: url, geminiApiKey: apiKey }),
      });
      const data = await res.json();
      if (data.success) { setScanResult(data.data.results as ScanResultData); fetchHistory(); }
      else setScanError(data.message || "Scan failed.");
    } catch { setScanError("Could not reach the server."); }
    finally { setLoading(false); }
  }, [fetchHistory]);

  const handleHeaderScan = (e: React.FormEvent) => {
    e.preventDefault();
    runScan(targetUrl);
  };

  const handleScanPageSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const full = scansTarget.startsWith("http") ? scansTarget : `${scanProtocol}://${scansTarget}`;
    setTargetUrl(full);
    runScan(full);
  };

  const handleLogout = async () => {
    localStorage.removeItem("user");
    await signOut({ callbackUrl: "/login" });
  };

  const handleCopyJson = () => {
    if (!displayResult) return;
    navigator.clipboard.writeText(JSON.stringify(displayResult, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSaveSettings = () => {
    const updated = { ...user, name: settingsName, email: settingsEmail };
    setUser(updated);
    localStorage.setItem("user", JSON.stringify(updated));
    localStorage.setItem("webshield_gemini_api_key", apiKey);
    setSettingsSaved(true);
    setTimeout(() => setSettingsSaved(false), 2500);
  };

  const handleDownloadCSV = (item: ScanItem) => {
    const rows = [
      ["Target", "Date", "Score", "Grade", "Vulnerabilities", "Critical"],
      [
        item.targetUrl,
        fmtDate(item.createdAt),
        String(item.score),
        item.grade,
        String(item.results?.vulnerabilities?.length ?? 0),
        String(getCritCount(item)),
      ],
      ...(item.results?.vulnerabilities?.map(v => [v.title, v.severity, v.cvss ?? "", v.description]) ?? []),
    ];
    const csv  = rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const a    = document.createElement("a");
    a.href     = URL.createObjectURL(blob);
    a.download = `webshield-report-${item.targetUrl.replace(/^https?:\/\//, "").replace(/\//g, "-")}.csv`;
    a.click();
  };

    const displayResult = selectedScan ? selectedScan.results : scanResult;
  const displayUrl    = selectedScan ? selectedScan.targetUrl : targetUrl;

  const fatalCount = displayResult?.fatalFindingsCount ??
    (displayResult?.vulnerabilities?.filter(v => {
      const s = v.severity.toLowerCase();
      return s.includes("kritis") || s.includes("crit") || s.includes("fatal");
    }).length ?? 0);

  const totalScans = history.length;
  const totalCrit  = history.reduce((acc, h) => acc + getCritCount(h), 0);
  const avgScore   = totalScans > 0
    ? Math.round(history.reduce((a, h) => a + h.score, 0) / totalScans)
    : 0;

    const D = {
    sidebar:     "bg-[#0B0F17]",
    topbar:      isDark ? "bg-[#0f1520]"  : "bg-[#1a2234]",
    content:     isDark ? "bg-[#121824]"  : "bg-[#eef2f7]",
    card:        isDark ? "bg-[#181f2e]"  : "bg-white",
    input:       isDark ? "bg-[#0d1421] border-white/[0.09] text-slate-200 placeholder-slate-600 focus:border-cyan-600/60 focus:ring-1 focus:ring-cyan-600/20"
                        : "bg-slate-50 border-slate-300 text-slate-900 placeholder-slate-400 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/20",
    border:      isDark ? "border-white/[0.07]" : "border-slate-200",
    borderSub:   isDark ? "border-white/[0.04]" : "border-slate-100",
    textPrimary: isDark ? "text-slate-100" : "text-slate-800",
    textSub:     isDark ? "text-slate-400" : "text-slate-500",
    textMuted:   isDark ? "text-slate-600" : "text-slate-400",
    label:       isDark ? "text-slate-400" : "text-slate-600",
    scrollbar:   isDark ? "scrollbar-dark" : "scrollbar-light",
  } as const;

  
    const PageDashboard = (
    <div className="space-y-5">
            {scanError && (
        <div className={`flex items-center gap-2.5 px-4 py-2.5 rounded-[6px] border text-xs font-mono ${
          isDark ? "bg-rose-950/30 border-rose-900 text-rose-300" : "bg-rose-50 border-rose-200 text-rose-700"
        }`}>
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {scanError}
          <button type="button" onClick={() => setScanError("")} className="ml-auto opacity-50 hover:opacity-100">✕</button>
        </div>
      )}

            {loading && (
        <div className={`px-4 py-3 rounded-[6px] border ${D.card} ${D.border}`}>
          <div className="flex items-center justify-between text-xs font-mono mb-2">
            <span className={`flex items-center gap-2 ${isDark ? "text-cyan-400" : "text-cyan-700"}`}>
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              Assessment running — {targetUrl}
            </span>
            <span className={D.textMuted}>ACTIVE</span>
          </div>
          <div className={`text-xs font-mono px-3 py-2 rounded-[4px] ${
            isDark ? "bg-[#0d1421] text-slate-400" : "bg-slate-50 text-slate-600"
          }`}>
            <span className="text-cyan-500 mr-2">&gt;</span>
            {SCAN_STEPS[loadingStep]}
            <span className={`ml-1 inline-block w-1.5 h-3 align-middle animate-pulse ${isDark ? "bg-cyan-500" : "bg-cyan-600"}`} />
          </div>
        </div>
      )}

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          {
            label: "Total Scans", value: totalScans, sub: "all-time",
            icon: Activity, accent: D.textPrimary,
          },
          {
            label: "Critical Threats", value: totalCrit, sub: "across all scans",
            icon: AlertOctagon, accent: totalCrit > 0 ? "text-rose-500" : D.textPrimary,
          },
          {
            label: "Avg Score", value: totalScans > 0 ? avgScore : "–", sub: totalScans > 0 ? "out of 100" : "no data",
            icon: TrendingUp, accent: totalScans > 0 ? gradeColor(avgScore) : D.textMuted,
          },
          {
            label: "Latest Score",
            value: displayResult ? displayResult.score : (history[0]?.score ?? "–"),
            sub: displayResult ? `Grade ${displayResult.grade}` : history[0] ? `Grade ${history[0].grade}` : "no data",
            icon: ShieldCheck,
            accent: displayResult ? gradeColor(displayResult.score) : history[0] ? gradeColor(history[0].score) : D.textMuted,
          },
        ].map(({ label, value, sub, icon: Icon, accent }) => (
          <div key={label} className={`${D.card} border ${D.border} rounded-[8px] p-4`}>
            <div className={`text-[10px] font-mono uppercase tracking-wider ${D.textMuted} mb-2`}>{label}</div>
            <div className={`text-3xl font-bold font-mono ${accent}`}>{value}</div>
            <div className={`text-[10px] font-mono mt-1 ${D.textMuted} flex items-center gap-1`}>
              <Icon className="w-3 h-3" />{sub}
            </div>
          </div>
        ))}
      </div>

            <div className={`${D.card} border ${D.border} rounded-[8px] overflow-hidden`}>
        <div className={`px-4 py-3 border-b ${D.border} flex items-center justify-between`}>
          <span className={`flex items-center gap-2 text-xs font-mono font-semibold ${D.textPrimary}`}>
            <ScanLine className={`w-3.5 h-3.5 ${D.textMuted}`} />
            Recent Vulnerability Logs
          </span>
          <span className={`text-[10px] font-mono ${D.textMuted}`}>{history.length} entries</span>
        </div>

        {history.length === 0 ? (
          <div className={`py-12 text-center ${D.textMuted}`}>
            <ScanLine className="w-6 h-6 mx-auto mb-2 opacity-30" />
            <p className="text-xs font-mono">No scans yet. Run your first scan using the bar above.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-xs font-mono">
              <thead>
                <tr className={`border-b ${D.borderSub} ${isDark ? "bg-[#0f1520]" : "bg-slate-50"}`}>
                  {["Target URL", "Date", "Score", "Risk Level", "Vulnerabilities", ""].map(h => (
                    <th key={h} className={`text-left px-4 py-2.5 text-[10px] uppercase tracking-wider font-semibold ${D.textMuted}`}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {history.map(item => {
                  const critN = getCritCount(item);
                  const isActive = selectedScan?.id === item.id;
                  return (
                    <tr
                      key={item.id}
                      onClick={() => { setSelectedScan(item); setScanResult(null); }}
                      className={`border-b ${D.borderSub} cursor-pointer transition-colors ${
                        isActive
                          ? isDark ? "bg-cyan-900/10" : "bg-cyan-50"
                          : isDark ? "hover:bg-white/[0.02]" : "hover:bg-slate-50"
                      }`}
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <Globe className={`w-3 h-3 shrink-0 ${D.textMuted}`} />
                          <span className={`truncate max-w-[180px] ${D.textPrimary}`}>
                            {item.targetUrl.replace(/^https?:\/\//, "")}
                          </span>
                        </div>
                      </td>
                      <td className={`px-4 py-3 ${D.textMuted} whitespace-nowrap`}>{fmtDate(item.createdAt)}</td>
                      <td className="px-4 py-3">
                        <span className={`font-bold ${gradeColor(item.score)}`}>
                          {item.score}<span className={`font-normal text-[10px] ${D.textMuted}`}>/100</span>
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded-[4px] border text-[10px] font-semibold ${riskBadge(item.score, isDark)}`}>
                          {riskLabel(item.score)}
                        </span>
                      </td>
                      <td className={`px-4 py-3 ${D.textSub}`}>
                        {item.results?.vulnerabilities?.length ?? 0} found
                        {critN > 0 && <span className="ml-2 text-rose-500 font-semibold">{critN} critical</span>}
                      </td>
                      <td className="px-4 py-3">
                        <ChevronRight className={`w-3.5 h-3.5 ${D.textMuted}`} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

            {displayResult && !loading && (
        <div className="space-y-4">
          {fatalCount > 0 && (
            <div className={`flex items-start gap-3 px-4 py-3.5 rounded-[6px] border ${
              isDark ? "bg-rose-950/20 border-rose-900 text-rose-300" : "bg-rose-50 border-rose-200 text-rose-700"
            }`}>
              <AlertOctagon className="w-4 h-4 shrink-0 mt-0.5 text-rose-500" />
              <div>
                <div className={`text-xs font-mono font-semibold mb-0.5 ${isDark ? "text-rose-200" : "text-rose-800"}`}>
                  {fatalCount} Critical {fatalCount === 1 ? "Vulnerability" : "Vulnerabilities"} Detected
                </div>
                <p className="text-xs leading-relaxed">
                  Critical-severity issues found that may allow server takeover (RCE),
                  database exfiltration (SQLi), or privilege escalation.
                </p>
              </div>
            </div>
          )}

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: "Security Score", value: `${displayResult.score}/100`, accent: isDark ? "text-cyan-400" : "text-cyan-600", icon: ShieldCheck },
              { label: "Grade",          value: displayResult.grade, accent: gradeColor(displayResult.score), icon: ShieldCheck },
              { label: "Total Issues",   value: `${displayResult.vulnerabilities?.length ?? 0}`, accent: D.textPrimary, icon: ShieldAlert },
              { label: "Critical",       value: `${fatalCount}`, accent: fatalCount > 0 ? "text-rose-500" : D.textMuted, icon: Flame },
            ].map(({ label, value, accent, icon: Icon }) => (
              <div key={label} className={`${D.card} border ${D.border} rounded-[8px] p-4 flex items-center justify-between`}>
                <div>
                  <div className={`text-[10px] font-mono uppercase tracking-wider ${D.textMuted} mb-1`}>{label}</div>
                  <div className={`text-2xl font-bold font-mono ${accent}`}>{value}</div>
                </div>
                <Icon className={`w-5 h-5 ${isDark ? "text-slate-700" : "text-slate-300"}`} />
              </div>
            ))}
          </div>

                    <div className={`${D.card} border ${D.border} rounded-[8px] overflow-hidden`}>
            <div className={`px-4 py-3 border-b ${D.border} flex flex-wrap items-center justify-between gap-3`}>
              <div className="flex items-center gap-2">
                {(["analysis", "json"] as const).map(tab => (
                  <button
                    key={tab}
                    type="button"
                    onClick={() => setActiveTab(tab)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-[6px] text-xs font-mono border transition-colors ${
                      activeTab === tab
                        ? isDark ? "bg-cyan-600/15 text-cyan-400 border-cyan-700/40 font-semibold" : "bg-cyan-100 text-cyan-800 border-cyan-300 font-semibold"
                        : isDark ? "text-slate-500 border-white/[0.06] hover:text-slate-300" : "text-slate-500 border-slate-200 hover:text-slate-700"
                    }`}
                  >
                    {tab === "analysis" ? <><FileText className="w-3.5 h-3.5" />Vulnerability Report</> : <><Code className="w-3.5 h-3.5" />Raw JSON</>}
                  </button>
                ))}
              </div>
              <span className={`text-xs font-mono flex items-center gap-1.5 ${D.textMuted}`}>
                <ExternalLink className="w-3 h-3" />{displayUrl}
              </span>
            </div>

            <div className="p-5">
              {activeTab === "analysis" ? (
                <div className="space-y-5">
                                    <div>
                    <div className={`text-[10px] font-mono uppercase tracking-wider mb-2 flex items-center gap-1.5 ${isDark ? "text-cyan-500" : "text-cyan-700"}`}>
                      <FileText className="w-3 h-3" /> Executive Summary
                    </div>
                    <p className={`text-xs leading-relaxed p-3 rounded-[6px] border ${
                      isDark ? "bg-[#0d1421] border-white/[0.07] text-slate-300" : "bg-slate-50 border-slate-200 text-slate-700"
                    }`}>
                      {displayResult.summary}
                    </p>
                  </div>

                                    <div>
                    <div className={`text-[10px] font-mono uppercase tracking-wider mb-3 flex items-center justify-between ${D.textSub}`}>
                      <span className="flex items-center gap-1.5">
                        <AlertTriangle className="w-3 h-3 text-rose-500" />
                        Findings ({displayResult.vulnerabilities?.length ?? 0})
                      </span>
                      <span className={D.textMuted}>CVSS 3.1 · OWASP</span>
                    </div>
                    <div className="space-y-2.5">
                      {displayResult.vulnerabilities?.map((vuln, idx) => {
                        const b = severityBadge(vuln.severity, isDark);
                        return (
                          <div key={idx} className={`rounded-[6px] border-l-2 ${
                            b.fatal
                              ? isDark ? "border-l-rose-600" : "border-l-rose-500"
                              : isDark ? "border-l-slate-700" : "border-l-slate-300"
                          } border ${D.border} overflow-hidden`}>
                            <div className={`px-4 py-3 ${isDark ? "bg-[#0f1520]" : "bg-slate-50"}`}>
                              <div className="flex flex-wrap items-start justify-between gap-2">
                                <div className="flex items-center gap-2 flex-wrap min-w-0">
                                  <span className={`text-[10px] font-mono ${D.textMuted} shrink-0`}>
                                    {String(idx + 1).padStart(2, "0")}
                                  </span>
                                  <h3 className={`text-xs font-semibold font-mono ${D.textPrimary}`}>{vuln.title}</h3>
                                  {vuln.category && (
                                    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded-[3px] border ${
                                      isDark ? "bg-[#111827] border-white/[0.07] text-slate-500" : "bg-slate-100 border-slate-300 text-slate-500"
                                    }`}>{vuln.category}</span>
                                  )}
                                </div>
                                <div className="flex items-center gap-1.5 shrink-0">
                                  {vuln.cvss && (
                                    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded-[3px] border font-semibold ${
                                      isDark ? "bg-red-950/40 border-red-900 text-red-400" : "bg-red-100 border-red-300 text-red-700"
                                    }`}>CVSS {vuln.cvss}</span>
                                  )}
                                  <span className={`text-[9px] font-mono px-2 py-0.5 rounded-[3px] border font-semibold ${b.badge}`}>{b.label}</span>
                                </div>
                              </div>
                            </div>
                            <div className={`px-4 py-3 border-t ${D.borderSub}`}>
                              <p className={`text-xs leading-relaxed ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                                {vuln.description}
                              </p>
                              {vuln.impact && (
                                <div className={`mt-2.5 flex items-start gap-2 p-2.5 rounded-[4px] border text-xs ${
                                  isDark ? "bg-red-950/20 border-red-900 text-red-300" : "bg-red-50 border-red-200 text-red-700"
                                }`}>
                                  <Flame className="w-3.5 h-3.5 shrink-0 mt-0.5 text-red-500" />
                                  <div>
                                    <span className={`font-mono text-[10px] font-semibold block mb-0.5 ${isDark ? "text-red-400" : "text-red-600"}`}>
                                      Potential Impact
                                    </span>
                                    {vuln.impact}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                                    {displayResult.recommendations && displayResult.recommendations.length > 0 && (
                    <div>
                      <div className={`text-[10px] font-mono uppercase tracking-wider mb-2.5 flex items-center gap-1.5 ${isDark ? "text-emerald-500" : "text-emerald-700"}`}>
                        <CheckCircle2 className="w-3 h-3" /> Remediation Steps
                      </div>
                      <div className={`rounded-[6px] border ${D.border} ${isDark ? "bg-[#0d1421]" : "bg-slate-50"} divide-y ${D.borderSub}`}>
                        {displayResult.recommendations.map((rec, i) => (
                          <div key={i} className="flex items-start gap-3 px-4 py-3">
                            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded-[3px] border shrink-0 mt-0.5 ${
                              isDark ? "text-cyan-500 bg-cyan-950/30 border-cyan-900" : "text-cyan-700 bg-cyan-50 border-cyan-200"
                            }`}>{i + 1}</span>
                            <span className={`text-xs leading-relaxed ${isDark ? "text-slate-300" : "text-slate-700"}`}>{rec}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div>
                  <div className={`flex items-center justify-between pb-2.5 mb-3 border-b ${D.border} text-[11px] font-mono ${D.textMuted}`}>
                    <span>200 OK · {JSON.stringify(displayResult).length} bytes</span>
                    <button type="button" onClick={handleCopyJson} className={`flex items-center gap-1.5 px-2.5 py-1 rounded-[4px] border transition-colors text-[10px] ${
                      isDark ? "bg-[#0d1421] border-white/[0.07] text-slate-400 hover:text-cyan-400 hover:border-cyan-800"
                             : "bg-white border-slate-300 text-slate-500 hover:text-cyan-700 hover:border-cyan-300"
                    }`}>
                      {copied ? <><Check className="w-3 h-3 text-emerald-500" />Copied</> : <><Copy className="w-3 h-3" />Copy JSON</>}
                    </button>
                  </div>
                  <div className={`rounded-[6px] border ${D.border} font-mono text-xs overflow-x-auto max-h-80 p-4 ${
                    isDark ? "bg-[#0b0f1a] text-cyan-300/90" : "bg-slate-900 text-cyan-300"
                  }`}>
                    <pre className="leading-relaxed">{JSON.stringify(displayResult, null, 2)}</pre>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

            {!displayResult && !loading && !scanError && (
        <div className={`${D.card} border ${D.border} rounded-[8px] py-14 text-center`}>
          <Shield className={`w-8 h-8 mx-auto mb-3 ${isDark ? "text-slate-700" : "text-slate-300"}`} />
          <p className={`text-sm font-mono font-semibold ${D.textPrimary} mb-1`}>No scan selected</p>
          <p className={`text-xs font-mono ${D.textMuted}`}>
            Enter a target URL in the bar above and click <strong className={D.textSub}>Run Scan</strong>,
            or pick a previous scan from the table.
          </p>
        </div>
      )}
    </div>
  );

    const PageScans = (
    <div className="space-y-5">
            <div>
        <h2 className={`text-sm font-bold font-mono ${D.textPrimary}`}>Vulnerability Scanner</h2>
        <p className={`text-xs font-mono mt-0.5 ${D.textMuted}`}>
          Configure and launch a deep vulnerability assessment against a target.
        </p>
      </div>

            <div className={`${D.card} border ${D.border} rounded-[8px] p-5`}>
        <div className={`text-[10px] font-mono uppercase tracking-wider mb-4 flex items-center gap-1.5 ${isDark ? "text-cyan-500" : "text-cyan-700"}`}>
          <ScanLine className="w-3 h-3" /> Scan Configuration
        </div>

        <form onSubmit={handleScanPageSubmit} className="space-y-4">
                    <div>
            <label className={`block text-[10px] font-mono uppercase tracking-wider mb-1.5 ${D.label}`}>
              Target URL or IP Address
            </label>
            <div className="flex gap-2">
                            <div className="relative">
                <select
                  value={scanProtocol}
                  onChange={e => setScanProtocol(e.target.value as "https" | "http")}
                  className={`h-full border rounded-[6px] pl-2.5 pr-6 py-2 text-xs font-mono outline-none transition-all appearance-none ${D.input}`}
                >
                  <option value="https">HTTPS</option>
                  <option value="http">HTTP</option>
                </select>
                <ChevronDown className={`absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none ${D.textMuted}`} />
              </div>
                            <div className="relative flex-1">
                <Globe className={`absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 pointer-events-none ${D.textMuted}`} />
                <input
                  type="text"
                  value={scansTarget}
                  onChange={e => setScansTarget(e.target.value)}
                  placeholder="example.com or 192.168.1.1"
                  className={`w-full border rounded-[6px] pl-8 pr-3 py-2 text-xs font-mono outline-none transition-all ${D.input}`}
                  required
                />
              </div>
            </div>
          </div>

                    <div>
            <label className={`block text-[10px] font-mono uppercase tracking-wider mb-1.5 ${D.label}`}>
              Demo Targets
            </label>
            <div className="flex flex-wrap gap-1.5">
              {PRESET_TARGETS.map(p => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setScansTarget(p.replace(/^https?:\/\//, ""))}
                  className={`text-[11px] font-mono px-2.5 py-1 rounded-[4px] border transition-colors ${
                    isDark ? "bg-[#0d1421] border-white/[0.07] text-slate-400 hover:text-cyan-400 hover:border-cyan-800"
                           : "bg-slate-50 border-slate-200 text-slate-500 hover:text-cyan-700 hover:border-cyan-300"
                  }`}
                >
                  {p.replace(/^https?:\/\//, "")}
                </button>
              ))}
            </div>
          </div>

                    <div className={`p-3.5 rounded-[6px] border ${D.border} ${isDark ? "bg-[#0d1421]" : "bg-slate-50"} space-y-3`}>
            <div className={`text-[10px] font-mono uppercase tracking-wider ${D.textMuted}`}>Scan Options</div>
            {[
              { label: "OWASP Top 10",          sub: "SQL Injection, XSS, SSRF, RCE…", on: true  },
              { label: "Header & TLS Audit",    sub: "Security headers, HSTS, cipher suites", on: true  },
              { label: "Exposed Secrets Scan",  sub: "API keys, .env files, tokens", on: true  },
              { label: "Deep Crawl (slow)",     sub: "Full sitemap traversal", on: deepScan },
            ].map(opt => (
              <div key={opt.label} className="flex items-center justify-between">
                <div>
                  <div className={`text-xs font-mono ${D.textPrimary}`}>{opt.label}</div>
                  <div className={`text-[10px] ${D.textMuted}`}>{opt.sub}</div>
                </div>
                <Toggle checked={opt.on} onChange={() => {}} isDark={isDark} />
              </div>
            ))}
          </div>

          <button
            type="submit"
            disabled={loading}
            className="bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 disabled:opacity-40 disabled:cursor-not-allowed text-white font-mono font-semibold px-5 py-2 rounded-[6px] text-xs flex items-center gap-2 transition-colors"
          >
            {loading
              ? <><RefreshCw className="w-3.5 h-3.5 animate-spin" />Scanning…</>
              : <><Search className="w-3.5 h-3.5" />Run Vulnerability Assessment</>
            }
          </button>
        </form>
      </div>

            <div className={`${D.card} border ${D.border} rounded-[8px] overflow-hidden`}>
        <div className={`px-4 py-3 border-b ${D.border} flex items-center justify-between`}>
          <span className={`flex items-center gap-2 text-xs font-mono font-semibold ${D.textPrimary}`}>
            <Clock className={`w-3.5 h-3.5 ${D.textMuted}`} />
            Scan History
          </span>
          <span className={`text-[10px] font-mono ${D.textMuted}`}>{history.length} total</span>
        </div>

        {history.length === 0 ? (
          <div className={`py-12 text-center ${D.textMuted}`}>
            <ScanLine className="w-6 h-6 mx-auto mb-2 opacity-30" />
            <p className="text-xs font-mono">No scans found. Run your first assessment above.</p>
          </div>
        ) : (
          <div className="divide-y divide-white/[0.04]">
            {history.map(item => {
              const critN = getCritCount(item);
              return (
                <div
                  key={item.id}
                  onClick={() => { setSelectedScan(item); setScanResult(null); setActiveNav("dashboard"); }}
                  className={`flex items-center justify-between px-4 py-3 cursor-pointer transition-colors ${
                    isDark ? "hover:bg-white/[0.02]" : "hover:bg-slate-50"
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                    <div className="min-w-0">
                      <div className={`text-xs font-mono truncate ${D.textPrimary}`}>
                        {item.targetUrl.replace(/^https?:\/\//, "")}
                      </div>
                      <div className={`text-[10px] font-mono ${D.textMuted}`}>
                        {fmtDate(item.createdAt)}
                        {critN > 0 && <span className="ml-2 text-rose-500">{critN} critical</span>}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded-[4px] border font-semibold ${riskBadge(item.score, isDark)}`}>
                      {riskLabel(item.score)}
                    </span>
                    <span className={`text-[10px] font-mono font-bold ${gradeColor(item.score)}`}>
                      {item.score}/100
                    </span>
                    <ChevronRight className={`w-3 h-3 ${D.textMuted}`} />
                  </div>
                </div>
              );
            })}

            {loading && (
              <div className={`flex items-center gap-3 px-4 py-3 ${isDark ? "bg-cyan-900/10" : "bg-cyan-50"}`}>
                <RefreshCw className="w-3.5 h-3.5 text-cyan-500 animate-spin shrink-0" />
                <div>
                  <div className={`text-xs font-mono ${isDark ? "text-cyan-400" : "text-cyan-700"}`}>
                    {targetUrl.replace(/^https?:\/\//, "")}
                  </div>
                  <div className={`text-[10px] font-mono ${D.textMuted}`}>Scanning in progress…</div>
                </div>
                <span className={`ml-auto text-[10px] font-mono px-2 py-0.5 rounded-[4px] border ${
                  isDark ? "text-amber-400 border-amber-800 bg-amber-950/40" : "text-amber-700 border-amber-200 bg-amber-50"
                }`}>
                  Running
                </span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );

    const PageReports = (
    <div className="space-y-5">
      <div>
        <h2 className={`text-sm font-bold font-mono ${D.textPrimary}`}>Reports</h2>
        <p className={`text-xs font-mono mt-0.5 ${D.textMuted}`}>
          Download vulnerability assessment reports for your scanned targets.
        </p>
      </div>

            <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Total Reports", value: history.length, icon: FileText },
          { label: "Critical Findings", value: totalCrit, icon: AlertOctagon },
          { label: "Avg Risk Score", value: totalScans > 0 ? avgScore : "–", icon: BarChart2 },
        ].map(({ label, value, icon: Icon }) => (
          <div key={label} className={`${D.card} border ${D.border} rounded-[8px] p-4 flex items-center gap-3`}>
            <Icon className={`w-4 h-4 shrink-0 ${D.textMuted}`} />
            <div>
              <div className={`text-[10px] font-mono ${D.textMuted}`}>{label}</div>
              <div className={`text-xl font-bold font-mono ${D.textPrimary}`}>{value}</div>
            </div>
          </div>
        ))}
      </div>

            <div className={`${D.card} border ${D.border} rounded-[8px] overflow-hidden`}>
        <div className={`px-4 py-3 border-b ${D.border} flex items-center justify-between`}>
          <span className={`flex items-center gap-2 text-xs font-mono font-semibold ${D.textPrimary}`}>
            <FileText className={`w-3.5 h-3.5 ${D.textMuted}`} />
            Available Reports
          </span>
        </div>

        {history.length === 0 ? (
          <div className={`py-12 text-center ${D.textMuted}`}>
            <FileText className="w-6 h-6 mx-auto mb-2 opacity-30" />
            <p className="text-xs font-mono">No reports available. Complete a scan first.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-xs font-mono">
              <thead>
                <tr className={`border-b ${D.borderSub} ${isDark ? "bg-[#0f1520]" : "bg-slate-50"}`}>
                  {["Report Name", "Date", "Target", "Score", "Risk", "Actions"].map(h => (
                    <th key={h} className={`text-left px-4 py-2.5 text-[10px] uppercase tracking-wider font-semibold ${D.textMuted}`}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {history.map((item, idx) => (
                  <tr key={item.id} className={`border-b ${D.borderSub} transition-colors ${isDark ? "hover:bg-white/[0.02]" : "hover:bg-slate-50"}`}>
                    <td className="px-4 py-3">
                      <div className={`font-semibold ${D.textPrimary}`}>
                        Scan Report #{String(idx + 1).padStart(3, "0")}
                      </div>
                      <div className={`text-[10px] ${D.textMuted}`}>
                        {item.results?.vulnerabilities?.length ?? 0} vulnerabilities found
                      </div>
                    </td>
                    <td className={`px-4 py-3 ${D.textMuted} whitespace-nowrap`}>{fmtDate(item.createdAt)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <Globe className={`w-3 h-3 ${D.textMuted}`} />
                        <span className={`truncate max-w-[160px] ${D.textSub}`}>
                          {item.targetUrl.replace(/^https?:\/\//, "")}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`font-bold ${gradeColor(item.score)}`}>
                        {item.score}<span className={`font-normal ${D.textMuted}`}>/100</span>
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded-[4px] border text-[10px] font-semibold ${riskBadge(item.score, isDark)}`}>
                        {riskLabel(item.score)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          title="Download PDF"
                          onClick={() => {
                            setSelectedScan(item);
                            setScanResult(null);
                            setActiveNav("dashboard");
                          }}
                          className={`flex items-center gap-1 px-2.5 py-1 rounded-[4px] border text-[10px] transition-colors ${
                            isDark ? "border-white/[0.07] text-slate-400 hover:text-cyan-400 hover:border-cyan-800"
                                   : "border-slate-200 text-slate-500 hover:text-cyan-700 hover:border-cyan-300"
                          }`}
                        >
                          <Eye className="w-3 h-3" />
                          View
                        </button>
                        <button
                          type="button"
                          title="Download CSV"
                          onClick={() => handleDownloadCSV(item)}
                          className={`flex items-center gap-1 px-2.5 py-1 rounded-[4px] border text-[10px] transition-colors ${
                            isDark ? "border-white/[0.07] text-slate-400 hover:text-emerald-400 hover:border-emerald-800"
                                   : "border-slate-200 text-slate-500 hover:text-emerald-700 hover:border-emerald-300"
                          }`}
                        >
                          <Download className="w-3 h-3" />
                          CSV
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

            <div className={`flex items-start gap-2.5 px-4 py-3 rounded-[6px] border text-xs ${
        isDark ? "bg-[#0d1421] border-white/[0.07] text-slate-500" : "bg-slate-50 border-slate-200 text-slate-400"
      }`}>
        <CircleDot className="w-3.5 h-3.5 shrink-0 mt-0.5" />
        PDF export requires a browser print dialog. Click <strong className={D.textSub}>View</strong> to open
        the full report, then use your browser&apos;s print function (Ctrl+P) and select &quot;Save as PDF&quot;.
      </div>
    </div>
  );

    const PageSettings = (
    <div className="space-y-5 max-w-2xl">
      <div>
        <h2 className={`text-sm font-bold font-mono ${D.textPrimary}`}>Settings</h2>
        <p className={`text-xs font-mono mt-0.5 ${D.textMuted}`}>
          Manage your account, API credentials, and scan preferences.
        </p>
      </div>

            {settingsSaved && (
        <div className={`flex items-center gap-2 px-4 py-2.5 rounded-[6px] border text-xs font-mono ${
          isDark ? "bg-emerald-950/30 border-emerald-900 text-emerald-400" : "bg-emerald-50 border-emerald-200 text-emerald-700"
        }`}>
          <CheckCircle className="w-4 h-4" />
          Settings saved successfully.
        </div>
      )}

            <div className={`${D.card} border ${D.border} rounded-[8px] p-5 space-y-4`}>
        <div className={`text-[10px] font-mono uppercase tracking-wider ${D.textMuted} flex items-center gap-1.5`}>
          <UserCircle className="w-3 h-3" /> Account Information
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className={`block text-[10px] font-mono uppercase tracking-wider mb-1.5 ${D.label}`}>
              Display Name
            </label>
            <input
              type="text"
              value={settingsName}
              onChange={e => setSettingsName(e.target.value)}
              placeholder="Your name"
              className={`w-full border rounded-[6px] px-3 py-2 text-xs font-mono outline-none transition-all ${D.input}`}
            />
          </div>
          <div>
            <label className={`block text-[10px] font-mono uppercase tracking-wider mb-1.5 ${D.label}`}>
              Email Address
            </label>
            <div className="relative">
              <Mail className={`absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none ${D.textMuted}`} />
              <input
                type="email"
                value={settingsEmail}
                onChange={e => setSettingsEmail(e.target.value)}
                placeholder="you@example.com"
                className={`w-full border rounded-[6px] pl-7 pr-3 py-2 text-xs font-mono outline-none transition-all ${D.input}`}
              />
            </div>
          </div>
        </div>
      </div>

            <div className={`${D.card} border ${D.border} rounded-[8px] p-5 space-y-4`}>
        <div className={`text-[10px] font-mono uppercase tracking-wider ${D.textMuted} flex items-center justify-between`}>
          <div className="flex items-center gap-1.5">
            <Key className="w-3.5 h-3.5 text-cyan-400" />
            <span className="font-bold text-slate-200">GEMINI API KEY</span>
          </div>
          <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/50 text-cyan-300 font-medium">
            AI Remediation Engine
          </span>
        </div>

        <div>
          <label className={`block text-[10px] font-mono uppercase tracking-wider mb-1.5 ${D.label}`}>
            GEMINI API KEY
          </label>
          <div className="relative">
            <input
              type={showApiKey ? "text" : "password"}
              value={apiKey}
              onChange={e => handleApiKeyChange(e.target.value)}
              placeholder="AIzaSyB3X..."
              className={`w-full border rounded-[6px] px-3 pr-9 py-2.5 text-xs font-mono outline-none transition-all ${D.input}`}
              spellCheck={false}
              autoComplete="off"
            />
            <button
              type="button"
              onClick={() => setShowApiKey(v => !v)}
              className={`absolute right-2.5 top-1/2 -translate-y-1/2 ${D.textMuted} hover:${isDark ? "text-slate-300" : "text-slate-600"} transition-colors`}
              title={showApiKey ? "Hide Key" : "Show Key"}
            >
              {showApiKey ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            </button>
          </div>
          <p className={`text-[10px] font-mono mt-1.5 ${D.textMuted} leading-relaxed`}>
            Function: Connects the application to Google Gemini AI to power automated vulnerability analysis and smart remediation advice.
          </p>
        </div>
      </div>

            <div className={`${D.card} border ${D.border} rounded-[8px] p-5 space-y-0 divide-y ${D.borderSub}`}>
        <div className={`pb-3 text-[10px] font-mono uppercase tracking-wider ${D.textMuted} flex items-center gap-1.5`}>
          <Zap className="w-3 h-3" /> Scan Preferences
        </div>

        {[
          {
            icon: Bell,
            label: "Email Notifications",
            sub: "Receive an email alert when a critical vulnerability is found.",
            value: emailNotif,
            set: setEmailNotif,
          },
          {
            icon: Zap,
            label: "Deep Scan Mode",
            sub: "Enable full sitemap crawling and extended payload testing. Slower but more thorough.",
            value: deepScan,
            set: setDeepScan,
          },
        ].map(({ icon: Icon, label, sub, value, set }) => (
          <div key={label} className="flex items-start justify-between py-4 gap-4">
            <div className="flex items-start gap-3 min-w-0">
              <div className={`w-7 h-7 rounded-[6px] border flex items-center justify-center shrink-0 mt-0.5 ${
                isDark ? "bg-[#0d1421] border-white/[0.07]" : "bg-slate-50 border-slate-200"
              }`}>
                <Icon className={`w-3.5 h-3.5 ${D.textMuted}`} />
              </div>
              <div>
                <div className={`text-xs font-mono font-medium ${D.textPrimary}`}>{label}</div>
                <div className={`text-[10px] font-mono mt-0.5 leading-relaxed ${D.textMuted}`}>{sub}</div>
              </div>
            </div>
            <Toggle checked={value} onChange={set} isDark={isDark} />
          </div>
        ))}
      </div>

            <button
        type="button"
        onClick={handleSaveSettings}
        className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 text-white font-mono font-semibold px-5 py-2 rounded-[6px] text-xs transition-colors"
      >
        <Save className="w-3.5 h-3.5" />
        Save Changes
      </button>
    </div>
  );

    const PAGE_MAP: Record<NavId, React.ReactNode> = {
    dashboard: PageDashboard,
    scans:     PageScans,
    reports:   PageReports,
    settings:  PageSettings,
  };

  return (
    <div className={`h-screen flex overflow-hidden font-sans ${D.content}`}>

            {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/80 backdrop-blur-sm lg:hidden transition-opacity"
          onClick={() => setSidebarOpen(false)}
        />
      )}

            <aside
        className={`fixed inset-y-0 left-0 z-50 lg:static shrink-0 flex flex-col bg-[#0B0F17] border-r border-white/[0.07] select-none transition-all duration-200 ${sidebarOpen ? "w-[280px]" : "hidden"}`}
      >
                <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <WebShieldLogo size={26} />
            <div>
              <div className="font-bold text-sm text-white font-mono tracking-wider leading-none flex items-center gap-1.5">
                WEBSHIELD <span className="text-[10px] text-cyan-400 bg-cyan-950/80 border border-cyan-800/60 px-1 py-0.2 rounded font-normal">AI</span>
              </div>
              <div className="text-[10px] text-slate-500 font-mono mt-1">Enterprise Cyber Defense</div>
            </div>
          </div>
                    <button
            type="button"
            onClick={() => setSidebarOpen(false)}
            className="text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-white/[0.06] transition-colors"
            aria-label="Close Sidebar"
            title="Tutup Sidebar"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

                <nav className="px-3.5 py-3 border-b border-white/[0.06] space-y-1.5">
          {NAV_ITEMS.map(({ icon: Icon, label, id }) => {
            const isActive = activeNav === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => {
                  setActiveNav(id);
                  if (typeof window !== "undefined" && window.innerWidth < 1024) {
                    setSidebarOpen(false);
                  }
                }}
                className={`w-full flex items-center gap-3 px-3.5 py-3 rounded-lg text-xs font-mono font-medium transition-all duration-150 border ${
                  isActive
                    ? "bg-cyan-500/15 text-cyan-300 border-cyan-500/30 shadow-[0_0_14px_rgba(6,182,212,0.15)]"
                    : "text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] border-transparent"
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 transition-colors ${isActive ? "text-cyan-400" : "text-slate-500"}`} />
                <span className="flex-1 text-left tracking-wide">{label}</span>
                {isActive && (
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-[0_0_8px_#22d3ee]" />
                )}
              </button>
            );
          })}
        </nav>

                <div className="px-4 py-2.5 border-b border-white/[0.06] flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>Recent Audits</span>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/[0.05] text-slate-300 border border-white/[0.08] font-semibold">
            {history.length}
          </span>
        </div>

                <div className="flex-1 overflow-y-auto px-3 py-2 space-y-1.5 scrollbar-dark">
          {history.length === 0 ? (
            <div className="text-center py-10 px-4">
              <Shield className="w-5 h-5 text-slate-700 mx-auto mb-2 opacity-60" />
              <p className="text-[11px] text-slate-500 font-mono">No scan telemetry recorded</p>
              <p className="text-[9.5px] text-slate-600 font-mono mt-0.5">Run a scan above to start</p>
            </div>
          ) : (
            history.map(item => {
              const isActive = selectedScan?.id === item.id;
              const cleanDomain = item.targetUrl.replace(/^https?:\/\//, "").replace(/\/$/, "");
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setSelectedScan(item);
                    setScanResult(null);
                    setActiveNav("dashboard");
                    if (typeof window !== "undefined" && window.innerWidth < 1024) {
                      setSidebarOpen(false);
                    }
                  }}
                  className={`w-full text-left px-3.5 py-2.5 rounded-lg transition-all border group ${
                    isActive
                      ? "bg-cyan-500/10 border-cyan-500/30 shadow-[0_0_12px_rgba(6,182,212,0.1)]"
                      : "border-transparent hover:bg-white/[0.04] hover:border-white/[0.06]"
                  }`}
                  title={cleanDomain}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className={`text-xs font-mono font-medium truncate flex-1 min-w-0 ${
                      isActive ? "text-cyan-300 font-semibold" : "text-slate-300 group-hover:text-white"
                    }`}>
                      {cleanDomain}
                    </span>
                    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded-[4px] border font-bold shrink-0 ${
                      item.score >= 80 ? "text-emerald-400 border-emerald-800/80 bg-emerald-950/60"
                      : item.score >= 50 ? "text-amber-400 border-amber-800/80 bg-amber-950/60"
                      : "text-rose-400 border-rose-800/80 bg-rose-950/60"
                    }`}>
                      {item.grade}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                    <span className="flex items-center gap-1.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${
                        item.score >= 80 ? "bg-emerald-500 shadow-[0_0_6px_#10b981]" : item.score >= 50 ? "bg-amber-500 shadow-[0_0_6px_#f59e0b]" : "bg-rose-500 shadow-[0_0_6px_#f43f5e]"
                      }`} />
                      Score: {item.score}/100
                    </span>
                    <span>{fmtDate(item.createdAt)}</span>
                  </div>
                </button>
              );
            })
          )}
        </div>

                <div className="p-3 border-t border-white/[0.06] bg-[#090e17]">
          <div className="flex items-center gap-2.5 mb-2.5">
            <div className="w-7 h-7 rounded-[5px] bg-cyan-600/20 border border-cyan-500/30 flex items-center justify-center font-mono text-xs font-bold text-cyan-400 shrink-0">
              {user?.name ? user.name[0].toUpperCase() : <User className="w-3.5 h-3.5" />}
            </div>
            <div className="truncate min-w-0 flex-1">
              <div className="text-xs font-medium text-slate-200 truncate font-mono">{user?.name || "Security Operator"}</div>
              <div className="text-[10px] text-slate-500 truncate font-mono">{user?.email || "operator@webshield.ai"}</div>
            </div>
          </div>
          <button
            type="button"
            onClick={handleLogout}
            className="w-full flex items-center justify-center gap-1.5 py-2 rounded-md text-[11px] font-mono font-medium text-slate-400 hover:text-rose-400 hover:bg-rose-950/20 border border-white/[0.06] hover:border-rose-900/50 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sign Out
          </button>
        </div>
      </aside>

            <div className="flex-1 flex flex-col min-w-0">

                <header className={`${D.topbar} border-b border-white/[0.07] px-4 lg:px-6 py-2.5 flex items-center gap-3 lg:gap-4 shrink-0`}>
                    <button
            type="button"
            onClick={() => setSidebarOpen(v => !v)}
            className="p-1.5 rounded-md border border-white/[0.1] text-slate-300 hover:text-white hover:border-cyan-500/50 hover:bg-white/[0.06] transition-colors shrink-0"
            aria-label="Toggle Navigation"
            title={sidebarOpen ? "Tutup Sidebar" : "Buka Sidebar"}
          >
            <Menu className="w-4 h-4 text-cyan-400" />
          </button>

                    <div className="flex items-center gap-2 shrink-0">
            {(() => {
              const nav = NAV_ITEMS.find(n => n.id === activeNav)!;
              return (
                <>
                  <nav.icon className="w-4 h-4 text-cyan-400" />
                  <span className="text-sm font-semibold text-slate-200 font-mono capitalize tracking-wide">{nav.label}</span>
                </>
              );
            })()}
          </div>

          <div className="hidden sm:block w-px h-4 bg-white/[0.08] shrink-0" />

                    <form onSubmit={handleHeaderScan} className="flex-1 flex items-center gap-2 max-w-xl">
            <div className="relative flex-1 min-w-0">
              <Globe className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-600 pointer-events-none" />
              <input
                type="url"
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                placeholder="https://target.example.com"
                className="w-full bg-[#0d1421] border border-white/[0.09] rounded-[6px] pl-8 pr-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-600 outline-none focus:border-cyan-600/60 focus:ring-1 focus:ring-cyan-600/20 transition-all truncate"
                required
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 disabled:opacity-40 disabled:cursor-not-allowed text-white font-mono font-semibold px-3 sm:px-4 py-1.5 rounded-[6px] text-xs flex items-center gap-1.5 transition-colors shrink-0"
            >
              {loading
                ? <><RefreshCw className="w-3.5 h-3.5 animate-spin" /><span className="hidden sm:inline">Scanning…</span></>
                : <><Search className="w-3.5 h-3.5" /><span className="hidden sm:inline">Run Scan</span></>
              }
            </button>
          </form>

                    <div className="ml-auto flex items-center gap-2 sm:gap-2.5 shrink-0">
                        <button
              type="button"
              onClick={handleInstallClick}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-white/[0.05] hover:bg-white/[0.08] border border-white/[0.08] text-slate-300 transition-colors"
              title={isAppInstalled ? "Aplikasi Sudah Diinstal" : "Install WebShield AI (PWA)"}
            >
              {isAppInstalled ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              ) : (
                <Download className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              )}
              <span className="text-[11px] font-mono font-semibold tracking-wide hidden sm:inline">
                {isAppInstalled ? "Aplikasi Sudah Diinstal" : "Install App"}
              </span>
              <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-white/[0.06] text-slate-400 border border-white/[0.08] font-medium">PWA</span>
            </button>

                        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-white/[0.05] border border-white/[0.08] text-slate-300 text-xs font-mono">
              <Lock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <span className="font-medium text-slate-300">TLS 1.3</span>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500/70" />
            </div>

                        <button
              type="button"
              onClick={toggleTheme}
              className="p-1.5 rounded-[6px] border border-white/[0.09] text-slate-400 hover:text-slate-200 hover:border-white/[0.2] transition-colors"
              title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
            >
              {isDark ? <Sun className="w-3.5 h-3.5 text-amber-400" /> : <Moon className="w-3.5 h-3.5 text-slate-300" />}
            </button>
          </div>
        </header>

                <main
          key={activeNav}
          className={`flex-1 overflow-y-auto ${D.scrollbar} px-4 sm:px-6 lg:px-8 py-6`}
          style={{ animation: "fadeIn 150ms ease-out" }}
        >
          <style>{`@keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }`}</style>
          <div className="w-full max-w-6xl mx-auto space-y-6">
            {PAGE_MAP[activeNav]}
          </div>
        </main>

                <footer className={`${D.topbar} border-t border-white/[0.07] px-4 sm:px-5 py-2 flex items-center justify-between shrink-0`}>
          <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400">
            <WebShieldLogo size={14} />
            <span>WebShield AI · Vulnerability Assessment</span>
          </div>
          <div className="hidden sm:flex items-center gap-3 text-[10px] font-mono text-slate-400">
            <span className="flex items-center gap-1"><Lock className="w-2.5 h-2.5 text-emerald-400" />OWASP Top 10</span>
            <span>·</span>
            <span>CVSS 3.1</span>
            <span>·</span>
            <span className="text-cyan-400">Gemini Flash Engine</span>
          </div>
        </footer>
      </div>

            {installModalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/80 backdrop-blur-md animate-in fade-in duration-200"
          onClick={() => setInstallModalOpen(false)}
        >
          <div
            className={`relative w-full max-w-lg ${isDark ? "bg-[#0c121d] border-cyan-900/50" : "bg-white border-slate-300"} border rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]`}
            onClick={e => e.stopPropagation()}
          >
                        <div className={`px-5 py-4 border-b ${isDark ? "border-white/[0.08] bg-[#080d15]" : "border-slate-200 bg-slate-50"} flex items-center justify-between shrink-0`}>
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
                  {isAppInstalled ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Download className="w-4 h-4" />}
                </div>
                <div>
                  <h3 className={`text-sm font-mono font-bold ${isDark ? "text-white" : "text-slate-900"} flex items-center gap-2`}>
                    {isAppInstalled ? "Aplikasi Sudah Diinstal" : "Install WebShield AI"}
                    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${isAppInstalled ? "bg-emerald-950 text-emerald-400 border border-emerald-800" : "bg-cyan-950 text-cyan-400 border border-cyan-800"}`}>
                      PWA
                    </span>
                  </h3>
                  <p className="text-[11px] font-mono text-slate-400">
                    {isAppInstalled ? "WebShield AI sudah terpasang dan dapat dibuka langsung dari perangkat Anda." : "Standalone desktop & mobile app experience"}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setInstallModalOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.08] transition-colors"
                aria-label="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

                        {deferredPrompt && (
              <div className="px-5 py-3 bg-gradient-to-r from-cyan-950/70 to-blue-950/50 border-b border-cyan-800/40 flex items-center justify-between gap-3 shrink-0">
                <div className="flex items-center gap-2 text-xs font-mono text-cyan-300">
                  <Sparkles className="w-4 h-4 text-cyan-400 shrink-0 animate-pulse" />
                  <span>Direct browser installation ready!</span>
                </div>
                <button
                  type="button"
                  onClick={handleNativeInstall}
                  className="px-3.5 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 active:bg-cyan-600 text-slate-950 font-mono text-xs font-bold transition-all shadow-[0_0_12px_rgba(6,182,212,0.4)] shrink-0"
                >
                  Install Now
                </button>
              </div>
            )}

                        <div className={`px-4 pt-3 pb-2 border-b ${isDark ? "border-white/[0.06] bg-[#0a0f19]" : "border-slate-200 bg-slate-100"} flex gap-1.5 shrink-0`}>
              {[
                { id: "desktop", label: "Windows / Mac", icon: Laptop },
                { id: "ios",     label: "iOS (Safari)", icon: Smartphone },
                { id: "android", label: "Android", icon: Monitor },
              ].map(tab => {
                const isSelected = activePlatformTab === tab.id;
                const TabIcon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setActivePlatformTab(tab.id as any)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all border ${
                      isSelected
                        ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40 font-semibold"
                        : "text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] border-transparent"
                    }`}
                  >
                    <TabIcon className="w-3.5 h-3.5" />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>

                        <div className="p-5 overflow-y-auto space-y-3.5">
              {activePlatformTab === "desktop" && (
                <div className="space-y-3 font-mono">
                  <div className="flex items-center gap-2 text-xs text-slate-300 font-semibold mb-2">
                    <Laptop className="w-4 h-4 text-cyan-400" />
                    <span>Installing on Windows or macOS via Chrome / Edge</span>
                  </div>

                  <div className={`p-3.5 rounded-lg border ${isDark ? "bg-[#080d16] border-white/[0.06]" : "bg-slate-50 border-slate-200"} flex items-start gap-3`}>
                    <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      1
                    </div>
                    <div className="text-xs leading-relaxed text-slate-300">
                      <span className="font-semibold text-white">Address Bar:</span> Look at the right edge of your browser URL bar for the <span className="text-cyan-400 font-semibold">Install Icon (💻 or ⤓)</span>. Click it.
                    </div>
                  </div>

                  <div className={`p-3.5 rounded-lg border ${isDark ? "bg-[#080d16] border-white/[0.06]" : "bg-slate-50 border-slate-200"} flex items-start gap-3`}>
                    <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      2
                    </div>
                    <div className="text-xs leading-relaxed text-slate-300">
                      <span className="font-semibold text-white">Browser Menu:</span> Click the <span className="text-slate-200 font-semibold">three dots (⋮)</span> in Chrome or Edge → Select <span className="text-cyan-400 font-semibold">&ldquo;Save and share&rdquo;</span> or <span className="text-cyan-400 font-semibold">&ldquo;Apps&rdquo;</span> → Click <span className="text-cyan-400 font-semibold">&ldquo;Install WebShield AI&rdquo;</span>.
                    </div>
                  </div>

                  <div className={`p-3.5 rounded-lg border ${isDark ? "bg-[#080d16] border-white/[0.06]" : "bg-slate-50 border-slate-200"} flex items-start gap-3`}>
                    <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      3
                    </div>
                    <div className="text-xs leading-relaxed text-slate-300">
                      Click <span className="text-emerald-400 font-bold">&ldquo;Install&rdquo;</span> on the popup. WebShield AI will now run in its own standalone window with a desktop & taskbar shortcut.
                    </div>
                  </div>
                </div>
              )}

              {activePlatformTab === "ios" && (
                <div className="space-y-3 font-mono">
                  <div className="flex items-center gap-2 text-xs text-slate-300 font-semibold mb-2">
                    <Smartphone className="w-4 h-4 text-cyan-400" />
                    <span>Installing on iPhone or iPad via Apple Safari</span>
                  </div>

                  <div className={`p-3.5 rounded-lg border ${isDark ? "bg-[#080d16] border-white/[0.06]" : "bg-slate-50 border-slate-200"} flex items-start gap-3`}>
                    <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      1
                    </div>
                    <div className="text-xs leading-relaxed text-slate-300">
                      Open this WebShield application inside <span className="font-bold text-white">Apple Safari</span>.
                    </div>
                  </div>

                  <div className={`p-3.5 rounded-lg border ${isDark ? "bg-[#080d16] border-white/[0.06]" : "bg-slate-50 border-slate-200"} flex items-start gap-3`}>
                    <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      2
                    </div>
                    <div className="text-xs leading-relaxed text-slate-300">
                      Tap the <span className="text-cyan-400 font-semibold">Share button</span> (the square icon with an upward arrow) on Safari toolbar.
                    </div>
                  </div>

                  <div className={`p-3.5 rounded-lg border ${isDark ? "bg-[#080d16] border-white/[0.06]" : "bg-slate-50 border-slate-200"} flex items-start gap-3`}>
                    <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      3
                    </div>
                    <div className="text-xs leading-relaxed text-slate-300">
                      Scroll down the options sheet and tap <span className="text-cyan-400 font-bold">&ldquo;Add to Home Screen&rdquo; (➕)</span>.
                    </div>
                  </div>

                  <div className={`p-3.5 rounded-lg border ${isDark ? "bg-[#080d16] border-white/[0.06]" : "bg-slate-50 border-slate-200"} flex items-start gap-3`}>
                    <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      4
                    </div>
                    <div className="text-xs leading-relaxed text-slate-300">
                      Tap <span className="text-emerald-400 font-bold">&ldquo;Add&rdquo;</span> at the top-right. WebShield will be placed on your Home Screen and run full-screen without address bars.
                    </div>
                  </div>
                </div>
              )}

              {activePlatformTab === "android" && (
                <div className="space-y-3 font-mono">
                  <div className="flex items-center gap-2 text-xs text-slate-300 font-semibold mb-2">
                    <Monitor className="w-4 h-4 text-cyan-400" />
                    <span>Installing on Android via Google Chrome</span>
                  </div>

                  <div className={`p-3.5 rounded-lg border ${isDark ? "bg-[#080d16] border-white/[0.06]" : "bg-slate-50 border-slate-200"} flex items-start gap-3`}>
                    <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      1
                    </div>
                    <div className="text-xs leading-relaxed text-slate-300">
                      Open WebShield in <span className="font-bold text-white">Google Chrome</span> on your Android phone or tablet.
                    </div>
                  </div>

                  <div className={`p-3.5 rounded-lg border ${isDark ? "bg-[#080d16] border-white/[0.06]" : "bg-slate-50 border-slate-200"} flex items-start gap-3`}>
                    <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      2
                    </div>
                    <div className="text-xs leading-relaxed text-slate-300">
                      Tap the <span className="text-cyan-400 font-semibold">three dots menu (⋮)</span> in the top-right corner.
                    </div>
                  </div>

                  <div className={`p-3.5 rounded-lg border ${isDark ? "bg-[#080d16] border-white/[0.06]" : "bg-slate-50 border-slate-200"} flex items-start gap-3`}>
                    <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      3
                    </div>
                    <div className="text-xs leading-relaxed text-slate-300">
                      Tap <span className="text-cyan-400 font-bold">&ldquo;Install app&rdquo;</span> or <span className="text-cyan-400 font-bold">&ldquo;Add to Home screen&rdquo;</span>.
                    </div>
                  </div>

                  <div className={`p-3.5 rounded-lg border ${isDark ? "bg-[#080d16] border-white/[0.06]" : "bg-slate-50 border-slate-200"} flex items-start gap-3`}>
                    <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-800 text-cyan-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">
                      4
                    </div>
                    <div className="text-xs leading-relaxed text-slate-300">
                      Tap <span className="text-emerald-400 font-bold">&ldquo;Install&rdquo;</span>. The WebShield icon will be added to your home screen and app launcher.
                    </div>
                  </div>
                </div>
              )}
            </div>

                        <div className={`px-5 py-3 border-t ${isDark ? "border-white/[0.08] bg-[#080d15]" : "border-slate-200 bg-slate-50"} flex items-center justify-between shrink-0`}>
              <div className="text-[10px] font-mono text-slate-500">
                PWA Certified · Standalone Mode
              </div>
              <button
                type="button"
                onClick={() => setInstallModalOpen(false)}
                className="px-4 py-1.5 rounded-md bg-white/[0.08] hover:bg-white/[0.12] text-slate-200 text-xs font-mono font-medium transition-colors"
              >
                Close Guide
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

"use client";

import { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { signIn, useSession } from "next-auth/react";
import WebShieldLogo from "@/components/WebShieldLogo";
import { useTheme } from "@/components/ThemeProvider";
import { Terminal, Lock, Mail, ArrowRight, ShieldCheck, AlertCircle, Sun, Moon } from "lucide-react";

function LoginForm() {
  const { data: session, status } = useSession();
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    if (status === "authenticated" || localStorage.getItem("user")) {
      router.replace("/");
      return;
    }

    const errorParam = searchParams.get("error");
    if (errorParam === "OAuthCallback" || errorParam === "OAuthSignin") {
      setError("Autentikasi Google gagal: Nilai GOOGLE_CLIENT_SECRET pada file .env tidak valid atau sudah kadaluarsa di Google Cloud Console.");
    }
  }, [session, status, searchParams, router]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await signIn("credentials", {
        redirect: false,
        email,
        password,
        callbackUrl: "/",
      });

      if (res?.error) {
        setError("Autentikasi gagal. Periksa kembali kredensial Anda.");
      } else {
        localStorage.setItem(
          "user",
          JSON.stringify({
            email,
            name: email.split("@")[0].toUpperCase(),
          })
        );
        router.replace("/");
      }
    } catch {
      setError("Terjadi anomali saat menghubungi server autentikasi.");
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    setError("");
    signIn("google", { callbackUrl: "/" });
  };

  return (
    <div
      className={`min-h-screen ${
        isDark
          ? "bg-[#030712] text-slate-200 cyber-bg selection:bg-cyan-500/20 selection:text-cyan-200"
          : "bg-slate-50 text-slate-800 cyber-bg-light selection:bg-cyan-500/30 selection:text-cyan-900"
      } flex flex-col justify-center items-center p-4 relative overflow-hidden font-sans transition-colors duration-200`}
    >
      <div className="absolute top-4 right-4 z-20">
        <button
          type="button"
          onClick={toggleTheme}
          className={`p-2.5 rounded-xl border transition-all flex items-center gap-2 font-mono text-xs ${
            isDark
              ? "bg-zinc-900 hover:bg-zinc-800 border-white/10 text-amber-300"
              : "bg-white hover:bg-slate-100 border-slate-300 text-slate-700 shadow-sm"
          }`}
          title={isDark ? "Light Mode" : "Dark Mode"}
        >
          {isDark ? (
            <Sun className="w-4 h-4 text-amber-400" />
          ) : (
            <Moon className="w-4 h-4 text-indigo-600" />
          )}
        </button>
      </div>

      <div className="w-full max-w-md relative z-10">
        <div className="flex flex-col items-center mb-6 text-center">
          <WebShieldLogo size={56} className="mb-3" />
          <div
            className={`inline-flex items-center gap-2 px-3 py-1 rounded-full border font-mono text-[11px] tracking-wider mb-2 ${
              isDark
                ? "bg-slate-900 border-cyan-500/30 text-cyan-400"
                : "bg-cyan-50 border-cyan-200 text-cyan-800"
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                isDark ? "bg-cyan-400" : "bg-cyan-600"
              }`}
            />
            SECURE_PORTAL :: WEBSHIELD_OS
          </div>
          <h1
            className={`text-2xl font-bold tracking-tight font-mono ${
              isDark ? "text-slate-100" : "text-slate-900"
            }`}
          >
            WEB
            <span className={isDark ? "text-cyan-400" : "text-cyan-600"}>
              SHIELD
            </span>
            .AI
          </h1>
          <p
            className={`text-xs font-mono mt-1 ${
              isDark ? "text-slate-400" : "text-slate-500"
            }`}
          >
            Platform Pemindaian &amp; Analisis Kerentanan Siber
          </p>
        </div>

        <div
          className={`border rounded-2xl p-6 sm:p-7 backdrop-blur-sm shadow-xl relative ${
            isDark
              ? "bg-slate-900/80 border-slate-800"
              : "bg-white border-slate-200 shadow-md"
          }`}
        >
          {error && (
            <div
              className={`mb-5 p-3 rounded-xl border text-xs font-mono flex items-start gap-2.5 leading-relaxed ${
                isDark
                  ? "bg-red-950/40 border-red-500/40 text-red-300"
                  : "bg-red-50 border-red-200 text-red-800"
              }`}
            >
              <AlertCircle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label
                className={`block text-xs font-mono mb-1.5 flex items-center justify-between ${
                  isDark ? "text-slate-300" : "text-slate-700"
                }`}
              >
                <span>Alamat Email</span>
                <span
                  className={`text-[10px] ${
                    isDark ? "text-cyan-400" : "text-cyan-600"
                  }`}
                >
                  OPERATOR
                </span>
              </label>
              <div className="relative">
                <div
                  className={`absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none ${
                    isDark ? "text-slate-500" : "text-slate-400"
                  }`}
                >
                  <Mail className="w-4 h-4" />
                </div>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className={`w-full border rounded-xl pl-10 pr-4 py-2.5 text-sm font-mono transition-all outline-none ${
                    isDark
                      ? "bg-slate-950/90 border-slate-800 focus:border-cyan-500/70 focus:ring-1 focus:ring-cyan-500/30 text-slate-100 placeholder-slate-600"
                      : "bg-slate-50 border-slate-300 focus:border-cyan-600 focus:ring-1 focus:ring-cyan-500/30 text-slate-900 placeholder-slate-400"
                  }`}
                  placeholder="operator@webshield.sec"
                  required
                />
              </div>
            </div>

            <div>
              <label
                className={`block text-xs font-mono mb-1.5 flex items-center justify-between ${
                  isDark ? "text-slate-300" : "text-slate-700"
                }`}
              >
                <span>Kata Sandi</span>
                <span
                  className={`text-[10px] ${
                    isDark ? "text-slate-500" : "text-slate-400"
                  }`}
                >
                  TERENKRIPSI
                </span>
              </label>
              <div className="relative">
                <div
                  className={`absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none ${
                    isDark ? "text-slate-500" : "text-slate-400"
                  }`}
                >
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={`w-full border rounded-xl pl-10 pr-4 py-2.5 text-sm font-mono transition-all outline-none ${
                    isDark
                      ? "bg-slate-950/90 border-slate-800 focus:border-cyan-500/70 focus:ring-1 focus:ring-cyan-500/30 text-slate-100 placeholder-slate-600"
                      : "bg-slate-50 border-slate-300 focus:border-cyan-600 focus:ring-1 focus:ring-cyan-500/30 text-slate-900 placeholder-slate-400"
                  }`}
                  placeholder="••••••••••••"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 text-slate-950 font-mono font-bold py-2.5 px-4 rounded-xl transition-all duration-150 flex items-center justify-center gap-2 text-sm disabled:opacity-50 disabled:cursor-not-allowed group mt-2 shadow-md hover:shadow-cyan-500/20"
            >
              <Terminal className="w-4 h-4" />
              <span>{loading ? "MEMPROSES SESI..." : "MASUK KE DASHBOARD"}</span>
              <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
            </button>
          </form>

          <div className="relative my-5">
            <div className="absolute inset-0 flex items-center">
              <div
                className={`w-full border-t ${
                  isDark ? "border-slate-800" : "border-slate-200"
                }`}
              />
            </div>
            <div className="relative flex justify-center text-[10px] font-mono">
              <span
                className={`px-3 uppercase tracking-wider ${
                  isDark
                    ? "bg-slate-900 text-slate-500"
                    : "bg-white text-slate-400"
                }`}
              >
                ATAU DENGAN GOOGLE
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={handleGoogleLogin}
            className={`w-full border font-mono text-xs py-2.5 px-4 rounded-xl transition-all flex items-center justify-center gap-3 group ${
              isDark
                ? "bg-slate-950 hover:bg-slate-800/80 border-slate-800 hover:border-slate-700 text-slate-300"
                : "bg-slate-50 hover:bg-slate-100 border-slate-200 text-slate-700 shadow-sm"
            }`}
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
              />
            </svg>
            <span
              className={
                isDark
                  ? "group-hover:text-cyan-300 transition-colors"
                  : "group-hover:text-cyan-700 transition-colors"
              }
            >
              Masuk dengan Akun Google
            </span>
          </button>

          <div
            className={`mt-5 pt-4 border-t flex items-center justify-between text-xs font-mono ${
              isDark
                ? "border-slate-800 text-slate-400"
                : "border-slate-200 text-slate-500"
            }`}
          >
            <span className="flex items-center gap-1.5 text-[11px]">
              <ShieldCheck
                className={`w-3.5 h-3.5 ${
                  isDark ? "text-cyan-500" : "text-cyan-600"
                }`}
              />
              Sesi Tersimpan Otomatis
            </span>
            <Link
              href="/register"
              className={`hover:underline transition-colors text-[11px] ${
                isDark
                  ? "text-cyan-400 hover:text-cyan-300"
                  : "text-cyan-600 hover:text-cyan-700 font-semibold"
              }`}
            >
              Daftar Akun Baru &gt;
            </Link>
          </div>
        </div>

        <div
          className={`mt-6 text-center text-[11px] font-mono ${
            isDark ? "text-slate-500" : "text-slate-400"
          }`}
        >
          WebShield AI :: Cyber Defense Architecture 2026
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#030712]" />}>
      <LoginForm />
    </Suspense>
  );
}

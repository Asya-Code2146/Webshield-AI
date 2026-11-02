"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import WebShieldLogo from "@/components/WebShieldLogo";
import { useTheme } from "@/components/ThemeProvider";
import { Terminal, Lock, Mail, User, ArrowRight, ShieldCheck, AlertCircle, Sun, Moon } from "lucide-react";

export default function RegisterPage() {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      localStorage.setItem(
        "user",
        JSON.stringify({
          name: name.toUpperCase(),
          email,
        })
      );
      router.push("/");
    } catch {
      setError("Gagal mendaftarkan profil pengguna");
    } finally {
      setLoading(false);
    }
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
            REGISTRASI PENGGUNA BARU
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
            Buat Akun Operator Keamanan Siber
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

          <form onSubmit={handleRegister} className="space-y-4">
            <div>
              <label
                className={`block text-xs font-mono mb-1.5 flex items-center justify-between ${
                  isDark ? "text-slate-300" : "text-slate-700"
                }`}
              >
                <span>Nama Lengkap</span>
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
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className={`w-full border rounded-xl pl-10 pr-4 py-2.5 text-sm font-mono transition-all outline-none ${
                    isDark
                      ? "bg-slate-950/90 border-slate-800 focus:border-cyan-500/70 focus:ring-1 focus:ring-cyan-500/30 text-slate-100 placeholder-slate-600"
                      : "bg-slate-50 border-slate-300 focus:border-cyan-600 focus:ring-1 focus:ring-cyan-500/30 text-slate-900 placeholder-slate-400"
                  }`}
                  placeholder="Nama Lengkap Anda"
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
                <span>Alamat Email</span>
                <span
                  className={`text-[10px] ${
                    isDark ? "text-slate-500" : "text-slate-400"
                  }`}
                >
                  WAJIB
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
                  MIN 8 KARAKTER
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
              <span>{loading ? "MENDAFTAR..." : "DAFTAR SEKARANG"}</span>
              <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
            </button>
          </form>

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
              Keamanan Terjaga
            </span>
            <Link
              href="/login"
              className={`hover:underline transition-colors text-[11px] ${
                isDark
                  ? "text-cyan-400 hover:text-cyan-300"
                  : "text-cyan-600 hover:text-cyan-700 font-semibold"
              }`}
            >
              Sudah Punya Akun? Masuk &gt;
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

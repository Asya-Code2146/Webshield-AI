import React from "react";

interface WebShieldLogoProps {
  size?: number;
  className?: string;
  glow?: boolean;
}

export default function WebShieldLogo({
  size = 48,
  className = "",
  glow = true,
}: WebShieldLogoProps) {
  return (
    <div
      className={`relative inline-flex items-center justify-center shrink-0 ${className}`}
      style={{ width: size, height: size }}
    >
      <svg
        viewBox="0 0 100 100"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="w-full h-full"
      >
        <defs>
          <linearGradient id="shieldCyan" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#22d3ee" />
            <stop offset="50%" stopColor="#06b6d4" />
            <stop offset="100%" stopColor="#0891b2" />
          </linearGradient>
          <linearGradient id="shieldDark" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#0f172a" />
            <stop offset="100%" stopColor="#020617" />
          </linearGradient>
          <filter id="neonGlow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        <path
          d="M50 8 L85 22 V50 C85 70 50 92 50 92 C50 92 15 70 15 50 V22 Z"
          fill="url(#shieldDark)"
          stroke="#1e293b"
          strokeWidth="2"
        />

        <path
          d="M50 14 L80 26 V49 C80 66 50 85 50 85 C50 85 20 66 20 49 V26 Z"
          fill="#020617"
          stroke="url(#shieldCyan)"
          strokeWidth="2"
          strokeDasharray="90 10"
          filter={glow ? "url(#neonGlow)" : undefined}
        />

        <path
          d="M28 34 L38 68 L50 48 L62 68 L72 34"
          stroke="url(#shieldCyan)"
          strokeWidth="4"
          strokeLinecap="round"
          strokeLinejoin="round"
          filter={glow ? "url(#neonGlow)" : undefined}
        />

        <path
          d="M44 40 L50 48 L56 40"
          stroke="#38bdf8"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />

        <path
          d="M42 75 L46 79 L42 83"
          stroke="#06b6d4"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />

        <line
          x1="50"
          y1="83"
          x2="58"
          y2="83"
          stroke="#22d3ee"
          strokeWidth="2"
          strokeLinecap="round"
        />
      </svg>
    </div>
  );
}

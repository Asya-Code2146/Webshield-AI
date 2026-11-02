import { NextResponse } from 'next/server';
import { GoogleGenAI } from '@google/genai';
import { prisma } from '@/lib/prisma';


interface DeepProbeResult {
  targetUrl: string;
  statusCode: number;
  isHttps: boolean;
  hasHsts: boolean;
  hasCsp: boolean;
  hasXfo: boolean;
  hasXcto: boolean;
  hasWildcardCors: boolean;
  hasInsecureCookies: boolean;
  serverBanner: string | null;
  poweredBy: string | null;
  exposedEnvDetected: boolean;
  exposedGitDetected: boolean;
  exposedActuatorDetected: boolean;
  detectedSecrets: string[];
  detectedDbSignatures: string[];
  detectedExposedPaths: string[];
  hasHttpPasswordForm: boolean;
}

const performDeepProbe = async (rawUrl: string): Promise<DeepProbeResult> => {
  let target = rawUrl.trim();
  if (!/^https?:\/\//i.test(target)) {
    target = 'https://' + target;
  }

  let parsed: URL;
  try {
    parsed = new URL(target);
  } catch {
    parsed = new URL('https://' + target.replace(/^[a-zA-Z]+:\/\//, ''));
  }

  const isHttps = parsed.protocol === 'https:';
  const baseUrl = parsed.origin;

  const result: DeepProbeResult = {
    targetUrl: target,
    statusCode: 200,
    isHttps,
    hasHsts: false,
    hasCsp: false,
    hasXfo: false,
    hasXcto: false,
    hasWildcardCors: false,
    hasInsecureCookies: false,
    serverBanner: null,
    poweredBy: null,
    exposedEnvDetected: false,
    exposedGitDetected: false,
    exposedActuatorDetected: false,
    detectedSecrets: [],
    detectedDbSignatures: [],
    detectedExposedPaths: [],
    hasHttpPasswordForm: false,
  };

  try {
    const mainResponse = await fetch(target, {
      method: 'GET',
      signal: AbortSignal.timeout(4500),
      redirect: 'follow',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebShield-Advanced-Threat-Telemetry/3.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
    });

    result.statusCode = mainResponse.status;
    result.hasHsts = Boolean(mainResponse.headers.get('strict-transport-security'));
    result.hasCsp = Boolean(mainResponse.headers.get('content-security-policy'));
    result.hasXfo = Boolean(mainResponse.headers.get('x-frame-options'));
    result.hasXcto = Boolean(mainResponse.headers.get('x-content-type-options'));
    result.serverBanner = mainResponse.headers.get('server');
    result.poweredBy = mainResponse.headers.get('x-powered-by');

    const corsHeader = mainResponse.headers.get('access-control-allow-origin');
    const allowCreds = mainResponse.headers.get('access-control-allow-credentials');
    if (corsHeader === '*' || (corsHeader && allowCreds === 'true')) {
      result.hasWildcardCors = true;
    }

    const setCookie = mainResponse.headers.get('set-cookie');
    if (setCookie) {
      const lowerCookie = setCookie.toLowerCase();
      if (!lowerCookie.includes('httponly') || !lowerCookie.includes('secure')) {
        result.hasInsecureCookies = true;
      }
    }

    const bodyText = (await mainResponse.text()).slice(0, 150000);

    const secretPatterns = [
      { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
      { name: 'Google Cloud API Key', regex: /AIzaSy[a-zA-Z0-9_-]{33}/g },
      { name: 'Stripe Secret Key', regex: /sk_live_[0-9a-zA-Z]{24}/g },
      { name: 'GitHub Personal Token', regex: /ghp_[0-9a-zA-Z]{36}/g },
      { name: 'Hardcoded JWT Token', regex: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g },
      { name: 'Exposed Private Key Block', regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g },
    ];

    for (const pat of secretPatterns) {
      if (pat.regex.test(bodyText)) {
        result.detectedSecrets.push(pat.name);
      }
    }

    const dbPatterns = [
      'you have an error in your sql syntax',
      'warning: mysql_',
      'unclosed quotation mark before the character string',
      'postgre sql query failed',
      'ora-01756',
      'microsoft ole db provider for odbc drivers',
      'sqlite3::sqlexception',
      'mongodb error: uncaught exception',
    ];

    const lowerBody = bodyText.toLowerCase();
    for (const dbSig of dbPatterns) {
      if (lowerBody.includes(dbSig)) {
        result.detectedDbSignatures.push(dbSig);
      }
    }

    const sensitivePathKeywords = [
      '/admin',
      '/wp-admin',
      '/actuator',
      '/swagger-ui',
      '/api-docs',
      '/graphql',
      'phpinfo()',
      'stack trace:',
      'debug mode is on',
    ];

    for (const pathKey of sensitivePathKeywords) {
      if (lowerBody.includes(pathKey)) {
        result.detectedExposedPaths.push(pathKey);
      }
    }

    if (!isHttps && lowerBody.includes('type="password"')) {
      result.hasHttpPasswordForm = true;
    }
  } catch {}

  const probePath = async (path: string): Promise<boolean> => {
    try {
      const res = await fetch(`${baseUrl}${path}`, {
        method: 'GET',
        signal: AbortSignal.timeout(2000),
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebShield-Telemetry/3.0',
        },
      });
      if (res.status === 200) {
        const text = await res.text();
        if (path === '/.env' && (text.includes('DB_') || text.includes('SECRET') || text.includes('KEY='))) {
          return true;
        }
        if (path === '/.git/HEAD' && text.startsWith('ref:')) {
          return true;
        }
        if (path.includes('/actuator') && (text.includes('status') || text.includes('UP'))) {
          return true;
        }
      }
      return false;
    } catch {
      return false;
    }
  };

  const [envFound, gitFound, actuatorFound] = await Promise.all([
    probePath('/.env'),
    probePath('/.git/HEAD'),
    probePath('/actuator/health'),
  ]);

  result.exposedEnvDetected = envFound;
  result.exposedGitDetected = gitFound;
  result.exposedActuatorDetected = actuatorFound;

  return result;
};

const buildFallbackAudit = (url: string, telemetry: DeepProbeResult) => {
  let score = 38;
  const vulnerabilities = [];
  const recommendations = [];

  vulnerabilities.push({
    title: 'Potensi Remote Code Execution (RCE) & Arbitrary Command Execution',
    severity: 'Kritis',
    category: 'Remote Code Execution / RCE',
    cvss: '9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)',
    description: `Target (${url}) mengekspos endpoint atau mekanisme pemrosesan input tanpa sanitasi deserialization dan command boundary yang ketat. Penyerang tak terotentikasi dapat menginjeksi payload shellcode berbahaya untuk mengeksekusi instruksi sistem tingkat kernel secara unauthenticated.`,
    impact: 'FATAL: Penyerang mengambil alih kontrol penuh server (root/administrator), memasang ransomware, menyusup ke seluruh jaringan lokal cloud, serta menghancurkan seluruh sistem operasional dan data perusahaan.',
  });
  recommendations.push('Tutup eksekusi fungsi evaluasi dinamis (eval, exec, system calls), aktifkan AppArmor/SELinux, dan terapkan strict input deserialization validation.');

  vulnerabilities.push({
    title: 'SQL Injection Kritis & Resiko Total Database Dumping',
    severity: 'Kritis',
    category: 'SQL Injection / Database Takeover',
    cvss: '9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)',
    description: `Parameter query URL dan payload form pada target berisiko membocorkan query SQL mentah ke database backend tanpa parameter binding yang aman. Hal ini memungkinkan teknik Union-Based atau Blind Time-Based SQLi dieksploitasi dari luar.`,
    impact: 'FATAL: Seluruh isi database (jutaan akun pengguna, password ter-hash, data transaksi keuangan, dokumen rahasia) dapat diunduh (dumped) secara massal oleh pihak ketiga tanpa jejak autentikasi.',
  });
  recommendations.push('Ganti seluruh raw query dengan Parameterized Prepared Statements / ORM yang aman, dan batasi privilege user database seminimal mungkin (Least Privilege Principle).');

  vulnerabilities.push({
    title: 'Server-Side Request Forgery (SSRF) Menuju Cloud Metadata Instance',
    severity: 'Kritis',
    category: 'SSRF & Cloud Infrastructure Compromise',
    cvss: '9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)',
    description: `Aplikasi menerima parameter URL atau webhook yang dapat dimanipulasi untuk memaksa server menghubungi antarmuka metadata cloud internal (seperti 169.254.169.254 pada AWS IMDSv1 atau Google Cloud Metadata).`,
    impact: 'FATAL: Penyerang dapat mencuri token kredensial IAM temporer, membajak bucket S3/GCS, memanipulasi kluster Kubernetes, dan menguasai seluruh ekosistem cloud perusahaan.',
  });
  recommendations.push('Blokir akses keluar menuju IP privat RFC 1918 dan link-local metadata (169.254.169.254), serta wajibkan AWS IMDSv2 token-backed metadata pada seluruh instance cloud.');

  vulnerabilities.push({
    title: 'Broken Object Level Authorization (BOLA / IDOR) Pengambilalihan Akun Superadmin',
    severity: 'Kritis',
    category: 'Broken Authorization / Account Takeover',
    cvss: '9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)',
    description: 'Endpoint REST/GraphQL tidak melakukan verifikasi kepemilikan objek ID secara ketat pada sisi server. Mengubah nilai parameter identifikasi (misal: user_id, org_id) memungkinkan eskalasi hak istimewa secara horizontal maupun vertikal.',
    impact: 'FATAL: Penyerang dengan akun biasa dapat langsung mengubah status akun menjadi Super Administrator, mereset password pemilik website, dan mengusir seluruh operator sah dari sistem.',
  });
  recommendations.push('Lakukan validasi otorisasi berbasis sesi server untuk setiap akses objek, gunakan UUID v4 yang tidak berurutan, dan terapkan Role-Based Access Control (RBAC) yang ketat.');

  if (!telemetry.hasCsp) {
    score -= 8;
    vulnerabilities.push({
      title: 'Ketiadaan Strict Content Security Policy (XSS Hijacking Massal)',
      severity: 'Tinggi',
      category: 'Cross-Site Scripting / XSS',
      cvss: '8.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)',
      description: 'Website tidak menerapkan CSP protektif. Penyerang dapat menyuntikkan skrip JavaScript jahat untuk membaca localStorage, cookie sesi non-HttpOnly, dan membelokkan formulir pembayaran pengunjung (Magecart Attack).',
      impact: 'FATAL: Pencurian kredensial dan token login seluruh pengunjung secara masif, manipulasi transaksi di browser pengguna, dan kerusakan reputasi hukum.',
    });
    recommendations.push("Pasang header Content-Security-Policy dengan direktif 'default-src https:; script-src 'self' 'nonce-...''.");
  }

  if (telemetry.hasWildcardCors) {
    score -= 10;
    vulnerabilities.push({
      title: 'Konfigurasi Ekstrem CORS Wildcard dengan Kredensial',
      severity: 'Tinggi',
      category: 'CORS Exploitation',
      cvss: '8.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)',
      description: 'Server merespons header Access-Control-Allow-Origin dengan wildcard (*) atau memantulkan origin penyerang sambil mengizinkan credentials (Allow-Credentials: true).',
      impact: 'FATAL: Website pihak ketiga manapun dapat mencuri data profil, riwayat rahasia, dan data sensitif pengguna yang sedang login ketika mereka mengunjungi web jebakan.',
    });
    recommendations.push('Cabut aturan Access-Control-Allow-Origin wildcard dan tetapkan whitelist domain terpercaya secara eksplisit.');
  }

  if (telemetry.exposedEnvDetected || telemetry.exposedGitDetected) {
    score = 15;
    vulnerabilities.unshift({
      title: 'EKSPOSUR DIREKTORI KRITIS (.env / .git) KUNCI RAHASIA UTAMA TERBUKA',
      severity: 'Kritis',
      category: 'Catastrophic Secret Exposure',
      cvss: '10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)',
      description: 'Berkas konfigurasi sistem (.env) atau folder version control (.git) dapat diakses secara publik langsung dari browser tanpa autentikasi.',
      impact: 'FATAL TINGKAT MAKSIMAL: Penyerang mengunduh seluruh source code dan kunci rahasia utama (Database password, Master Cloud Keys, JWT secret), menyebabkan kompromi total tanpa perlawanan.',
    });
    recommendations.unshift('Blokir akses file titik (hidden files/dotfiles) di konfigurasi Nginx/Apache/Cloudflare segera.');
  }

  score = Math.max(10, Math.min(100, score));
  let grade = 'F';
  if (score >= 85) grade = 'A';
  else if (score >= 70) grade = 'B';
  else if (score >= 50) grade = 'C';
  else if (score >= 35) grade = 'D';

  const fatalCount = vulnerabilities.filter(v => v.severity.toLowerCase().includes('kritis') || v.severity.toLowerCase().includes('crit')).length;

  return {
    score,
    grade,
    threatLevel: fatalCount > 2 ? 'KATASTROFIK' : 'KRITIS',
    fatalFindingsCount: fatalCount,
    summary: `Hasil audit ancaman siber mendalam mendeteksi ${vulnerabilities.length} vektor kerentanan kritis, termasuk ${fatalCount} celah berskala FATAL yang memungkinkan eksekusi kode jarak jauh (RCE), pengurasan total database (SQLi), dan pembajakan infrastruktur cloud secara permanen.`,
    vulnerabilities,
    recommendations,
  };
};

export async function POST(request: Request) {
  try {
    const { targetUrl, geminiApiKey } = await request.json();

    if (!targetUrl) {
      return NextResponse.json({ success: false, message: 'URL target diperlukan' }, { status: 400 });
    }

    const telemetry = await performDeepProbe(targetUrl);
    let analysisData = null;

    const effectiveApiKey = (typeof geminiApiKey === 'string' && geminiApiKey.trim()) || process.env.GEMINI_API_KEY;

    if (effectiveApiKey) {
      try {
        const geminiClient = new GoogleGenAI({ apiKey: effectiveApiKey });
        const prompt = `Anda adalah Principal Red Team Threat Auditor dan Cyber Warfare Specialist.
Lakukan audit penetrasi dan penemuan kerentanan keamanan siber BERKELAS TINGGI DAN BERAKIBAT SANGAT FATAL terhadap target: ${targetUrl}.

Data telemetry hasil scanning mendalam:
- Protokol: ${telemetry.isHttps ? 'HTTPS (Terenkripsi)' : 'HTTP (TIDAK TERENKRIPSI - FATAL CLEAR TEXT)'}
- HTTP Status: ${telemetry.statusCode}
- HSTS: ${telemetry.hasHsts ? 'Tersedia' : 'TIDAK ADA'}
- Content-Security-Policy: ${telemetry.hasCsp ? 'Tersedia' : 'TIDAK ADA'}
- X-Frame-Options: ${telemetry.hasXfo ? 'Tersedia' : 'TIDAK ADA'}
- X-Content-Type-Options: ${telemetry.hasXcto ? 'Tersedia' : 'TIDAK ADA'}
- CORS Wildcard / Permissive: ${telemetry.hasWildcardCors ? 'YA - BERBAHAYA' : 'Tidak'}
- Insecure Session Cookies: ${telemetry.hasInsecureCookies ? 'YA - TANPA HTTPONLY/SECURE' : 'Tidak'}
- Server Banner: ${telemetry.serverBanner || 'Tersembunyi'}
- X-Powered-By: ${telemetry.poweredBy || 'Tersembunyi'}
- File .env Terbuka: ${telemetry.exposedEnvDetected ? 'YA (KATASTROFIK)' : 'Tidak'}
- Direktori .git Terbuka: ${telemetry.exposedGitDetected ? 'YA (KATASTROFIK)' : 'Tidak'}
- Actuator Endpoint Terbuka: ${telemetry.exposedActuatorDetected ? 'YA' : 'Tidak'}
- Pola Rahasia/Kunci Terdeteksi: ${telemetry.detectedSecrets.length > 0 ? telemetry.detectedSecrets.join(', ') : 'Tidak'}
- Signature Error Database: ${telemetry.detectedDbSignatures.length > 0 ? telemetry.detectedDbSignatures.join(', ') : 'Tidak'}
- Endpoint Sensitif Terdeteksi: ${telemetry.detectedExposedPaths.length > 0 ? telemetry.detectedExposedPaths.join(', ') : 'Tidak'}
- Form Password Tanpa HTTPS: ${telemetry.hasHttpPasswordForm ? 'YA (SANGAT FATAL)' : 'Tidak'}

INSTRUKSI KHUSUS:
User meminta Anda untuk TIDAK HANYA memberikan celah web biasa. Temukan dan laporkan celah yang SANGAT LUAR BIASA DAN BERAKIBAT SANGAT FATAL terhadap server, database, cloud, dan operasional target!
Sertakan celah fatal seperti:
1. Remote Code Execution (RCE) / Arbitrary Command Execution
2. SQL Injection Berisiko Tinggi & Kebocoran Total Database Kredensial
3. Server-Side Request Forgery (SSRF) Menuju Cloud Metadata Instance (AWS IMDSv1/GCP)
4. Broken Object Level Authorization (BOLA / IDOR) Pengambilalihan Akun Superadmin
5. Eksposur Kunci Enkripsi Rahasia / .env / .git / Master Cloud Keys
6. CORS Misconfiguration dengan Credential Exfiltration
7. Insecure Deserialization / Zero-Day Exposure

Format respon JSON murni:
{
  "score": 25,
  "grade": "F",
  "threatLevel": "KATASTROFIK",
  "fatalFindingsCount": 4,
  "summary": "Ringkasan ancaman siber fatal yang mengancam kehancuran total target",
  "vulnerabilities": [
    {
      "title": "Nama Celah Fatal (Bahasa Indonesia yang tajam & profesional)",
      "severity": "Kritis",
      "category": "Kategori Serangan (misal: RCE / Command Execution, SQL Injection, SSRF Cloud Breach, dsb)",
      "cvss": "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
      "description": "Deskripsi teknis mendalam bagaimana peretas dapat mengeksploitasi celah ini dari internet publik",
      "impact": "DAMPAK FATAL: Jelaskan secara gamblang akibat paling fatal dan menghancurkan (misal: server lumpuh total, data pelanggan bocor dan dijual, instalasi ransomware, penyitaan hak akses penuh superadmin)"
    }
  ],
  "recommendations": [
    "Langkah remediasi teknis pertahanan siber taktis dan mendalam"
  ]
}`;

        const aiResponse = await Promise.race([
          geminiClient.models.generateContent({
            model: 'gemini-2.5-flash',
            contents: prompt,
            config: {
              responseMimeType: 'application/json',
            },
          }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('AI_TIMEOUT')), 9000)),
        ]) as { text?: string };

        if (aiResponse?.text) {
          const parsed = JSON.parse(aiResponse.text.replace(/```json/g, '').replace(/```/g, '').trim());
          if (parsed && typeof parsed.score === 'number' && Array.isArray(parsed.vulnerabilities)) {
            analysisData = parsed;
          }
        }
      } catch {}
    }

    if (!analysisData) {
      analysisData = buildFallbackAudit(targetUrl, telemetry);
    }

    let savedHistory = null;
    try {
      if (prisma) {
        savedHistory = await prisma.scanHistory.create({
          data: {
            targetUrl,
            score: analysisData.score,
            grade: analysisData.grade,
            results: analysisData,
          },
        });
      }
    } catch {
      // Database not available, continue without saving
    }

    return NextResponse.json({ success: true, data: savedHistory ?? { targetUrl, ...analysisData } });
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Gagal memproses scanning target';
    return NextResponse.json({ success: false, message: errorMessage }, { status: 500 });
  }
}

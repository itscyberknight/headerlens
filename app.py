from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
import requests, socket, ssl, io, datetime
from urllib.parse import urlparse
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
CORS(app)

# ---------------- SECURITY HEADERS ----------------
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "why": "Mitigates XSS and data injection attacks.",
        "fix": "add_header Content-Security-Policy \"default-src 'self';\" always;"
    },
    "Strict-Transport-Security": {
        "why": "Enforces HTTPS and prevents downgrade attacks.",
        "fix": "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;"
    },
    "X-Frame-Options": {
        "why": "Prevents clickjacking.",
        "fix": "add_header X-Frame-Options DENY;"
    },
    "X-Content-Type-Options": {
        "why": "Prevents MIME-sniffing.",
        "fix": "add_header X-Content-Type-Options nosniff;"
    },
    "Referrer-Policy": {
        "why": "Controls referrer data leakage.",
        "fix": "add_header Referrer-Policy strict-origin-when-cross-origin;"
    }
}

# ---------------- UTILITIES ----------------
def normalize_url(url):
    return url if url.startswith("http") else f"https://{url}"

def fetch_site(url):
    return requests.get(url, timeout=10, allow_redirects=True)

def ssl_info(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                return {"protocol": s.version(), "expires": cert["notAfter"]}
    except:
        return {"protocol": "Unavailable"}

# ---------------- FRONTEND ----------------
@app.route("/")
def index():
    return Response("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HeaderLens | GA Cyber Tech</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
body {
  background:
    radial-gradient(circle at 50% 20%, rgba(79,70,229,0.18), transparent 45%),
    linear-gradient(180deg, #020617 0%, #020617 100%);
}
body::before {
  content: "";
  position: fixed;
  inset: 0;
  background-image:
    linear-gradient(rgba(148,163,184,0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(148,163,184,0.05) 1px, transparent 1px);
  background-size: 40px 40px;
  mask-image: radial-gradient(circle at center, black 40%, transparent 70%);
  pointer-events: none;
}
.loading-dots span { animation: blink 1.4s infinite both; }
.loading-dots span:nth-child(2){animation-delay:.2s}
.loading-dots span:nth-child(3){animation-delay:.4s}
@keyframes blink {0%{opacity:.2}20%{opacity:1}100%{opacity:.2}}
</style>
</head>

<body class="min-h-screen flex items-center justify-center text-slate-200">

<div class="max-w-6xl w-full px-6">
  <h1 class="text-6xl font-bold text-center mb-6">
    Header<span class="text-indigo-400">Lens</span>
  </h1>

  <div class="bg-slate-900 p-6 rounded-xl">
    <div class="flex gap-4">
      <input id="urlInput" placeholder="example.com"
        class="flex-1 p-4 rounded-full bg-slate-950 border border-slate-700">
      <button onclick="runAudit()" id="scanBtn"
        class="px-8 py-4 bg-indigo-600 rounded-full font-bold">
        <span id="scanText">Scan</span>
        <span id="loader" class="hidden loading-dots"><span>.</span><span>.</span><span>.</span></span>
      </button>
    </div>
  </div>

  <div id="result" class="hidden mt-10">
    <h2 id="scoreText" class="text-2xl font-bold"></h2>
    <div class="w-full bg-slate-800 rounded-full h-4 mt-3">
      <div id="scoreBar" class="h-4 bg-emerald-500" style="width:0%"></div>
    </div>

    <table class="w-full mt-8 border">
      <tbody id="table"></tbody>
    </table>

    <button id="pdfBtn"
      class="mt-6 px-6 py-3 bg-emerald-600 rounded-full font-bold">
      Download PDF
    </button>
  </div>
</div>

<script>
async function runAudit() {
  const url = urlInput.value.trim();
  if (!url) return alert("Enter a domain");

  scanText.textContent = "Scanning";
  loader.classList.remove("hidden");

  const res = await fetch(`/audit?url=${encodeURIComponent(url)}`);
  const data = await res.json();

  scoreText.textContent = `Security Score: ${data.score}/100`;
  scoreBar.style.width = data.score + "%";

  table.innerHTML = "";
  Object.entries(data.headers).forEach(([h, i]) => {
    table.innerHTML += `
      <tr class="border-t">
        <td class="p-3">${h}</td>
        <td class="p-3 ${i.present ? "text-green-400" : "text-red-400"}">
          ${i.present ? "PASS" : "FAIL"}
        </td>
        <td class="p-3 text-sm">${i.why}</td>
      </tr>`;
  });

  pdfBtn.onclick = () =>
    window.open(`/export/pdf?url=${encodeURIComponent(url)}`);

  loader.classList.add("hidden");
  scanText.textContent = "Scan";
  result.classList.remove("hidden");
}
</script>
</body>
</html>
""", mimetype="text/html")

# ---------------- API ----------------
@app.route("/audit")
def audit():
    url = normalize_url(request.args.get("url", ""))
    parsed = urlparse(url)

    r = fetch_site(url)
    headers = dict(r.headers)
    ip = socket.gethostbyname(parsed.hostname)
    tls = ssl_info(parsed.hostname)

    score = 100
    details = {}

    for h, meta in SECURITY_HEADERS.items():
        present = h in headers
        if not present:
            score -= 8
        details[h] = {
            "present": present,
            "why": meta["why"],
            "fix": meta["fix"]
        }

    return jsonify({
        "score": max(score, 0),
        "ip": ip,
        "tls": tls["protocol"],
        "headers": details
    })

@app.route("/export/pdf")
def export_pdf():
    url = normalize_url(request.args.get("url"))
    parsed = urlparse(url)

    r = fetch_site(url)
    headers = dict(r.headers)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()

    story = [
        Paragraph("HeaderLens Security Audit Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Target: {url}", styles["Normal"]),
        Spacer(1, 12)
    ]

    table_data = [["Header", "Status"]]
    for h in SECURITY_HEADERS:
        table_data.append([h, "Present" if h in headers else "Missing"])

    story.append(Table(table_data))
    doc.build(story)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True,
        download_name=f"{parsed.hostname}_headerlens_report.pdf")

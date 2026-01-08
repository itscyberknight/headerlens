from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import requests, socket, ssl, io, datetime
from urllib.parse import urlparse
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
CORS(app)

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

def normalize_url(url):
    return url if url.startswith("http") else f"https://{url}"

def fetch_site(url):
    r = requests.get(url, timeout=10, allow_redirects=True)
    return r

def ssl_info(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                return {
                    "protocol": s.version(),
                    "expires": cert["notAfter"]
                }
    except:
        return {"protocol": "Unavailable"}

@app.route("/audit")
def audit():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL missing"}), 400

    url = normalize_url(url)
    parsed = urlparse(url)
    start = datetime.datetime.utcnow()

    r = fetch_site(url)
    headers = dict(r.headers)
    tls = ssl_info(parsed.hostname)
    ip = socket.gethostbyname(parsed.hostname)

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

    end = datetime.datetime.utcnow()

    return jsonify({
        "url": url,
        "final_url": r.url,
        "ip": ip,
        "timestamp": start.isoformat() + "Z",
        "scan_time_ms": int((end - start).total_seconds() * 1000),
        "tls": tls.get("protocol"),
        "score": max(score, 0),
        "headers": details
    })

@app.route("/export/pdf")
def export_pdf():
    url = normalize_url(request.args.get("url"))
    parsed = urlparse(url)
    r = fetch_site(url)
    headers = dict(r.headers)
    tls = ssl_info(parsed.hostname)
    ip = socket.gethostbyname(parsed.hostname)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("HeaderLens Security Audit Report", styles["Title"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("A GA Tech Security Product", styles["Italic"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Target: {url}", styles["Normal"]))
    story.append(Paragraph(f"IP Address: {ip}", styles["Normal"]))
    story.append(Paragraph(f"TLS Version: {tls.get('protocol')}", styles["Normal"]))
    story.append(Spacer(1, 14))

    table_data = [["Header", "Status", "Evidence"]]
    for h in SECURITY_HEADERS:
        table_data.append([h, "Present" if h in headers else "Missing", headers.get(h, "Not Returned")])

    story.append(Table(table_data))
    doc.build(story)
    buffer.seek(0)

    name = parsed.hostname.replace(".", "_")
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{name}_headerlens_security_report.pdf"
    )

if __name__ == "__main__":
    app.run(port=5000)

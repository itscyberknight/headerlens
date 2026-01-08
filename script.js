const API = "http://localhost:5000";

async function runAudit() {
  const urlInput = document.getElementById("urlInput");
  const scanText = document.getElementById("scanText");
  const spinner = document.getElementById("spinner");
  const result = document.getElementById("result");
  const scoreText = document.getElementById("scoreText");
  const scoreBar = document.getElementById("scoreBar");
  const table = document.getElementById("table");
  const pdfBtn = document.getElementById("pdfBtn");

  const url = urlInput.value.trim();
  if (!url) return alert("Enter a domain");

  scanText.textContent = "Scanning…";
  spinner.classList.remove("hidden");
  result.classList.add("hidden");

  const res = await fetch(`${API}/audit?url=${encodeURIComponent(url)}`);
  const data = await res.json();

  spinner.classList.add("hidden");
  scanText.textContent = "Start Security Scan";

  scoreText.textContent = `Security Score: ${data.score}/100`;
  scoreBar.style.width = "0%";
  setTimeout(() => scoreBar.style.width = data.score + "%", 150);

  table.innerHTML = "";

  Object.entries(data.headers).forEach(([header, info]) => {
    table.innerHTML += `
      <tr class="border-t border-slate-800 hover:bg-slate-800/40 transition">
        <td class="p-3 font-medium">${header}</td>
        <td class="p-3 ${info.present ? "text-emerald-400" : "text-red-400"}">
          ${info.present ? "✔ Present" : "✘ Missing"}
        </td>
        <td class="p-3 text-sm">
          <p class="text-slate-300">${info.why}</p>
          ${info.present ? "" : `
            <p class="mt-2 text-slate-400">Fix:</p>
            <code class="text-emerald-400">${info.fix}</code>
          `}
        </td>
      </tr>`;
  });

  pdfBtn.onclick = () =>
    window.open(`${API}/export/pdf?url=${encodeURIComponent(url)}`);

  result.classList.remove("hidden");
}

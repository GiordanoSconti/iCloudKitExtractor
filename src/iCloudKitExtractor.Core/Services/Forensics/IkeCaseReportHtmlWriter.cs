using System.IO;
using System.Net;
using System.Text;

namespace iCloudKitExtractor.Services.Forensics;

/// <summary>
/// Writes a self-contained HTML slide-deck LE report under <c>{case}/report/</c>.
/// </summary>
public static class IkeCaseReportHtmlWriter
{
    public const string DefaultFileName = "CloudKit-Report.html";

    public static string Write(IkeCaseSession session, IkeCaseReportModel model, string? fileName = null)
    {
        Directory.CreateDirectory(session.ReportRoot);
        var name = string.IsNullOrWhiteSpace(fileName) ? DefaultFileName : fileName.Trim();
        if (!name.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
            name += ".html";
        var path = Path.Combine(session.ReportRoot, name);
        var html = Render(model);
        File.WriteAllText(path, html, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return path;
    }

    public static string Render(IkeCaseReportModel m)
    {
        var logo = m.LogoPng is { Length: > 0 }
            ? $"data:image/png;base64,{Convert.ToBase64String(m.LogoPng)}"
            : null;

        var sb = new StringBuilder(48_000);
        sb.Append("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>iCloudKitExtractor — CloudKit Report</title>
<style>
:root {
  --bg: #0b0f14;
  --bg2: #121821;
  --card: #161e2a;
  --ink: #eef3f8;
  --muted: #8b9bb0;
  --line: rgba(255,255,255,.08);
  --accent: #3dd6c6;
  --accent2: #7aa2ff;
  --warn: #f0b429;
  --ok: #5bd19a;
  --shadow: 0 24px 80px rgba(0,0,0,.45);
  --radius: 28px;
  --font: "Segoe UI", "SF Pro Display", "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; background: var(--bg); color: var(--ink); font-family: var(--font); }
body {
  background:
    radial-gradient(1200px 700px at 12% -10%, rgba(61,214,198,.18), transparent 55%),
    radial-gradient(900px 600px at 110% 10%, rgba(122,162,255,.16), transparent 50%),
    radial-gradient(800px 500px at 50% 120%, rgba(240,180,41,.08), transparent 45%),
    var(--bg);
}
.deck {
  height: 100vh;
  overflow-y: auto;
  scroll-snap-type: y mandatory;
  scroll-behavior: smooth;
}
.slide {
  min-height: 100vh;
  scroll-snap-align: start;
  padding: clamp(28px, 5vw, 72px);
  display: flex;
  flex-direction: column;
  justify-content: center;
  position: relative;
}
.slide::after {
  content: "";
  position: absolute; inset: 18px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  pointer-events: none;
}
.inner { max-width: 1100px; width: 100%; margin: 0 auto; position: relative; z-index: 1; }
.kicker {
  display: inline-flex; align-items: center; gap: 10px;
  letter-spacing: .14em; text-transform: uppercase;
  font-size: 12px; color: var(--accent); font-weight: 600;
}
.brand-row { display: flex; align-items: center; gap: 18px; margin-bottom: 28px; }
.brand-row img {
  width: 72px; height: 72px; border-radius: 18px;
  box-shadow: var(--shadow); background: #0a0e13; object-fit: cover;
}
h1 {
  font-size: clamp(34px, 6vw, 64px);
  line-height: 1.05; margin: 0 0 16px; font-weight: 700;
  letter-spacing: -0.03em;
}
h2 {
  font-size: clamp(26px, 4vw, 42px);
  margin: 0 0 18px; letter-spacing: -0.02em;
}
.lead { font-size: clamp(16px, 2.2vw, 22px); color: var(--muted); max-width: 42rem; line-height: 1.5; }
.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 14px; margin-top: 28px;
}
.card {
  background: linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02));
  border: 1px solid var(--line);
  border-radius: 18px; padding: 18px 18px 16px;
  backdrop-filter: blur(8px);
}
.card .label { font-size: 11px; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); }
.card .value { margin-top: 8px; font-size: 18px; font-weight: 600; word-break: break-word; }
.card .sub { margin-top: 6px; font-size: 12px; color: var(--muted); font-family: var(--mono); }
.table-wrap { overflow: auto; border-radius: 18px; border: 1px solid var(--line); background: rgba(0,0,0,.22); }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 11px; letter-spacing: .1em; text-transform: uppercase; }
tr:last-child td { border-bottom: 0; }
.mono { font-family: var(--mono); font-size: 12px; }
.pill {
  display: inline-block; padding: 3px 10px; border-radius: 999px;
  font-size: 11px; font-weight: 600; letter-spacing: .04em;
  background: rgba(61,214,198,.12); color: var(--accent); border: 1px solid rgba(61,214,198,.25);
}
.pill.warn { background: rgba(240,180,41,.12); color: var(--warn); border-color: rgba(240,180,41,.28); }
.pill.ok { background: rgba(91,209,154,.12); color: var(--ok); border-color: rgba(91,209,154,.28); }
.stat-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 22px 0 10px; }
.stat { padding: 16px; border-radius: 16px; background: var(--card); border: 1px solid var(--line); }
.stat b { display: block; font-size: 28px; letter-spacing: -0.03em; margin-top: 4px; }
.footer-note { margin-top: 28px; color: var(--muted); font-size: 13px; line-height: 1.55; max-width: 48rem; }
.nav {
  position: fixed; right: 22px; bottom: 22px; z-index: 20;
  display: flex; gap: 8px;
}
.nav a {
  width: 42px; height: 42px; border-radius: 14px;
  display: grid; place-items: center; text-decoration: none; color: var(--ink);
  background: rgba(22,30,42,.9); border: 1px solid var(--line); backdrop-filter: blur(10px);
  font-size: 18px;
}
.timeline { position: relative; margin-top: 8px; }
.timeline::before {
  content: ""; position: absolute; left: 10px; top: 6px; bottom: 6px; width: 2px;
  background: linear-gradient(var(--accent), transparent);
}
.tl-item { position: relative; padding: 0 0 18px 36px; }
.tl-item::before {
  content: ""; position: absolute; left: 4px; top: 6px; width: 14px; height: 14px;
  border-radius: 50%; background: var(--bg); border: 2px solid var(--accent);
}
.tl-time { color: var(--muted); font-family: var(--mono); font-size: 12px; }
.tl-title { font-weight: 600; margin-top: 2px; }
.tl-detail { color: var(--muted); font-size: 13px; margin-top: 4px; }
@media print {
  .deck { height: auto; overflow: visible; scroll-snap-type: none; }
  .slide { min-height: auto; page-break-after: always; padding: 36px; }
  .slide::after { inset: 0; }
  .nav { display: none; }
}
</style>
</head>
<body>
<div class="deck">
""");

        // Slide 1 — title
        sb.Append("""
<section class="slide" id="s1">
  <div class="inner">
    <div class="brand-row">
""");
        if (logo is not null)
            sb.Append($"      <img src=\"{logo}\" alt=\"iCloudKit Extractor\"/>\n");
        sb.Append("""
      <div>
        <div class="kicker">Forensic acquisition package</div>
        <div style="margin-top:6px;color:var(--muted);font-size:14px">iCloudKitExtractor · CloudKit Report</div>
      </div>
    </div>
    <h1>CloudKit Report</h1>
    <p class="lead">A presentation-ready summary of case metadata, acquisition areas, operation timeline, and integrity hashes — without session tokens or credentials.</p>
""");
        sb.Append($"""
    <div class="meta-grid">
      <div class="card"><div class="label">Case</div><div class="value">{E(m.Case.CaseId)}</div><div class="sub">{E(m.Case.CaseName)}</div></div>
      <div class="card"><div class="label">Examiner</div><div class="value">{E(m.Case.Examiner)}</div><div class="sub">{E(m.Case.Agency ?? "—")}</div></div>
      <div class="card"><div class="label">Generated (UTC)</div><div class="value">{m.GeneratedAt:yyyy-MM-dd}</div><div class="sub">{m.GeneratedAt:HH:mm:ss}Z · tool {E(m.ToolVersion)}</div></div>
    </div>
  </div>
</section>
""");

        // Slide 2 — case dossier
        sb.Append($"""
<section class="slide" id="s2">
  <div class="inner">
    <div class="kicker">01 · Case dossier</div>
    <h2>Identity &amp; package root</h2>
    <div class="meta-grid">
      <div class="card"><div class="label">Case ID</div><div class="value">{E(m.Case.CaseId)}</div></div>
      <div class="card"><div class="label">Case name</div><div class="value">{E(m.Case.CaseName)}</div></div>
      <div class="card"><div class="label">Examiner</div><div class="value">{E(m.Case.Examiner)}</div></div>
      <div class="card"><div class="label">Agency / lab</div><div class="value">{E(m.Case.Agency ?? "—")}</div></div>
      <div class="card"><div class="label">Created (UTC)</div><div class="value">{m.Case.CreatedAt:yyyy-MM-dd HH:mm:ss}Z</div></div>
      <div class="card"><div class="label">Updated (UTC)</div><div class="value">{m.Case.UpdatedAt:yyyy-MM-dd HH:mm:ss}Z</div></div>
    </div>
    <div class="card" style="margin-top:14px">
      <div class="label">Case root</div>
      <div class="value" style="font-size:15px;font-family:var(--mono)">{E(m.Case.RootPath)}</div>
      <div class="sub">case.json SHA-256: {E(m.CaseJsonSha256 ?? "n/a")}</div>
    </div>
""");
        if (!string.IsNullOrWhiteSpace(m.Case.Notes))
        {
            sb.Append($"""
    <div class="card" style="margin-top:14px">
      <div class="label">Notes</div>
      <div class="value" style="font-size:15px;font-weight:500;white-space:pre-wrap">{E(m.Case.Notes)}</div>
    </div>
""");
        }

        sb.Append("""
  </div>
</section>
""");

        // Slide 3 — timeline
        sb.Append($"""
<section class="slide" id="s3">
  <div class="inner">
    <div class="kicker">02 · Operations</div>
    <h2>Timeline</h2>
    <p class="lead">High-level actions recorded for this case. Secrets and tokens are redacted.</p>
    <div class="stat-row">
      <div class="stat"><span class="label">Events</span><b>{m.Operations.Count}</b></div>
      <div class="stat"><span class="label">First</span><b style="font-size:16px">{(m.Operations.Count == 0 ? "—" : m.Operations[0].Utc.ToString("yyyy-MM-dd HH:mm") + "Z")}</b></div>
      <div class="stat"><span class="label">Last</span><b style="font-size:16px">{(m.Operations.Count == 0 ? "—" : m.Operations[^1].Utc.ToString("yyyy-MM-dd HH:mm") + "Z")}</b></div>
    </div>
    <div class="timeline">
""");
        if (m.Operations.Count == 0)
        {
            sb.Append("""
      <div class="tl-item"><div class="tl-title">No operations recorded yet</div>
      <div class="tl-detail">Run acquisitions in this case, then regenerate the report.</div></div>
""");
        }
        else
        {
            foreach (var op in m.Operations.Take(40))
            {
                var pill = op.Status.Equals("ok", StringComparison.OrdinalIgnoreCase) ? "ok"
                    : op.Status.Equals("inferred", StringComparison.OrdinalIgnoreCase) ? "warn" : "";
                sb.Append($"""
      <div class="tl-item">
        <div class="tl-time">{op.Utc:yyyy-MM-dd HH:mm:ss}Z · <span class="pill {pill}">{E(op.Status)}</span></div>
        <div class="tl-title">{E(op.Area)} — {E(op.Action)}</div>
        <div class="tl-detail">{E(op.Detail ?? "")}</div>
      </div>
""");
            }

            if (m.Operations.Count > 40)
                sb.Append($"""
      <div class="tl-item"><div class="tl-detail">… and {m.Operations.Count - 40} more events in ops/operations.jsonl</div></div>
""");
        }

        sb.Append("""
    </div>
  </div>
</section>
""");

        // Slide 4 — inventory
        var activeAreas = m.Areas.Where(a => a.FileCount > 0).ToList();
        sb.Append($"""
<section class="slide" id="s4">
  <div class="inner">
    <div class="kicker">03 · Acquisition inventory</div>
    <h2>Package contents</h2>
    <div class="stat-row">
      <div class="stat"><span class="label">Areas with data</span><b>{activeAreas.Count}</b></div>
      <div class="stat"><span class="label">Total files</span><b>{m.Areas.Sum(a => a.FileCount):N0}</b></div>
      <div class="stat"><span class="label">Total size</span><b style="font-size:22px">{E(IkeCaseReportBuilder.FormatBytes(m.Areas.Sum(a => a.TotalBytes)))}</b></div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Area</th><th>Path</th><th>Files</th><th>Size</th><th>Newest (UTC)</th></tr></thead>
        <tbody>
""");
        foreach (var a in m.Areas)
        {
            sb.Append($"""
          <tr>
            <td>{E(a.Label)}</td>
            <td class="mono">{E(a.RelativePath)}</td>
            <td>{a.FileCount:N0}</td>
            <td>{E(IkeCaseReportBuilder.FormatBytes(a.TotalBytes))}</td>
            <td class="mono">{(a.NewestUtc is null ? "—" : a.NewestUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") + "Z")}</td>
          </tr>
""");
        }

        sb.Append("""
        </tbody>
      </table>
    </div>
  </div>
</section>
""");

        // Slide 5 — integrity
        sb.Append($"""
<section class="slide" id="s5">
  <div class="inner">
    <div class="kicker">04 · Integrity</div>
    <h2>Hash manifests</h2>
    <p class="lead">SHA-256 inventories written during acquisition (<span class="mono">HASHES.sha256</span> + <span class="mono">integrity.json</span>). The hash of each HASHES file is shown for package verification.</p>
    <div class="table-wrap" style="margin-top:18px">
      <table>
        <thead><tr><th>Manifest</th><th>Files</th><th>Bytes</th><th>Generated</th><th>HASHES.sha256 digest</th></tr></thead>
        <tbody>
""");
        if (m.IntegrityManifests.Count == 0)
        {
            sb.Append("""
          <tr><td colspan="5">No integrity.json found yet in this case package.</td></tr>
""");
        }
        else
        {
            foreach (var i in m.IntegrityManifests)
            {
                sb.Append($"""
          <tr>
            <td class="mono">{E(i.RelativePath)}</td>
            <td>{i.FileCount:N0}</td>
            <td>{E(IkeCaseReportBuilder.FormatBytes(i.TotalBytes))}</td>
            <td class="mono">{(i.GeneratedAt is null ? "—" : i.GeneratedAt.Value.ToString("yyyy-MM-dd HH:mm:ss") + "Z")}</td>
            <td class="mono">{E(i.HashesFileSha256 ?? "n/a")}</td>
          </tr>
""");
            }
        }

        sb.Append("""
        </tbody>
      </table>
    </div>
  </div>
</section>
""");

        // Slide 6 — closing
        sb.Append($"""
<section class="slide" id="s6">
  <div class="inner">
    <div class="kicker">05 · Closing</div>
    <h2>Scope &amp; limitations</h2>
    <p class="lead">This report summarises the local case package produced by iCloudKit Extractor. It is a lab acquisition aid, not a court-ready chain-of-custody certificate and not a digitally signed examiner attestation.</p>
    <div class="meta-grid">
      <div class="card"><div class="label">Included</div><div class="value" style="font-size:15px;font-weight:500">Case metadata · operation timeline · folder inventory · integrity digests</div></div>
      <div class="card"><div class="label">Excluded</div><div class="value" style="font-size:15px;font-weight:500">Apple ID passwords · PET / GS / session tokens · Recovery Keys · raw auth cookies</div></div>
    </div>
    <p class="footer-note">
      Header: <strong>iCloudKitExtractor — CloudKit Report</strong><br/>
      Generated {m.GeneratedAt:O} · Case {E(m.Case.CaseId)} · Examiner {E(m.Case.Examiner)}<br/>
      Verify file integrity against <span class="mono">HASHES.sha256</span> companions inside each acquisition subtree.
    </p>
  </div>
</section>
""");

        sb.Append("""
</div>
<nav class="nav" aria-label="Slides">
  <a href="#s1" title="Title">⌂</a>
  <a href="#s2" title="Case">1</a>
  <a href="#s3" title="Ops">2</a>
  <a href="#s4" title="Inventory">3</a>
  <a href="#s5" title="Hashes">4</a>
  <a href="#s6" title="Close">5</a>
</nav>
</body>
</html>
""");
        return sb.ToString();
    }

    private static string E(string? value) =>
        WebUtility.HtmlEncode(value ?? "");
}

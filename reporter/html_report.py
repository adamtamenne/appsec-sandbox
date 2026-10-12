"""HTML report generator — single self-contained file."""

from pathlib import Path

from jinja2 import Template

from normalizer.models import Finding, Severity

HTML_TEMPLATE = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AppSec Sandbox Report — {{ metadata.scan_id }}</title>
<style>
  :root { --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #e6edf3;
          --muted: #8b949e; --critical: #f85149; --high: #f0883e; --medium: #d29922;
          --low: #3fb950; --info: #58a6ff; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.5; padding: 2rem; }
  h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
  .meta { color: var(--muted); margin-bottom: 2rem; font-size: 0.875rem; }
  .summary { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .summary .card { background: var(--surface); border: 1px solid var(--border);
                   border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; }
  .summary .card .count { font-size: 1.75rem; font-weight: 700; }
  .summary .card .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; }
  .severity-critical .count { color: var(--critical); }
  .severity-high .count { color: var(--high); }
  .severity-medium .count { color: var(--medium); }
  .severity-low .count { color: var(--low); }
  .severity-info .count { color: var(--info); }
  table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
  th, td { text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }
  th { background: var(--surface); color: var(--muted); font-size: 0.75rem;
       text-transform: uppercase; position: sticky; top: 0; }
  tr:hover { background: var(--surface); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
           font-size: 0.75rem; font-weight: 600; }
  .badge-critical { background: var(--critical); color: #fff; }
  .badge-high { background: var(--high); color: #fff; }
  .badge-medium { background: var(--medium); color: #000; }
  .badge-low { background: var(--low); color: #000; }
  .badge-info { background: var(--info); color: #000; }
  .correlated { color: var(--info); font-size: 0.8rem; }
  .tools { display: flex; gap: 0.5rem; margin-top: 1.5rem; margin-bottom: 1rem; }
  .tool-badge { background: var(--surface); border: 1px solid var(--border);
                padding: 4px 12px; border-radius: 6px; font-size: 0.8rem; }
</style>
</head>
<body>
<h1>AppSec Sandbox Report</h1>
<div class="meta">
  Scan {{ metadata.scan_id }} &middot; {{ metadata.target }} &middot;
  {{ metadata.timestamp }} &middot; {{ metadata.duration_seconds }}s
</div>

<div class="tools">
  {% for tool in metadata.tools_run %}
  <span class="tool-badge">{{ tool }}</span>
  {% endfor %}
</div>

<div class="summary">
  <div class="card"><div class="count">{{ findings | length }}</div><div class="label">Total</div></div>
  {% for sev in severities %}
  <div class="card severity-{{ sev }}">
    <div class="count">{{ counts[sev] }}</div>
    <div class="label">{{ sev }}</div>
  </div>
  {% endfor %}
  <div class="card"><div class="count">{{ correlated_count }}</div><div class="label">Cross-tool</div></div>
</div>

<table>
<thead>
<tr><th>Severity</th><th>CWE</th><th>Title</th><th>Location</th><th>Tool</th><th>Correlated</th></tr>
</thead>
<tbody>
{% for f in findings %}
<tr>
  <td><span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span></td>
  <td>{{ f.cwe or '—' }}</td>
  <td>{{ f.title }}</td>
  <td><code>{{ f.location }}</code></td>
  <td>{{ f.tool }}</td>
  <td class="correlated">{{ f.correlated_tools | join(', ') }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</body>
</html>
""")


def generate_html(
    findings: list[Finding], metadata: dict, output_path: Path
) -> Path:
    """Render the self-contained HTML report."""
    severities = [s.value for s in Severity]
    counts = {s.value: sum(1 for f in findings if f.severity.value == s.value) for s in Severity}
    correlated_count = sum(1 for f in findings if f.correlated_tools)

    html = HTML_TEMPLATE.render(
        findings=findings,
        metadata=metadata,
        severities=severities,
        counts=counts,
        correlated_count=correlated_count,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    return output_path

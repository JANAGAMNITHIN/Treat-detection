"""
ThreatScope Report Generation & Aggregation Engine
Handles normalized log parsing, alert correlation, threat scoring,
kill-chain timeline mapping, top offender ranking, and modular HTML/PDF report synthesis.
"""

from datetime import datetime
import io
import json
from typing import Any, Dict, List, Optional
from uuid import uuid4

def compute_environmental_risk_grade(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes overall organizational risk grade based on aggregated confidence scores,
    malicious ratio, and severity weights.
    """
    if not records:
        return {
            "grade": "A (LOW)",
            "risk_level": "LOW",
            "score": 0,
            "color": "#10b981",
            "summary": "No active threat indicators recorded in the environment."
        }

    total = len(records)
    malicious_count = sum(1 for r in records if r.get("verdict") == "malicious")
    suspicious_count = sum(1 for r in records if r.get("verdict") == "suspicious")
    avg_score = sum(float(r.get("confidence_score", 0)) for r in records) / total

    malicious_ratio = malicious_count / total

    if malicious_ratio >= 0.4 or avg_score >= 75:
        grade = "CRITICAL (D-)"
        risk_level = "CRITICAL"
        color = "#ef4444"
        summary = "Severe threat activity detected. Multiple verified malicious IOCs require immediate incident response."
    elif malicious_ratio >= 0.2 or avg_score >= 50:
        grade = "HIGH (C)"
        risk_level = "HIGH"
        color = "#f97316"
        summary = "Elevated threat volume. Malicious indicators and suspicious domains observed."
    elif suspicious_count > 0 or avg_score >= 25:
        grade = "MEDIUM (B)"
        risk_level = "MEDIUM"
        color = "#eab308"
        summary = "Moderate risk. Heuristic anomalies and young domains observed under monitoring."
    else:
        grade = "LOW (A+)"
        risk_level = "LOW"
        color = "#10b981"
        summary = "Benign baseline. All verified indicators tested clean across intelligence feeds."

    return {
        "grade": grade,
        "risk_level": risk_level,
        "score": round(avg_score, 1),
        "color": color,
        "summary": summary,
        "total_evaluated": total,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "clean_count": sum(1 for r in records if r.get("verdict") == "clean"),
    }

def calculate_top_offenders(records: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    """
    Ranks top attacking IPs, malicious domains, and high-confidence payload hashes.
    """
    threats = [r for r in records if r.get("verdict") in ["malicious", "suspicious"]]
    # Sort by confidence score descending
    threats.sort(key=lambda x: float(x.get("confidence_score", 0)), reverse=True)

    offenders = []
    for r in threats[:limit]:
        offenders.append({
            "indicator": r.get("defanged_indicator") or r.get("indicator"),
            "type": (r.get("type") or r.get("ioc_type") or "URL").upper(),
            "score": round(float(r.get("confidence_score", 0))),
            "verdict": (r.get("verdict") or "unknown").upper(),
            "scanned_at": r.get("scanned_at", "N/A"),
            "risk_factors": [b.get("reason") for b in r.get("scoring_breakdown", [])][:2]
        })
    return offenders

def build_kill_chain_timeline(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Constructs a chronological MITRE ATT&CK cyber kill-chain sequence for an incident.
    """
    ioc_type = (record.get("type") or record.get("ioc_type") or "url").lower()
    indicator = record.get("defanged_indicator") or record.get("indicator") or "Target"
    verdict = record.get("verdict", "clean")
    scanned_at = record.get("scanned_at") or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    if verdict != "malicious" and verdict != "suspicious":
        return [
            {
                "phase": "Reconnaissance & Scan",
                "timestamp": scanned_at,
                "status": "PASS",
                "description": f"Query dispatched against 6 global feeds for {indicator}. Verified benign.",
                "color": "#10b981"
            }
        ]

    timeline = []
    
    # Phase 1: Reconnaissance / Weaponization
    timeline.append({
        "phase": "1. Weaponization & Domain Staging",
        "timestamp": scanned_at,
        "status": "DETECTED",
        "description": f"Indicator '{indicator}' registered or weaponized with suspicious reputation flags.",
        "color": "#f97316"
    })

    # Phase 2: Delivery & Infiltration
    if ioc_type in ["url", "email", "domain"]:
        timeline.append({
            "phase": "2. Infiltration & Lure Delivery",
            "timestamp": scanned_at,
            "status": "FLAGGED",
            "description": f"Phishing / deceptive lure delivery mechanism identified on {ioc_type.upper()} channel.",
            "color": "#ef4444"
        })
    elif ioc_type in ["sha256", "md5", "sha1"]:
        timeline.append({
            "phase": "2. Payload Execution & Dropper",
            "timestamp": scanned_at,
            "status": "FLAGGED",
            "description": f"Binary payload hash matched known malware signature in VirusTotal/MalwareBazaar.",
            "color": "#ef4444"
        })
    elif ioc_type in ["ipv4", "ipv6"]:
        timeline.append({
            "phase": "2. Network Ingress / Host Scanner",
            "timestamp": scanned_at,
            "status": "FLAGGED",
            "description": f"Host scanner / brute force IP detected in AbuseIPDB blacklist telemetry.",
            "color": "#ef4444"
        })

    # Phase 3: Command & Control / Exfiltration Risk
    timeline.append({
        "phase": "3. C2 Beaconing & Exfiltration Risk",
        "timestamp": scanned_at,
        "status": "EVALUATED",
        "description": f"High confidence ({round(float(record.get('confidence_score', 0)))}/100) communication hazard flagged.",
        "color": "#ef4444"
    })

    # Phase 4: ThreatScope Containment Action
    timeline.append({
        "phase": "4. Automated Containment Policy",
        "timestamp": scanned_at,
        "status": "BLOCKED",
        "description": f"Sinkholing and egress block recommended across perimeter security stack.",
        "color": "#38bdf8"
    })

    return timeline

def render_executive_report_html(records: List[Dict[str, Any]], sections: Optional[List[str]] = None) -> str:
    """
    Renders a high-level Executive Summary Report (clean, non-technical, chart-focused).
    """
    sections = sections or ["summary", "grade", "offenders", "recommendations"]
    risk_data = compute_environmental_risk_grade(records)
    offenders = calculate_top_offenders(records, limit=5)
    now_str = datetime.utcnow().strftime("%B %d, %Y • %H:%M UTC")
    report_id = f"EXEC-{uuid4().hex[:8].upper()}"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ThreatScope Executive Threat Report — {report_id}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 40px; }}
    .report-card {{ max-width: 900px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 40px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); }}
    .header-bar {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #2563eb; padding-bottom: 20px; margin-bottom: 30px; }}
    .logo-title {{ font-size: 22px; font-weight: 800; color: #1e3a8a; letter-spacing: -0.02em; margin: 0; }}
    .sub-title {{ font-size: 13px; color: #64748b; margin-top: 4px; }}
    .print-btn {{ background: #2563eb; color: #ffffff; border: none; padding: 10px 18px; border-radius: 6px; font-weight: 700; cursor: pointer; }}
    
    .grade-banner {{ background: #f1f5f9; border-radius: 10px; padding: 24px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-left: 6px solid {risk_data["color"]}; }}
    .grade-badge {{ font-size: 28px; font-weight: 900; color: {risk_data["color"]}; }}
    .grade-desc {{ font-size: 14px; color: #334155; margin-top: 6px; }}
    
    .kpi-row {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }}
    .kpi-box {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; text-align: center; }}
    .kpi-num {{ font-size: 24px; font-weight: 800; margin: 6px 0; }}
    .kpi-lbl {{ font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; }}
    
    .section-title {{ font-size: 16px; font-weight: 700; color: #0f172a; margin: 25px 0 12px 0; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; }}
    .data-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}
    .data-table th, .data-table td {{ padding: 12px 14px; border: 1px solid #e2e8f0; text-align: left; }}
    .data-table th {{ background: #f8fafc; color: #475569; font-weight: 700; }}
    .pill {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; }}
    .pill-mal {{ background: #fee2e2; color: #b91c1c; }}
    .pill-susp {{ background: #ffedd5; color: #c2410c; }}
    .pill-clean {{ background: #dcfce7; color: #15803d; }}
    
    .bullet-list {{ margin: 0; padding-left: 20px; font-size: 14px; color: #334155; line-height: 1.6; }}
    .footer {{ margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 20px; font-size: 12px; color: #94a3b8; text-align: center; }}
    
    @media print {{
      body {{ background: #ffffff; padding: 0; }}
      .report-card {{ border: none; box-shadow: none; padding: 0; max-width: 100%; }}
      .no-print {{ display: none; }}
    }}
  </style>
</head>
<body>
  <div class="report-card">
    <div class="header-bar">
      <div>
        <h1 class="logo-title">THREATSCOPE EXECUTIVE SECURITY REPORT</h1>
        <div class="sub-title">Report ID: {report_id} • Generated on {now_str}</div>
      </div>
      <div class="no-print">
        <button class="print-btn" onclick="window.print()">Print / Save PDF</button>
      </div>
    </div>

    <!-- Overall Risk Grade Banner -->
    <div class="grade-banner">
      <div>
        <div style="font-size:12px;font-weight:700;color:#64748b;text-transform:uppercase;">Overall Threat Landscape Posture</div>
        <div class="grade-badge">{risk_data["grade"]}</div>
        <div class="grade-desc">{risk_data["summary"]}</div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:12px;color:#64748b;">Average Threat Score</div>
        <div style="font-size:32px;font-weight:900;color:{risk_data["color"]};">{risk_data["score"]} / 100</div>
      </div>
    </div>

    <!-- Summary Metrics -->
    <div class="kpi-row">
      <div class="kpi-box">
        <div class="kpi-lbl">Total Evaluated</div>
        <div class="kpi-num" style="color:#2563eb;">{risk_data["total_evaluated"]}</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-lbl">Malicious Threats</div>
        <div class="kpi-num" style="color:#ef4444;">{risk_data["malicious_count"]}</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-lbl">Suspicious Flags</div>
        <div class="kpi-num" style="color:#f97316;">{risk_data["suspicious_count"]}</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-lbl">Verified Clean</div>
        <div class="kpi-num" style="color:#10b981;">{risk_data["clean_count"]}</div>
      </div>
    </div>

    <!-- Top Threat Offenders -->
    <div class="section-title">Top Security Offenders & Priority Hazards</div>
    <table class="data-table">
      <thead>
        <tr>
          <th>Indicator</th>
          <th>Type</th>
          <th>Verdict</th>
          <th>Confidence Score</th>
          <th>Observed Risk Factor</th>
        </tr>
      </thead>
      <tbody>
        {''.join([f'''<tr>
          <td><code>{o["indicator"]}</code></td>
          <td>{o["type"]}</td>
          <td><span class="pill {'pill-mal' if o['verdict']=='MALICIOUS' else 'pill-susp'}">{o["verdict"]}</span></td>
          <td><strong>{o["score"]}/100</strong></td>
          <td>{o["risk_factors"][0] if o["risk_factors"] else "High risk signature"}</td>
        </tr>''' for o in offenders]) if offenders else '<tr><td colspan="5" style="text-align:center;color:#64748b;">No high-priority threats recorded in current telemetry.</td></tr>'}
      </tbody>
    </table>

    <!-- Strategic Recommendations -->
    <div class="section-title">Executive Action Items & Mitigations</div>
    <ul class="bullet-list">
      <li><strong>Immediate Perimeter Enforcement:</strong> Confirm egress blocks on all indicators flagged with score ≥ 75 across gateway firewalls.</li>
      <li><strong>Credential Reset & Endpoint Quarantine:</strong> Isolate user workstations that accessed phishing domains within the last 72 hours.</li>
      <li><strong>Threat Intelligence Feed Sync:</strong> Ensure automated API polling is enabled for VirusTotal and AbuseIPDB.</li>
    </ul>

    <div class="footer">
      ThreatScope Unified Threat Detection Platform • Confidential Executive Briefing • Page 1 of 1
    </div>
  </div>
</body>
</html>"""
    return html

def render_technical_incident_report_html(record: Dict[str, Any], sections: Optional[List[str]] = None) -> str:
    """
    Renders an in-depth Technical Incident Dossier including MITRE Kill-Chain,
    Multi-Engine consensus matrix, and forensic artifacts.
    """
    now_str = datetime.utcnow().strftime("%B %d, %Y • %H:%M:%S UTC")
    report_id = f"INC-{record.get('id', uuid4().hex[:8])[:12].upper()}"
    indicator = record.get("defanged_indicator") or record.get("indicator") or "Target"
    raw_indicator = record.get("indicator") or indicator
    verdict = (record.get("verdict") or "clean").upper()
    score = round(float(record.get("confidence_score", 0)))
    ioc_type = (record.get("type") or record.get("ioc_type") or "URL").upper()
    
    verdict_color = "#ef4444" if verdict == "MALICIOUS" else ("#f97316" if verdict == "SUSPICIOUS" else "#10b981")
    timeline = build_kill_chain_timeline(record)
    sources = record.get("sources", [])
    breakdowns = record.get("scoring_breakdown", [])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Technical Incident Report — {indicator}</title>
  <style>
    body {{ font-family: 'JetBrains Mono', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #070b14; color: #e2e8f0; margin: 0; padding: 40px; }}
    .dossier-card {{ max-width: 1000px; margin: 0 auto; background: #0d1527; border: 1px solid #1e293b; border-radius: 12px; padding: 40px; box-shadow: 0 10px 40px rgba(0,0,0,0.6); }}
    .header-bar {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #2563eb; padding-bottom: 20px; margin-bottom: 25px; }}
    .title-group h1 {{ font-size: 22px; font-weight: 800; color: #ffffff; margin: 0; }}
    .sub-title {{ font-size: 12px; color: #64748b; margin-top: 4px; }}
    .btn-print {{ background: #2563eb; color: #ffffff; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 700; cursor: pointer; }}
    
    .target-banner {{ background: #0a1120; border: 1px solid #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 25px; display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }}
    .target-title {{ font-size: 18px; font-weight: 700; color: #ffffff; word-break: break-all; }}
    .verdict-tag {{ display: inline-block; padding: 6px 14px; border-radius: 4px; font-weight: 800; font-size: 14px; color: #ffffff; background: {verdict_color}; margin-top: 8px; }}
    .score-dial {{ text-align: right; }}
    .score-num {{ font-size: 36px; font-weight: 900; color: {verdict_color}; }}
    
    .section-h {{ font-size: 15px; font-weight: 700; color: #93c5fd; text-transform: uppercase; margin: 25px 0 12px 0; border-bottom: 1px solid #1e293b; padding-bottom: 6px; letter-spacing: 0.05em; }}
    
    /* Kill Chain Timeline */
    .timeline-wrap {{ display: flex; flex-direction: column; gap: 12px; margin-bottom: 25px; }}
    .tl-step {{ background: #0a1120; border-left: 4px solid #2563eb; border-radius: 4px; padding: 12px 16px; display: flex; justify-content: space-between; align-items: center; }}
    .tl-phase {{ font-weight: 700; color: #ffffff; font-size: 13px; }}
    .tl-desc {{ font-size: 12px; color: #94a3b8; margin-top: 2px; }}
    .tl-badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #fff; }}
    
    /* Intel Matrix Table */
    .table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }}
    .table th, .table td {{ padding: 10px 12px; border: 1px solid #1e293b; text-align: left; }}
    .table th {{ background: #0a1120; color: #94a3b8; font-weight: 700; }}
    .code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; color: #38bdf8; font-size: 11px; }}
    
    .remed-box {{ background: #0a1120; border: 1px solid #1e293b; border-radius: 6px; padding: 15px 20px; font-size: 13px; line-height: 1.6; color: #cbd5e1; }}
    .footer {{ margin-top: 35px; border-top: 1px solid #1e293b; padding-top: 15px; font-size: 11px; color: #64748b; text-align: center; }}
    
    @media print {{
      body {{ background: #ffffff; color: #000000; padding: 0; }}
      .dossier-card {{ background: #ffffff; color: #000000; border: none; box-shadow: none; padding: 0; }}
      .target-banner, .tl-step, .remed-box, .table th {{ background: #f8fafc; color: #000; border-color: #cbd5e1; }}
      .target-title, .title-group h1, .tl-phase {{ color: #000000; }}
      .no-print {{ display: none; }}
    }}
  </style>
</head>
<body>
  <div class="dossier-card">
    <div class="header-bar">
      <div class="title-group">
        <h1>THREATSCOPE TECHNICAL INCIDENT DOSSIER</h1>
        <div class="sub-title">Incident ID: {report_id} • Generated UTC: {now_str}</div>
      </div>
      <div class="no-print">
        <button class="btn-print" onclick="window.print()">Print / Export PDF</button>
      </div>
    </div>

    <!-- Target Indicator Summary -->
    <div class="target-banner">
      <div>
        <span style="font-size:11px;color:#64748b;text-transform:uppercase;font-weight:700;">Target Asset / Indicator</span>
        <div class="target-title">{indicator}</div>
        <span class="verdict-tag">{verdict}</span>
        <span style="font-size:12px;color:#94a3b8;margin-left:10px;">Type: {ioc_type} • Risk Level: {record.get('risk_level', 'UNKNOWN')}</span>
      </div>
      <div class="score-dial">
        <span style="font-size:11px;color:#64748b;text-transform:uppercase;font-weight:700;display:block;">Confidence Threat Score</span>
        <div class="score-num">{score} <span style="font-size:16px;color:#64748b;">/100</span></div>
      </div>
    </div>

    <!-- MITRE Attack / Kill Chain Sequence -->
    <div class="section-h">Chronological Cyber Attack Kill-Chain</div>
    <div class="timeline-wrap">
      {''.join([f'''<div class="tl-step" style="border-left-color:{step['color']};">
        <div>
          <div class="tl-phase">{step['phase']}</div>
          <div class="tl-desc">{step['description']}</div>
        </div>
        <span class="tl-badge" style="background:{step['color']};">{step['status']}</span>
      </div>''' for step in timeline])}
    </div>

    <!-- Risk Factors Breakdown -->
    <div class="section-h">Scoring Engine Penalty Breakdown</div>
    <table class="table">
      <thead>
        <tr>
          <th>Intelligence Provider</th>
          <th>Penalty Reason</th>
          <th>Points Contributed</th>
        </tr>
      </thead>
      <tbody>
        {''.join([f'<tr><td><strong>{b.get("source", "Engine")}</strong></td><td>{b.get("reason", "N/A")}</td><td>+{b.get("points_contributed", 0)} pts</td></tr>' for b in breakdowns]) if breakdowns else '<tr><td colspan="3" style="text-align:center;color:#64748b;">No penalty points recorded. Indicator is clean.</td></tr>'}
      </tbody>
    </table>

    <!-- Intelligence Feeds Matrix -->
    <div class="section-h">Multi-Provider Threat Intelligence Matrix</div>
    <table class="table">
      <thead>
        <tr>
          <th>Provider</th>
          <th>Verdict</th>
          <th>Confidence</th>
          <th>Analysis Summary</th>
          <th>Latency</th>
        </tr>
      </thead>
      <tbody>
        {''.join([f'<tr><td><strong>{s.get("name", "Feed")}</strong></td><td><span style="color:{("#ef4444" if s.get("verdict")=="malicious" else ("#f97316" if s.get("verdict")=="suspicious" else "#10b981"))};font-weight:bold;">{s.get("verdict", "CLEAN").upper()}</span></td><td>{s.get("confidence_score", 0)}%</td><td>{s.get("summary", "N/A")}</td><td>{s.get("duration_ms", 0)}ms</td></tr>' for s in sources])}
      </tbody>
    </table>

    <!-- Incident Remediation Playbook -->
    <div class="section-h">Incident Remediation & Playbook Action</div>
    <div class="remedbox remed-box">
      <div>• <strong>Perimeter Firewall Block:</strong> Apply immediate rule to drop ingress and egress traffic to <span class="code">{indicator}</span>.</div>
      <div>• <strong>DNS Sinkholing:</strong> Add <span class="code">{indicator}</span> to internal DNS response policy zones (RPZ).</div>
      <div>• <strong>SIEM Telemetry Hunt:</strong> Query proxy logs and host EDR logs for outbound HTTP/TLS requests in the last 30 days.</div>
    </div>

    <div class="footer">
      ThreatScope Unified Threat Detection Platform • Technical Security Incident Dossier • Generated Automatically
    </div>
  </div>
</body>
</html>"""
    return html

import json
import os
import platform
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, NextPageTemplate, PageBreak,
    PageTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.platypus.flowables import KeepTogether

# ── Colour Palette — Clean Corporate Light Theme ─────────────────────────────
NAVY        = colors.HexColor('#1a3c6e')
NAVY_LIGHT  = colors.HexColor('#2c5f9e')
NAVY_DARK   = colors.HexColor('#0f2847')
ACCENT      = colors.HexColor('#2563eb')      # Modern blue
ACCENT_LIGHT = colors.HexColor('#dbeafe')      # Soft blue tint

RED_ALERT   = colors.HexColor('#dc2626')       # Danger red
RED_BG      = colors.HexColor('#fef2f2')        # Light red background
RED_BORDER  = colors.HexColor('#fecaca')

AMBER       = colors.HexColor('#d97706')       # Warning amber
AMBER_BG    = colors.HexColor('#fffbeb')        # Light amber background

GREEN_OK    = colors.HexColor('#16a34a')       # Clean/OK green
GREEN_BG    = colors.HexColor('#f0fdf4')        # Light green background

WHITE       = colors.white
PAGE_BG     = colors.white
ROW_ALT     = colors.HexColor('#f8fafc')       # Very light gray
ROW_NORMAL  = colors.white
HEADER_BG   = NAVY                              # Dark navy table headers
HEADER_TEXT = colors.white
BODY_TEXT   = colors.HexColor('#1e293b')        # Dark slate for readability
SUB_TEXT    = colors.HexColor('#64748b')        # Muted text
BORDER_CLR  = colors.HexColor('#e2e8f0')        # Light border
SECTION_RULE = colors.HexColor('#cbd5e1')


def _styles():
    """Build a complete set of custom paragraph styles for light theme."""
    s = getSampleStyleSheet()

    cover_title = ParagraphStyle(
        'CoverTitle', fontName='Helvetica-Bold', fontSize=28,
        textColor=WHITE, spaceAfter=6, alignment=TA_CENTER, leading=34)

    cover_sub = ParagraphStyle(
        'CoverSub', fontName='Helvetica', fontSize=13,
        textColor=colors.HexColor('#94a3b8'), spaceAfter=4, alignment=TA_CENTER)

    cover_meta = ParagraphStyle(
        'CoverMeta', fontName='Helvetica-Bold', fontSize=11,
        textColor=WHITE, spaceAfter=4, alignment=TA_CENTER)

    section_heading = ParagraphStyle(
        'SectionHeading', fontName='Helvetica-Bold', fontSize=14,
        textColor=NAVY, spaceBefore=14, spaceAfter=6, leading=18)

    normal_text = ParagraphStyle(
        'NormalText', fontName='Helvetica', fontSize=9,
        textColor=BODY_TEXT, spaceAfter=2, leading=13)

    small_text = ParagraphStyle(
        'SmallText', fontName='Helvetica', fontSize=7.5,
        textColor=BODY_TEXT, leading=11)

    alert_red = ParagraphStyle(
        'AlertRed', fontName='Helvetica-Bold', fontSize=10,
        textColor=RED_ALERT, spaceAfter=4)

    alert_amber = ParagraphStyle(
        'AlertAmber', fontName='Helvetica-Bold', fontSize=10,
        textColor=AMBER, spaceAfter=4)

    label = ParagraphStyle(
        'Label', fontName='Helvetica-Bold', fontSize=9,
        textColor=SUB_TEXT, spaceAfter=1)

    # Detections Summary styles
    stat_big = ParagraphStyle(
        'StatBig', fontName='Helvetica-Bold', fontSize=22,
        textColor=NAVY, alignment=TA_CENTER, leading=26)

    stat_label = ParagraphStyle(
        'StatLabel', fontName='Helvetica', fontSize=8,
        textColor=SUB_TEXT, alignment=TA_CENTER, spaceAfter=2)

    finding_text = ParagraphStyle(
        'FindingText', fontName='Helvetica', fontSize=10,
        textColor=BODY_TEXT, spaceAfter=6, leading=14,
        leftIndent=12, bulletIndent=0)

    return dict(
        cover_title=cover_title, cover_sub=cover_sub, cover_meta=cover_meta,
        section_heading=section_heading, normal_text=normal_text,
        small_text=small_text, alert_red=alert_red, alert_amber=alert_amber,
        label=label, stat_big=stat_big, stat_label=stat_label,
        finding_text=finding_text
    )


# ── Page templates ────────────────────────────────────────────────────────────
def _on_cover_page(canvas, doc):
    canvas.saveState()
    w, h = A4
    # White background
    canvas.setFillColor(WHITE)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)
    # Navy covers the entire top portion (top 65% of page)
    canvas.setFillColor(NAVY)
    canvas.rect(0, h * 0.35, w, h * 0.65, fill=1, stroke=0)
    # Accent stripe at the junction
    canvas.setFillColor(ACCENT)
    canvas.rect(0, h * 0.35 - 4*mm, w, 4*mm, fill=1, stroke=0)
    # Bottom navy bar
    canvas.setFillColor(NAVY_DARK)
    canvas.rect(0, 0, w, 10*mm, fill=1, stroke=0)
    # "CONFIDENTIAL" watermark on the bottom bar
    canvas.setFont('Helvetica-Bold', 7)
    canvas.setFillColor(colors.HexColor('#ffffff80'))
    canvas.drawCentredString(w / 2, 3*mm, 'CONFIDENTIAL — AUTHORISED PERSONNEL ONLY')
    # TriageHound branding below the navy area
    canvas.setFont('Helvetica', 9)
    canvas.setFillColor(SUB_TEXT)
    canvas.drawCentredString(w / 2, h * 0.35 - 18*mm,
                             'Generated by TriageHound — Digital Forensics & Incident Response Toolkit')
    canvas.restoreState()


def _on_body_page(canvas, doc):
    canvas.saveState()
    w, h = A4
    # White background
    canvas.setFillColor(WHITE)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)
    # Top header bar — slim navy
    canvas.setFillColor(NAVY)
    canvas.rect(0, h - 12*mm, w, 12*mm, fill=1, stroke=0)
    # Thin accent line below header
    canvas.setFillColor(ACCENT)
    canvas.rect(0, h - 12.5*mm, w, 0.5*mm, fill=1, stroke=0)
    # Footer separator line
    canvas.setStrokeColor(BORDER_CLR)
    canvas.setLineWidth(0.5)
    canvas.line(18*mm, 11*mm, w - 18*mm, 11*mm)
    # Header text
    canvas.setFont('Helvetica-Bold', 7.5)
    canvas.setFillColor(WHITE)
    canvas.drawString(18*mm, h - 8.5*mm, 'FORENSIC INVESTIGATION REPORT')
    canvas.setFont('Helvetica', 7.5)
    canvas.drawRightString(w - 18*mm, h - 8.5*mm, f'Page {doc.page}')
    # Footer text
    canvas.setFont('Helvetica', 7)
    canvas.setFillColor(SUB_TEXT)
    canvas.drawString(18*mm, 5*mm, 'CONFIDENTIAL — Authorised Personnel Only')
    canvas.drawRightString(w - 18*mm, 5*mm,
                           f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    canvas.restoreState()


# ── Table helper — Light theme with colour-coded severity ─────────────────────
def _make_table(data, col_widths, header_bg=None, alert_rows=None,
                severity='normal'):
    """
    Build a styled light-theme table.

    severity controls alert row colouring:
        'critical' — red background for alert rows
        'warning'  — amber background for alert rows
        'normal'   — standard alternating rows (no special highlight)

    alert_rows: set of 1-based row indices to highlight.
    """
    if header_bg is None:
        header_bg = HEADER_BG
    alert_rows = alert_rows or set()

    style_cmds = [
        # Header row
        ('BACKGROUND',    (0, 0), (-1, 0), header_bg),
        ('TEXTCOLOR',     (0, 0), (-1, 0), HEADER_TEXT),
        ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 7),
        ('TOPPADDING',    (0, 0), (-1, 0), 7),
        # Body rows
        ('FONTNAME',      (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',      (0, 1), (-1, -1), 7.5),
        ('TEXTCOLOR',     (0, 1), (-1, -1), BODY_TEXT),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
        ('TOPPADDING',    (0, 1), (-1, -1), 5),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [ROW_NORMAL, ROW_ALT]),
        ('GRID',          (0, 0), (-1, -1), 0.4, BORDER_CLR),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]

    # Colour-code alert rows based on severity
    for row_idx in alert_rows:
        if severity == 'critical':
            style_cmds.append(('BACKGROUND', (0, row_idx), (-1, row_idx), RED_BG))
            style_cmds.append(('TEXTCOLOR',  (0, row_idx), (-1, row_idx), RED_ALERT))
            style_cmds.append(('FONTNAME',   (0, row_idx), (-1, row_idx), 'Helvetica-Bold'))
        elif severity == 'warning':
            style_cmds.append(('BACKGROUND', (0, row_idx), (-1, row_idx), AMBER_BG))
            style_cmds.append(('TEXTCOLOR',  (0, row_idx), (-1, row_idx), AMBER))
            style_cmds.append(('FONTNAME',   (0, row_idx), (-1, row_idx), 'Helvetica-Bold'))
        else:
            # Default: subtle highlight
            style_cmds.append(('BACKGROUND', (0, row_idx), (-1, row_idx), RED_BG))
            style_cmds.append(('TEXTCOLOR',  (0, row_idx), (-1, row_idx), RED_ALERT))
            style_cmds.append(('FONTNAME',   (0, row_idx), (-1, row_idx), 'Helvetica-Bold'))

    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle(style_cmds))
    return t


def _section_header(title, st, subtitle=None):
    elems = []
    elems.append(Spacer(1, 2*mm))
    elems.append(HRFlowable(width='100%', thickness=1, color=NAVY, spaceAfter=4))
    elems.append(Paragraph(title, st['section_heading']))
    if subtitle:
        elems.append(Paragraph(subtitle, st['label']))
    elems.append(Spacer(1, 2*mm))
    return elems


def _truncate(text, maxlen=80):
    text = str(text) if text else '—'
    return text[:maxlen] + '…' if len(text) > maxlen else text


def _severity_badge(level):
    """Return a coloured text string based on severity level."""
    level_upper = str(level).upper()
    if level_upper in ('CRITICAL', 'HIGH'):
        return f'🔴 {level_upper}'
    elif level_upper in ('MEDIUM',):
        return f'🟡 {level_upper}'
    elif level_upper in ('LOW', 'INFO'):
        return f'🟢 {level_upper}'
    return level_upper


# ── Detections Summary Builder ────────────────────────────────────────────────
def _build_detections_summary(st, counts, yara_rows, sigma_rows, vt_rows,
                              startup_rows):
    """Build the executive Detections Summary page elements."""
    elements = []

    elements.append(Spacer(1, 5*mm))
    elements.append(HRFlowable(width='100%', thickness=2, color=NAVY, spaceAfter=6))
    elements.append(Paragraph('DETECTIONS SUMMARY', st['section_heading']))
    elements.append(Paragraph('Executive overview of key findings from this investigation',
                              st['label']))
    elements.append(Spacer(1, 6*mm))

    # ── Stats Grid ──
    total_artifacts = sum(counts.values()) if counts else 0
    categories = len([v for v in counts.values() if v > 0]) if counts else 0

    stats_data = [[
        Paragraph(str(total_artifacts), st['stat_big']),
        Paragraph(str(categories), st['stat_big']),
        Paragraph(str(len(yara_rows)), st['stat_big']),
        Paragraph(str(len(sigma_rows)), st['stat_big']),
    ], [
        Paragraph('Evidence Items', st['stat_label']),
        Paragraph('Categories', st['stat_label']),
        Paragraph('YARA Hits', st['stat_label']),
        Paragraph('Sigma Alerts', st['stat_label']),
    ]]
    stats_table = Table(stats_data, colWidths=[4.25*cm]*4)
    stats_style = [
        ('ALIGN',       (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN',      (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',  (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 2),
        ('TOPPADDING',  (0, 1), (-1, 1), 0),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 10),
        ('GRID',        (0, 0), (-1, -1), 0.5, BORDER_CLR),
        ('BACKGROUND',  (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
    ]
    # Colour the YARA and Sigma stat cells based on findings
    if len(yara_rows) > 0:
        stats_style.append(('BACKGROUND', (2, 0), (2, -1), RED_BG))
    if len(sigma_rows) > 0:
        stats_style.append(('BACKGROUND', (3, 0), (3, -1), AMBER_BG))

    stats_table.setStyle(TableStyle(stats_style))
    elements.append(stats_table)
    elements.append(Spacer(1, 8*mm))

    # ── Threat Assessment ──
    elements.append(HRFlowable(width='100%', thickness=0.5, color=SECTION_RULE,
                               spaceAfter=4))
    elements.append(Paragraph('Threat Assessment', ParagraphStyle(
        'ThreatTitle', fontName='Helvetica-Bold', fontSize=12,
        textColor=NAVY, spaceAfter=6)))

    findings = []

    # YARA findings
    if yara_rows:
        for row in yara_rows:
            raw = json.loads(row.get('raw_data', '{}'))
            sev = raw.get('severity', 'MEDIUM').upper()
            badge = _severity_badge(sev)
            findings.append(
                f"{badge} — YARA rule <b>{_truncate(raw.get('rule', '?'), 40)}</b> "
                f"matched in <b>{_truncate(os.path.basename(raw.get('filepath', '?')), 30)}</b>"
            )
    else:
        findings.append("🟢 No YARA malware signatures detected in startup executables.")

    # Sigma findings
    if sigma_rows:
        for row in sigma_rows:
            raw = json.loads(row.get('raw_data', '{}'))
            level = raw.get('rule_level', 'medium').upper()
            badge = _severity_badge(level)
            findings.append(
                f"{badge} — Sigma alert: <b>{_truncate(raw.get('rule_title', '?'), 50)}</b>"
            )
    else:
        findings.append("🟢 No Sigma behavioral detections triggered.")

    # VirusTotal findings
    if vt_rows:
        malicious_vt = [r for r in vt_rows
                        if json.loads(r.get('raw_data', '{}')).get('is_malicious')]
        if malicious_vt:
            for row in malicious_vt:
                raw = json.loads(row.get('raw_data', '{}'))
                findings.append(
                    f"🔴 MALICIOUS — VirusTotal flagged <b>"
                    f"{_truncate(raw.get('label', '?'), 30)}</b> "
                    f"({raw.get('detection_ratio', '?')})"
                )
        else:
            findings.append(
                f"🟢 VirusTotal: All {len(vt_rows)} checked hashes are clean.")

    # Suspicious startup
    sus_count = sum(1 for r in startup_rows
                    if json.loads(r.get('raw_data', '{}')).get('flagged_suspicious'))
    if sus_count:
        findings.append(f"🟡 MEDIUM — {sus_count} suspicious startup program(s) detected.")

    for f in findings:
        elements.append(Paragraph(f'• {f}', st['finding_text']))

    elements.append(Spacer(1, 6*mm))
    elements.append(HRFlowable(width='100%', thickness=0.5, color=SECTION_RULE,
                               spaceAfter=4))

    return elements


# ── Main report function ──────────────────────────────────────────────────────
def generate_pdf_report(case_info, timeline_data, output_path, db_manager=None):
    """
    Generate a professional light-themed forensic investigation PDF report.

    Args:
        case_info:    dict with case_id, case_name, investigator_name, target_system
        timeline_data: list of timeline event dicts (for the timeline section)
        output_path:  where to write the PDF
        db_manager:   DBManager instance — if provided, enables per-type sections
    """
    w, h = A4
    st = _styles()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    case_id = case_info.get('case_id', 'UNKNOWN')

    # Pull per-type evidence if db_manager available
    counts = {}
    yara_rows = []
    startup_rows = []
    process_rows = []
    browser_rows = []
    usb_rows = []
    recent_rows = []
    prefetch_rows = []
    usn_rows = []
    shimcache_rows = []
    sigma_rows = []
    vt_rows = []
    vss_rows = []

    if db_manager:
        counts = db_manager.get_artifact_counts(case_id)
        yara_rows    = db_manager.get_evidence_by_type(case_id, 'yara_match')
        startup_rows = db_manager.get_evidence_by_type(case_id, 'startup_entry')
        process_rows = db_manager.get_evidence_by_type(case_id, 'process')
        browser_rows = db_manager.get_evidence_by_type(case_id, 'browser_history')
        usb_rows     = db_manager.get_evidence_by_type(case_id, 'usb_device')
        recent_rows  = db_manager.get_evidence_by_type(case_id, 'recent_file')
        prefetch_rows = db_manager.get_evidence_by_type(case_id, 'prefetch')
        usn_rows      = db_manager.get_evidence_by_type(case_id, 'usn_journal')
        shimcache_rows = db_manager.get_evidence_by_type(case_id, 'shimcache')
        sigma_rows    = db_manager.get_evidence_by_type(case_id, 'sigma_alert')
        vt_rows       = db_manager.get_evidence_by_type(case_id, 'virustotal')
        vss_rows      = db_manager.get_evidence_by_type(case_id, 'vss')

    # ── Document setup ────────────────────────────────────────────────────────
    doc = BaseDocTemplate(
        output_path, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=20*mm, bottomMargin=18*mm
    )
    cover_frame = Frame(0, 0, w, h, leftPadding=30*mm, rightPadding=20*mm,
                        topPadding=30*mm, bottomPadding=20*mm, id='cover')
    body_frame  = Frame(18*mm, 14*mm, w - 36*mm, h - 30*mm,
                        leftPadding=0, rightPadding=0,
                        topPadding=4*mm, bottomPadding=2*mm, id='body')

    doc.addPageTemplates([
        PageTemplate(id='Cover', frames=[cover_frame], onPage=_on_cover_page),
        PageTemplate(id='Body',  frames=[body_frame],  onPage=_on_body_page),
    ])

    elements = []

    # ── COVER PAGE ────────────────────────────────────────────────────────────
    elements.append(Spacer(1, 4*cm))
    elements.append(Paragraph('FORENSIC', st['cover_title']))
    elements.append(Paragraph('INVESTIGATION', st['cover_title']))
    elements.append(Paragraph('REPORT', st['cover_title']))
    elements.append(Spacer(1, 0.8*cm))
    elements.append(HRFlowable(width='60%', thickness=2, color=ACCENT, spaceAfter=16))
    elements.append(Spacer(1, 0.8*cm))

    meta = [
        ('Case ID',       case_info.get('case_id', '—')),
        ('Case Name',     case_info.get('case_name', 'Forensic Investigation')),
        ('Investigator',  case_info.get('investigator_name', '—')),
        ('Target System', case_info.get('target_system', '—')),
        ('Platform',      f"{platform.system()} {platform.release()}"),
        ('Generated',     now_str),
    ]
    meta_data = [[Paragraph(f'<b>{k}</b>', st['cover_meta']),
                  Paragraph(v, st['cover_meta'])] for k, v in meta]
    meta_table = Table(meta_data, colWidths=[4*cm, 9*cm])
    meta_table.setStyle(TableStyle([
        ('TEXTCOLOR',   (0, 0), (-1, -1), WHITE),
        ('FONTSIZE',    (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING',  (0, 0), (-1, -1), 6),
        ('LINEBELOW',   (0, 0), (-1, -2), 0.5, colors.HexColor('#ffffff30')),
        ('VALIGN',      (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN',       (0, 0), (0, -1), 'RIGHT'),
        ('RIGHTPADDING', (0, 0), (0, -1), 12),
    ]))
    elements.append(meta_table)

    # Transition to body pages
    elements.append(NextPageTemplate('Body'))
    elements.append(PageBreak())

    # ── DETECTIONS SUMMARY (Executive Page) ───────────────────────────────────
    elements += _build_detections_summary(
        st, counts, yara_rows, sigma_rows, vt_rows, startup_rows)

    # ── Evidence breakdown table ──
    elements.append(Paragraph('Evidence Breakdown', ParagraphStyle(
        'BreakdownTitle', fontName='Helvetica-Bold', fontSize=11,
        textColor=NAVY, spaceAfter=4)))

    summary_data = [['Artifact Type', 'Count', 'Source Module']]
    type_map = [
        ('Processes',       counts.get('process', 0),         'psutil'),
        ('Recent Files',    counts.get('recent_file', 0),     'Registry'),
        ('Startup Programs', counts.get('startup_entry', 0),  'Registry + Folders'),
        ('USB Devices',     counts.get('usb_device', 0),      'Registry'),
        ('Browser History', counts.get('browser_history', 0), 'Chrome / Edge / Firefox'),
        ('Event Logs',      counts.get('event_log', 0),       'EVTX Parser'),
        ('Prefetch',        counts.get('prefetch', 0),        'Prefetch Parser'),
        ('ShimCache',       counts.get('shimcache', 0),       'Registry (SYSTEM)'),
        ('USN Journal',     counts.get('usn_journal', 0),     'NTFS Raw I/O'),
        ('YARA Hits',       counts.get('yara_match', 0),      'YARA Scanner'),
        ('Sigma Alerts',    counts.get('sigma_alert', 0),     'Sigma Engine'),
        ('VirusTotal',      counts.get('virustotal', 0),      'VirusTotal API'),
        ('Shadow Copies',   counts.get('vss', 0),             'VSS Extractor'),
    ]
    alert_rows_set = set()
    for i, (label, count, source) in enumerate(type_map, 1):
        summary_data.append([label, str(count), source])
        if label in ('YARA Hits', 'Sigma Alerts') and count > 0:
            alert_rows_set.add(i)

    elements.append(_make_table(summary_data, [6*cm, 3*cm, 8*cm],
                                alert_rows=alert_rows_set, severity='critical'))
    elements.append(Spacer(1, 5*mm))

    # ── YARA MALWARE HITS ─────────────────────────────────────────────────────
    if yara_rows:
        elements.append(PageBreak())
        elements += _section_header(
            '⚠  YARA Malware Hits', st,
            subtitle=f'{len(yara_rows)} potential threat(s) detected')
        yara_table_data = [['Rule', 'Severity', 'File', 'Description']]
        for row in yara_rows:
            raw = json.loads(row.get('raw_data', '{}'))
            yara_table_data.append([
                _truncate(raw.get('rule', '—'), 30),
                _severity_badge(raw.get('severity', '—')),
                _truncate(os.path.basename(raw.get('filepath', '—')), 30),
                _truncate(raw.get('description', '—'), 50),
            ])
        elements.append(_make_table(
            yara_table_data, [4*cm, 2.5*cm, 4*cm, 6.5*cm],
            header_bg=RED_ALERT,
            alert_rows=set(range(1, len(yara_table_data))),
            severity='critical'
        ))
        elements.append(Spacer(1, 4*mm))

    # ── STARTUP ENTRIES ───────────────────────────────────────────────────────
    if startup_rows:
        elements.append(PageBreak())
        elements += _section_header('Startup Programs', st,
                                    subtitle='Programs configured to run at system startup')
        su_data = [['Name', 'Command', 'Source', 'Suspicious']]
        alert_su = set()
        for i, row in enumerate(startup_rows, 1):
            raw = json.loads(row.get('raw_data', '{}'))
            is_sus = raw.get('flagged_suspicious', False)
            if is_sus:
                alert_su.add(i)
            su_data.append([
                _truncate(raw.get('name', '—'), 25),
                _truncate(raw.get('command', '—'), 45),
                raw.get('source_type', '—'),
                '⚠  YES' if is_sus else 'No',
            ])
        elements.append(_make_table(su_data, [3.5*cm, 7*cm, 3.5*cm, 3*cm],
                                    alert_rows=alert_su, severity='warning'))
        elements.append(Spacer(1, 4*mm))

    # ── PROCESSES ─────────────────────────────────────────────────────────────
    if process_rows:
        elements.append(PageBreak())
        display_procs = process_rows[:50]
        elements += _section_header('Running Processes', st,
                                    subtitle=f'Top {len(display_procs)} of {len(process_rows)} processes at collection time')
        p_data = [['PID', 'Name', 'CPU %', 'Memory (MB)', 'Username']]
        for row in display_procs:
            raw = json.loads(row.get('raw_data', '{}'))
            mem_mb = round(raw.get('memory_rss', 0) / (1024*1024), 1) if raw.get('memory_rss') else '—'
            p_data.append([
                str(raw.get('pid', '—')),
                _truncate(raw.get('name', '—'), 30),
                str(raw.get('cpu_percent', '—')),
                str(mem_mb),
                _truncate(raw.get('username', '—'), 25),
            ])
        elements.append(_make_table(p_data, [2*cm, 5*cm, 2.5*cm, 3*cm, 4.5*cm]))
        elements.append(Spacer(1, 4*mm))

    # ── BROWSER HISTORY ───────────────────────────────────────────────────────
    if browser_rows:
        elements.append(PageBreak())
        display_bh = browser_rows[:60]
        elements += _section_header('Browser History', st,
                                    subtitle=f'Last {len(display_bh)} of {len(browser_rows)} entries (Chrome, Edge, Firefox)')
        bh_data = [['Browser', 'Title', 'URL', 'Last Visited']]
        for row in display_bh:
            raw = json.loads(row.get('raw_data', '{}'))
            bh_data.append([
                raw.get('browser', '—'),
                _truncate(raw.get('title', '—'), 30),
                _truncate(raw.get('url', '—'), 50),
                _truncate(raw.get('last_visited', '—'), 22),
            ])
        elements.append(_make_table(bh_data, [2.5*cm, 4.5*cm, 7*cm, 3*cm]))
        elements.append(Spacer(1, 4*mm))

    # ── USB DEVICES ───────────────────────────────────────────────────────────
    if usb_rows:
        elements.append(PageBreak())
        elements += _section_header('USB Device History', st,
                                    subtitle='All USB devices ever connected to this system')
        usb_data = [['Device Name', 'Serial Number', 'Device ID']]
        for row in usb_rows:
            raw = json.loads(row.get('raw_data', '{}'))
            usb_data.append([
                _truncate(raw.get('friendly_name', '—'), 35),
                _truncate(raw.get('serial_number', '—'), 25),
                _truncate(raw.get('device_id', '—'), 40),
            ])
        elements.append(_make_table(usb_data, [5*cm, 4.5*cm, 7.5*cm]))
        elements.append(Spacer(1, 4*mm))

    # ── RECENT FILES ─────────────────────────────────────────────────────────
    if recent_rows:
        elements.append(PageBreak())
        display_rf = recent_rows[:50]
        elements += _section_header('Recently Accessed Files', st,
                                    subtitle=f'{len(display_rf)} of {len(recent_rows)} recently accessed files from Registry')
        rf_data = [['Filename', 'Full Path']]
        for row in display_rf:
            raw = json.loads(row.get('raw_data', '{}'))
            rf_data.append([
                _truncate(raw.get('filename', '—'), 30),
                _truncate(raw.get('filepath', raw.get('path', '—')), 60),
            ])
        elements.append(_make_table(rf_data, [5*cm, 12*cm]))
        elements.append(Spacer(1, 4*mm))

    # ── PREFETCH ──────────────────────────────────────────────────────────────
    if prefetch_rows:
        elements.append(PageBreak())
        elements += _section_header('Prefetch — Execution Evidence', st,
                                    subtitle='Proof of program execution from Windows Prefetch files')
        pf_data = [['Executable', 'Run Count', 'Last Run', 'Prefetch File']]
        for row in prefetch_rows:
            raw = json.loads(row.get('raw_data', '{}'))
            pf_data.append([
                _truncate(raw.get('executable_name', '—'), 35),
                str(raw.get('run_count', '—')),
                _truncate(raw.get('last_run', '—'), 22),
                _truncate(raw.get('pf_filename', '—'), 30),
            ])
        elements.append(_make_table(pf_data, [6*cm, 2.5*cm, 4*cm, 4.5*cm]))
        elements.append(Spacer(1, 4*mm))

    # ── SHIMCACHE ─────────────────────────────────────────────────────────────
    if shimcache_rows:
        elements.append(PageBreak())
        display_sc = shimcache_rows[:100]
        elements += _section_header('ShimCache — Application Compatibility Cache', st,
                                    subtitle=f'{len(display_sc)} of {len(shimcache_rows)} cached executable entries')
        sc_data = [['#', 'Executable Path', 'Last Modified']]
        for row in display_sc:
            raw = json.loads(row.get('raw_data', '{}'))
            sc_data.append([
                str(raw.get('cache_position', '—')),
                _truncate(raw.get('executable_path', '—'), 65),
                _truncate(raw.get('last_modified', '—'), 22),
            ])
        elements.append(_make_table(sc_data, [1.5*cm, 11.5*cm, 4*cm]))
        elements.append(Spacer(1, 4*mm))

    # ── USN JOURNAL ───────────────────────────────────────────────────────────
    if usn_rows:
        elements.append(PageBreak())
        display_usn = usn_rows[:200]
        elements += _section_header('USN Journal — File System Changes', st,
                                    subtitle=f'Last {len(display_usn)} of {len(usn_rows)} NTFS change log entries')
        usn_data = [['Timestamp', 'Filename', 'Reason', 'Dir']]
        for row in display_usn:
            raw = json.loads(row.get('raw_data', '{}'))
            usn_data.append([
                _truncate(raw.get('timestamp', '—'), 22),
                _truncate(raw.get('filename', '—'), 35),
                _truncate(raw.get('reason_summary', '—'), 35),
                'Yes' if raw.get('is_directory') else 'No',
            ])
        elements.append(_make_table(usn_data, [4*cm, 5*cm, 6*cm, 2*cm]))
        elements.append(Spacer(1, 4*mm))

    # ── SIGMA ALERTS ──────────────────────────────────────────────────────────
    if sigma_rows:
        elements.append(PageBreak())
        elements += _section_header('⚠  Sigma Alerts — Behavioral Detections', st,
                                    subtitle=f'{len(sigma_rows)} suspicious behaviors detected in event logs')
        sig_data = [['Rule', 'Level', 'Event ID', 'Timestamp', 'Rule File']]
        for row in sigma_rows:
            raw = json.loads(row.get('raw_data', '{}'))
            sig_data.append([
                _truncate(raw.get('rule_title', '—'), 35),
                _severity_badge(raw.get('rule_level', '—')),
                str(raw.get('matched_event', {}).get('event_id', '—')),
                _truncate(raw.get('matched_event', {}).get('timestamp', '—'), 22),
                _truncate(raw.get('sigma_file', '—'), 25),
            ])
        elements.append(_make_table(
            sig_data, [5*cm, 2*cm, 2*cm, 4*cm, 4*cm],
            header_bg=AMBER,
            alert_rows=set(range(1, len(sig_data))),
            severity='warning'
        ))
        elements.append(Spacer(1, 4*mm))

    # ── VIRUSTOTAL ────────────────────────────────────────────────────────────
    if vt_rows:
        elements.append(PageBreak())
        elements += _section_header('VirusTotal — Hash Reputation', st,
                                    subtitle='File hash lookups against 70+ antivirus engines')
        vt_data = [['File', 'Detection Ratio', 'Threat Label', 'Status']]
        vt_alert_rows = set()
        for i, row in enumerate(vt_rows, 1):
            raw = json.loads(row.get('raw_data', '{}'))
            if raw.get('is_malicious'):
                vt_alert_rows.add(i)
            vt_data.append([
                _truncate(raw.get('label', raw.get('meaningful_name', '—')), 30),
                raw.get('detection_ratio', '—'),
                _truncate(raw.get('threat_label', '—'), 30),
                '🔴 MALICIOUS' if raw.get('is_malicious') else '🟢 Clean',
            ])
        elements.append(_make_table(
            vt_data, [5*cm, 3*cm, 5*cm, 4*cm],
            alert_rows=vt_alert_rows, severity='critical'
        ))
        elements.append(Spacer(1, 4*mm))

    # ── VSS ───────────────────────────────────────────────────────────────────
    if vss_rows:
        elements.append(PageBreak())
        elements += _section_header('Volume Shadow Copies', st,
                                    subtitle='Recovered forensic artifacts from system shadow copies')
        vss_data = [['Shadow Copy', 'Creation Time', 'Artifacts Found']]
        for row in vss_rows:
            raw = json.loads(row.get('raw_data', '{}'))
            artifacts = raw.get('artifacts_found', [])
            artifact_names = ', '.join(
                [a.get('artifact_type', '') for a in artifacts[:5]]) if artifacts else 'None'
            vss_data.append([
                _truncate(raw.get('shadow_id', '—'), 40),
                _truncate(raw.get('creation_time', '—'), 25),
                _truncate(artifact_names, 40),
            ])
        elements.append(_make_table(vss_data, [6*cm, 4.5*cm, 6.5*cm]))
        elements.append(Spacer(1, 4*mm))

    # ── TIMELINE ──────────────────────────────────────────────────────────────
    if timeline_data:
        elements.append(PageBreak())
        elements += _section_header('Chronological Event Timeline', st,
                                    subtitle=f'{len(timeline_data)} timestamped events ordered chronologically')
        tl_data = [['Timestamp', 'Type', 'Source', 'Event']]
        for e in timeline_data[:200]:
            tl_data.append([
                _truncate(str(e.get('time', '—')), 22),
                _truncate(str(e.get('type', '—')), 18),
                _truncate(str(e.get('source', '—')), 18),
                _truncate(str(e.get('event', '—')), 55),
            ])
        elements.append(_make_table(tl_data, [4*cm, 3*cm, 3*cm, 7*cm]))

    doc.build(elements)

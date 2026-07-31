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

# ── Colour Palette ────────────────────────────────────────────────────────────
DARK_BG     = colors.HexColor('#0d1117')
ACCENT      = colors.HexColor('#1f6feb')
ACCENT2     = colors.HexColor('#388bfd')
RED_ALERT   = colors.HexColor('#da3633')
AMBER       = colors.HexColor('#d29922')
GREEN_OK    = colors.HexColor('#238636')
SECTION_BG  = colors.HexColor('#161b22')
ROW_ALT     = colors.HexColor('#1c2128')
ROW_NORMAL  = colors.HexColor('#0d1117')
HEADER_TEXT = colors.white
BODY_TEXT   = colors.HexColor('#c9d1d9')
SUB_TEXT    = colors.HexColor('#8b949e')
BORDER_CLR  = colors.HexColor('#30363d')
WHITE       = colors.white


def _styles():
    """Build a complete set of custom paragraph styles."""
    s = getSampleStyleSheet()

    cover_title = ParagraphStyle(
        'CoverTitle', fontName='Helvetica-Bold', fontSize=26,
        textColor=WHITE, spaceAfter=6, alignment=TA_CENTER, leading=32)

    cover_sub = ParagraphStyle(
        'CoverSub', fontName='Helvetica', fontSize=13,
        textColor=colors.HexColor('#8b949e'), spaceAfter=4, alignment=TA_CENTER)

    cover_meta = ParagraphStyle(
        'CoverMeta', fontName='Helvetica-Bold', fontSize=11,
        textColor=BODY_TEXT, spaceAfter=4, alignment=TA_CENTER)

    section_heading = ParagraphStyle(
        'SectionHeading', fontName='Helvetica-Bold', fontSize=14,
        textColor=ACCENT2, spaceBefore=14, spaceAfter=6, leading=18)

    normal_dark = ParagraphStyle(
        'NormalDark', fontName='Helvetica', fontSize=9,
        textColor=BODY_TEXT, spaceAfter=2, leading=13)

    small_dark = ParagraphStyle(
        'SmallDark', fontName='Helvetica', fontSize=7.5,
        textColor=BODY_TEXT, leading=11)

    alert_red = ParagraphStyle(
        'AlertRed', fontName='Helvetica-Bold', fontSize=10,
        textColor=RED_ALERT, spaceAfter=4)

    label = ParagraphStyle(
        'Label', fontName='Helvetica-Bold', fontSize=9,
        textColor=SUB_TEXT, spaceAfter=1)

    return dict(
        cover_title=cover_title, cover_sub=cover_sub, cover_meta=cover_meta,
        section_heading=section_heading, normal_dark=normal_dark,
        small_dark=small_dark, alert_red=alert_red, label=label
    )


# ── Page templates ────────────────────────────────────────────────────────────
def _on_cover_page(canvas, doc):
    canvas.saveState()
    w, h = A4
    # Full dark background
    canvas.setFillColor(DARK_BG)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)
    # Top accent stripe
    canvas.setFillColor(ACCENT)
    canvas.rect(0, h - 8*mm, w, 8*mm, fill=1, stroke=0)
    # Bottom accent stripe
    canvas.rect(0, 0, w, 5*mm, fill=1, stroke=0)
    # Left side bar
    canvas.setFillColor(SECTION_BG)
    canvas.rect(0, 5*mm, 6*mm, h - 13*mm, fill=1, stroke=0)
    canvas.restoreState()


def _on_body_page(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(DARK_BG)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)
    # Header bar
    canvas.setFillColor(SECTION_BG)
    canvas.rect(0, h - 14*mm, w, 14*mm, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.rect(0, h - 14*mm, w, 1.5*mm, fill=1, stroke=0)
    # Footer bar
    canvas.setFillColor(SECTION_BG)
    canvas.rect(0, 0, w, 12*mm, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.rect(0, 12*mm, w, 0.5*mm, fill=1, stroke=0)
    # Header text
    canvas.setFont('Helvetica-Bold', 8)
    canvas.setFillColor(SUB_TEXT)
    canvas.drawString(18*mm, h - 9*mm, 'DIGITAL FORENSICS INVESTIGATION REPORT')
    canvas.setFont('Helvetica', 8)
    canvas.drawRightString(w - 18*mm, h - 9*mm, f'Page {doc.page}')
    # Footer text
    canvas.setFont('Helvetica', 7.5)
    canvas.setFillColor(SUB_TEXT)
    canvas.drawString(18*mm, 4*mm, 'CONFIDENTIAL — Authorised Personnel Only')
    canvas.drawRightString(w - 18*mm, 4*mm, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    canvas.restoreState()


# ── Table helper ──────────────────────────────────────────────────────────────
def _make_table(data, col_widths, header_bg=ACCENT, alert_rows=None):
    """Build a styled dark-theme table. alert_rows is a set of row indices to highlight red."""
    alert_rows = alert_rows or set()
    style_cmds = [
        # Header row
        ('BACKGROUND',  (0, 0), (-1, 0), header_bg),
        ('TEXTCOLOR',   (0, 0), (-1, 0), WHITE),
        ('FONTNAME',    (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('TOPPADDING',  (0, 0), (-1, 0), 6),
        # Body rows
        ('FONTNAME',    (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',    (0, 1), (-1, -1), 7.5),
        ('TEXTCOLOR',   (0, 1), (-1, -1), BODY_TEXT),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
        ('TOPPADDING',  (0, 1), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [ROW_NORMAL, ROW_ALT]),
        ('GRID',        (0, 0), (-1, -1), 0.4, BORDER_CLR),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('VALIGN',      (0, 0), (-1, -1), 'MIDDLE'),
    ]
    for row_idx in alert_rows:
        style_cmds.append(('BACKGROUND', (0, row_idx), (-1, row_idx), colors.HexColor('#3d0000')))
        style_cmds.append(('TEXTCOLOR',  (0, row_idx), (-1, row_idx), RED_ALERT))
        style_cmds.append(('FONTNAME',   (0, row_idx), (-1, row_idx), 'Helvetica-Bold'))

    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle(style_cmds))
    return t


def _section_header(title, st, subtitle=None):
    elems = []
    elems.append(HRFlowable(width='100%', thickness=0.5, color=ACCENT, spaceAfter=4))
    elems.append(Paragraph(title, st['section_heading']))
    if subtitle:
        elems.append(Paragraph(subtitle, st['label']))
    return elems


def _truncate(text, maxlen=80):
    text = str(text) if text else '—'
    return text[:maxlen] + '…' if len(text) > maxlen else text


# ── Main report function ──────────────────────────────────────────────────────
def generate_pdf_report(case_info, timeline_data, output_path, db_manager=None):
    """
    Generate a professional multi-section forensic investigation PDF report.

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
    elements.append(Spacer(1, 3*cm))
    elements.append(Paragraph('DIGITAL FORENSICS', st['cover_title']))
    elements.append(Paragraph('INVESTIGATION REPORT', st['cover_title']))
    elements.append(Spacer(1, 0.5*cm))
    elements.append(HRFlowable(width='80%', thickness=2, color=ACCENT, spaceAfter=16))
    elements.append(Spacer(1, 0.5*cm))

    meta = [
        ('Case ID',       case_info.get('case_id', '—')),
        ('Case Name',     case_info.get('case_name', 'Forensic Investigation')),
        ('Investigator',  case_info.get('investigator_name', '—')),
        ('Target System', case_info.get('target_system', '—')),
        ('Platform',      f"{platform.system()} {platform.release()}"),
        ('Generated',     now_str),
    ]
    for label, value in meta:
        elements.append(Paragraph(f'<font color="#8b949e">{label}:</font>  '
                                  f'<font color="#c9d1d9"><b>{value}</b></font>',
                                  st['cover_meta']))

    elements.append(Spacer(1, 1.5*cm))
    elements.append(HRFlowable(width='80%', thickness=0.5, color=BORDER_CLR, spaceAfter=10))
    elements.append(Paragraph(
        '⚠  CONFIDENTIAL — FOR AUTHORISED PERSONNEL ONLY',
        ParagraphStyle('conf', fontName='Helvetica-Bold', fontSize=9,
                       textColor=AMBER, alignment=TA_CENTER)))

    elements.append(NextPageTemplate('Body'))
    elements.append(PageBreak())

    # ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
    elements += _section_header('Executive Summary', st)
    elements.append(Spacer(1, 3*mm))

    yara_count   = len(yara_rows)
    total_arts   = sum(counts.values()) if counts else len(timeline_data)
    proc_count   = counts.get('process', 0)
    browser_count= counts.get('browser_history', 0)
    startup_count= counts.get('startup_entry', 0)
    usb_count    = counts.get('usb_device', 0)

    summary_data = [
        ['Metric', 'Value', 'Status'],
        ['Total Artifacts Collected', str(total_arts),        'OK'],
        ['Running Processes',         str(proc_count),        'OK'],
        ['Startup Entries',           str(startup_count),     'OK'],
        ['Browser History Entries',   str(browser_count),     'OK'],
        ['USB Devices Detected',      str(usb_count),         'OK'],
        ['YARA Malware Hits',         str(yara_count),
         '⚠  THREAT DETECTED' if yara_count > 0 else 'CLEAN'],
    ]
    alert_rows_set = {6} if yara_count > 0 else set()
    elements.append(_make_table(summary_data, [8*cm, 4*cm, 5*cm],
                                alert_rows=alert_rows_set))
    elements.append(Spacer(1, 5*mm))

    # ── YARA MALWARE HITS ─────────────────────────────────────────────────────
    if yara_rows:
        elements += _section_header(
            '⚠  YARA Malware Hits', st,
            subtitle=f'{len(yara_rows)} potential threat(s) detected')
        yara_table_data = [['Rule', 'Severity', 'File', 'Description']]
        for row in yara_rows:
            raw = json.loads(row.get('raw_data', '{}'))
            yara_table_data.append([
                _truncate(raw.get('rule', '—'), 30),
                raw.get('severity', '—'),
                _truncate(os.path.basename(raw.get('filepath', '—')), 30),
                _truncate(raw.get('description', '—'), 50),
            ])
        elements.append(_make_table(
            yara_table_data, [4*cm, 2.5*cm, 4*cm, 6.5*cm],
            header_bg=RED_ALERT,
            alert_rows=set(range(1, len(yara_table_data)))
        ))
        elements.append(Spacer(1, 4*mm))

    # ── STARTUP ENTRIES ───────────────────────────────────────────────────────
    if startup_rows:
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
                                    alert_rows=alert_su))
        elements.append(Spacer(1, 4*mm))

    # ── PROCESSES ─────────────────────────────────────────────────────────────
    if process_rows:
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
        elements += _section_header('⚠  Sigma Alerts — Behavioral Detections', st,
                                    subtitle=f'{len(sigma_rows)} suspicious behaviors detected in event logs')
        sig_data = [['Rule', 'Level', 'Event ID', 'Timestamp', 'Rule File']]
        for row in sigma_rows:
            raw = json.loads(row.get('raw_data', '{}'))
            sig_data.append([
                _truncate(raw.get('rule_title', '—'), 35),
                raw.get('rule_level', '—').upper(),
                str(raw.get('matched_event', {}).get('event_id', '—')),
                _truncate(raw.get('matched_event', {}).get('timestamp', '—'), 22),
                _truncate(raw.get('sigma_file', '—'), 25),
            ])
        elements.append(_make_table(
            sig_data, [5*cm, 2*cm, 2*cm, 4*cm, 4*cm],
            header_bg=AMBER,
            alert_rows=set(range(1, len(sig_data)))
        ))
        elements.append(Spacer(1, 4*mm))

    # ── VIRUSTOTAL ─────────────────────────────────────────────────────────────
    if vt_rows:
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
                '⚠  MALICIOUS' if raw.get('is_malicious') else raw.get('status', '—'),
            ])
        elements.append(_make_table(
            vt_data, [5*cm, 3*cm, 5*cm, 4*cm],
            alert_rows=vt_alert_rows
        ))
        elements.append(Spacer(1, 4*mm))

    # ── VSS ───────────────────────────────────────────────────────────────────
    if vss_rows:
        elements += _section_header('Volume Shadow Copies', st,
                                    subtitle='Recovered forensic artifacts from system shadow copies')
        vss_data = [['Shadow Copy', 'Creation Time', 'Artifacts Found']]
        for row in vss_rows:
            raw = json.loads(row.get('raw_data', '{}'))
            artifacts = raw.get('artifacts_found', [])
            artifact_names = ', '.join([a.get('artifact_type', '') for a in artifacts[:5]]) if artifacts else 'None'
            vss_data.append([
                _truncate(raw.get('shadow_id', '—'), 40),
                _truncate(raw.get('creation_time', '—'), 25),
                _truncate(artifact_names, 40),
            ])
        elements.append(_make_table(vss_data, [6*cm, 4.5*cm, 6.5*cm]))
        elements.append(Spacer(1, 4*mm))

    # ── TIMELINE ───────────────────────────────────────────────────────────────
    if timeline_data:
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

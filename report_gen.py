"""
USB Sentinel AI - PDF Forensic Investigation Report Generator
Generates comprehensive cyber-forensic audit reports using ReportLab.
"""

import os
from datetime import datetime
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """Adds professional header and footer with dynamic page counts."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#06B6D4"))
        
        # Header rule and label
        self.drawString(54, 755, "USB SENTINEL AI // DIGITAL FORENSICS & THREAT INTELLIGENCE")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawRightString(558, 755, "CONFIDENTIAL EVIDENCE REPORT")
        self.setStrokeColor(colors.HexColor("#1E293B"))
        self.setLineWidth(0.75)
        self.line(54, 747, 558, 747)

        # Footer
        self.line(54, 45, 558, 45)
        self.drawString(54, 32, "USB Sentinel AI Threat Intelligence Engine")
        self.drawRightString(558, 32, f"Page {self._pageNumber} of {total_pages}")
        self.restoreState()


def generate_forensic_pdf(
    output_pdf_path: str,
    device_info: dict,
    scan_summary: dict,
    scan_results: list,
    ai_insights: list,
    audit_logs: list
) -> str:
    """
    Builds and writes a comprehensive PDF forensic report to output_pdf_path.
    """
    out_path = Path(output_pdf_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=60,
        bottomMargin=55
    )

    styles = getSampleStyleSheet()

    # Custom Cyber Forensics Styles
    style_title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A")
    )
    style_subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569")
    )
    style_section = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0284C7"),
        spaceBefore=14,
        spaceAfter=6
    )
    style_body = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1E293B")
    )
    style_code = ParagraphStyle(
        "CodeStyle",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0F172A")
    )
    style_badge_red = ParagraphStyle(
        "BadgeRed",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#DC2626")
    )
    style_badge_yellow = ParagraphStyle(
        "BadgeYellow",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#D97706")
    )
    style_badge_green = ParagraphStyle(
        "BadgeGreen",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#16A34A")
    )
    style_th = ParagraphStyle(
        "TableHeaderWhite",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=colors.white
    )
    style_th_center = ParagraphStyle(
        "TableHeaderCenterWhite",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=colors.white,
        alignment=1  # Centered
    )
    style_cell_center = ParagraphStyle(
        "TableCellCenter",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#0F172A"),
        alignment=1  # Centered
    )

    story = []

    # Title Banner
    story.append(Paragraph("FORENSIC EVIDENCE & THREAT REPORT", style_title))
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(f"Generated by USB Sentinel AI &bull; {timestamp_str}", style_subtitle))
    story.append(Spacer(1, 10))

    # SECTION 1: USB Device & Hardware Metadata
    story.append(Paragraph("1. PHYSICAL HARDWARE & VOLUME METADATA", style_section))
    
    mount = device_info.get("mount_point", "N/A")
    vol_label = device_info.get("volume_label", "Unknown")
    serial_no = device_info.get("serial_number", "Unknown")
    fs_type = device_info.get("file_system", "Unknown")
    total_gb = device_info.get("total_gb", 0)
    free_gb = device_info.get("free_gb", 0)

    device_table_data = [
        [Paragraph("<b>Mount Point / Drive:</b>", style_body), Paragraph(str(mount), style_body),
         Paragraph("<b>Volume Serial No:</b>", style_body), Paragraph(str(serial_no), style_code)],
        [Paragraph("<b>Volume Label:</b>", style_body), Paragraph(str(vol_label), style_body),
         Paragraph("<b>File System:</b>", style_body), Paragraph(str(fs_type), style_body)],
        [Paragraph("<b>Capacity:</b>", style_body), Paragraph(f"{total_gb} GB Total", style_body),
         Paragraph("<b>Free Space:</b>", style_body), Paragraph(f"{free_gb} GB Available", style_body)]
    ]
    t_device = Table(device_table_data, colWidths=[110, 142, 110, 142])
    t_device.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_device)
    story.append(Spacer(1, 12))

    # SECTION 2: Scan Metrics & Threat Overview
    story.append(Paragraph("2. HEURISTIC SCAN SUMMARY & RISK OVERVIEW", style_section))
    
    total_files = scan_summary.get("total_scanned", len(scan_results))
    clean_cnt = scan_summary.get("clean", 0)
    susp_cnt = scan_summary.get("suspicious", 0)
    mal_cnt = scan_summary.get("malicious", 0)

    summary_table_data = [
        [
            Paragraph("Total Files Scanned", style_th_center),
            Paragraph("Clean Files", style_th_center),
            Paragraph("Suspicious Artifacts", style_th_center),
            Paragraph("Malicious Payloads", style_th_center)
        ],
        [
            Paragraph(f"<b>{total_files}</b>", style_cell_center),
            Paragraph(f"<font color='#16A34A'><b>{clean_cnt}</b></font>", style_cell_center),
            Paragraph(f"<font color='#D97706'><b>{susp_cnt}</b></font>", style_cell_center),
            Paragraph(f"<font color='#DC2626'><b>{mal_cnt}</b></font>", style_cell_center)
        ]
    ]
    t_summary = Table(summary_table_data, colWidths=[126, 126, 126, 126])
    t_summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#0F172A")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 14))

    # SECTION 3: Detailed Flagged Items & Cryptographic Hashes
    story.append(Paragraph("3. FLAGGED ARTIFACTS & CRYPTOGRAPHIC INTEGRITY", style_section))
    
    flagged_files = [f for f in scan_results if f.get("risk_level") in ["SUSPICIOUS", "MALICIOUS"]]
    
    if not flagged_files:
        story.append(Paragraph("<i>No suspicious or malicious files detected during physical drive scan. Volume appears clean.</i>", style_body))
    else:
        table_rows = [
            [
                Paragraph("File / Path", style_th),
                Paragraph("SHA-256 Hash", style_th),
                Paragraph("Entropy / Magic", style_th),
                Paragraph("Alert Rules & Verdict", style_th)
            ]
        ]
        for f in flagged_files[:15]:  # Cap at top 15 in main table
            r_level = f.get("risk_level", "CLEAN")
            badge = style_badge_red if r_level == "MALICIOUS" else style_badge_yellow
            rules_str = "<br/>".join([f"&bull; {r}" for r in f.get("rules_triggered", [])[:3]]) or "None"
            
            p_name = Paragraph(f"<b>{f.get('name')}</b><br/><font size='7' color='#64748B'>{f.get('path')}</font>", style_body)
            p_hash = Paragraph(f"<font size='6.5'>{f.get('sha256', 'N/A')}</font>", style_code)
            p_ent = Paragraph(f"Entropy: <b>{f.get('entropy', 0.0):.2f}</b><br/>{f.get('magic_desc', 'Unknown')}", style_body)
            p_alert = Paragraph(f"<b>Score: {f.get('threat_score', 0)}/100</b> ({r_level})<br/>{rules_str}", badge)

            table_rows.append([p_name, p_hash, p_ent, p_alert])

        t_flags = Table(table_rows, colWidths=[120, 140, 110, 134])
        t_flags.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#94A3B8")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t_flags)

    story.append(Spacer(1, 14))

    # SECTION 4: Groq AI Deep Threat Intelligence Insights
    if ai_insights:
        story.append(Paragraph("4. GROQ AI THREAT INTELLIGENCE & MITRE ATT&CK CLASSIFICATION", style_section))
        for item in ai_insights[:5]:
            file_name = item.get("file_name", "Analyzed Payload")
            verdict = item.get("threat_verdict", "Unknown")
            score = item.get("threat_score", 0)
            category = item.get("malware_category", "General Threat")
            mitre = ", ".join(item.get("mitre_att_ck", [])) or "None Identified"
            summary = item.get("deobfuscated_summary", "No detailed summary available.")
            action = item.get("recommended_action", "Quarantine")

            ai_box = [
                [
                    Paragraph(f"<b>Artifact: {file_name}</b>", style_body),
                    Paragraph(f"<b>Verdict: <font color='#DC2626'>{verdict} ({score}/100)</font></b>", style_body)
                ],
                [
                    Paragraph(f"<b>Malware Category:</b> {category}", style_body),
                    Paragraph(f"<b>Recommended Action:</b> <b>{action}</b>", style_body)
                ],
                [
                    Paragraph(f"<b>MITRE ATT&CK:</b> <font color='#0284C7'>{mitre}</font>", style_body),
                    Paragraph("", style_body)
                ],
                [
                    Paragraph(f"<b>De-obfuscation Analysis:</b><br/>{summary}", style_body),
                    Paragraph("", style_body)
                ]
            ]
            t_ai = Table(ai_box, colWidths=[252, 252])
            t_ai.setStyle(TableStyle([
                ("SPAN", (0, 2), (1, 2)),
                ("SPAN", (0, 3), (1, 3)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#38BDF8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(KeepTogether([t_ai, Spacer(1, 8)]))

    story.append(Spacer(1, 10))

    # SECTION 5: Forensic Session Audit Trail
    story.append(Paragraph("5. FORENSIC AUDIT LOG & REMEDIATION TRAIL", style_section))
    if audit_logs:
        audit_rows = [[Paragraph("Timestamp", style_th), Paragraph("Action / Event Description", style_th)]]
        for log in audit_logs[-12:]:
            t_stamp = log.get("timestamp", "")
            msg = log.get("message", "")
            audit_rows.append([
                Paragraph(f"<font size='7.5'>{t_stamp}</font>", style_code),
                Paragraph(msg, style_body)
            ])
        t_audit = Table(audit_rows, colWidths=[130, 374])
        t_audit.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(t_audit)
    else:
        story.append(Paragraph("<i>No audit log entries recorded for this session.</i>", style_body))

    # Build PDF with dynamic NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    return str(out_path)

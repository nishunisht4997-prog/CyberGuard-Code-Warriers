import os
import shutil
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

pdf_filename = "CYBERGUARD_V2_FORENSICS_FEATURE_UPGRADE.pdf"
doc = SimpleDocTemplate(
    pdf_filename,
    pagesize=letter,
    rightMargin=36,
    leftMargin=36,
    topMargin=36,
    bottomMargin=36
)

styles = getSampleStyleSheet()

primary_color = colors.HexColor('#0f172a')
accent_purple = colors.HexColor('#7c3aed')
accent_cyan = colors.HexColor('#0284c7')
text_dark = colors.HexColor('#1e293b')
card_bg = colors.HexColor('#f8fafc')
border_color = colors.HexColor('#cbd5e1')

title_style = ParagraphStyle(
    'DocTitle',
    parent=styles['Heading1'],
    fontName='Helvetica-Bold',
    fontSize=20,
    leading=24,
    textColor=colors.HexColor('#4c1d95'),
    alignment=1,
    spaceAfter=4
)

subtitle_style = ParagraphStyle(
    'DocSubTitle',
    parent=styles['Normal'],
    fontName='Helvetica-Bold',
    fontSize=10,
    leading=14,
    textColor=colors.HexColor('#475569'),
    alignment=1,
    spaceAfter=12
)

section_heading = ParagraphStyle(
    'SectionHeading',
    parent=styles['Heading2'],
    fontName='Helvetica-Bold',
    fontSize=12,
    leading=16,
    textColor=colors.HexColor('#1e1b4b'),
    spaceBefore=10,
    spaceAfter=5
)

table_header_style = ParagraphStyle(
    'TableHeader',
    parent=styles['Normal'],
    fontName='Helvetica-Bold',
    fontSize=9,
    leading=12,
    textColor=colors.white,
    alignment=1
)

cell_cat_style = ParagraphStyle(
    'CellCat',
    parent=styles['Normal'],
    fontName='Helvetica-Bold',
    fontSize=8,
    leading=11,
    textColor=colors.HexColor('#4338ca')
)

cell_before_style = ParagraphStyle(
    'CellBefore',
    parent=styles['Normal'],
    fontName='Helvetica',
    fontSize=7.8,
    leading=10.5,
    textColor=colors.HexColor('#64748b')
)

cell_after_style = ParagraphStyle(
    'CellAfter',
    parent=styles['Normal'],
    fontName='Helvetica',
    fontSize=7.8,
    leading=10.5,
    textColor=colors.HexColor('#0f172a')
)

story = []

# Title & Header
story.append(Paragraph('CYBERGUARD-X — AI SOC THREAT INTELLIGENCE PLATFORM', title_style))
story.append(Paragraph('Forensic Architecture & Feature Upgrade Technical Report<br/><font size=8.5 color="#64748b">Before vs. After Analysis (URL, Image, and Video Intelligence Engines)</font>', subtitle_style))
story.append(HRFlowable(width='100%', thickness=1.5, color=accent_purple, spaceAfter=10))

# ----------------- SECTION 1: URL INTELLIGENCE -----------------
story.append(Paragraph('1. URL Intelligence & Phishing Telemetry Engine', section_heading))
url_data = [
    [Paragraph('Category', table_header_style), Paragraph('Earlier Capability (Before)', table_header_style), Paragraph('Upgraded Advanced Capability (After)', table_header_style)],
    [
        Paragraph('Live DNS & Host Verification', cell_cat_style),
        Paragraph('Checked only static string parameters. Could not verify if the domain actually exists on the Internet.', cell_before_style),
        Paragraph('<b>Socket-Level DNS Resolution:</b> Performs real-time IPv4 resolution. Detects dead, unconfigured, or NXDOMAIN hosts (e.g. <i>https://nishat.com</i>) immediately.', cell_after_style)
    ],
    [
        Paragraph('Brand Spoofing & Impersonation', cell_cat_style),
        Paragraph('Simple substring check against static strings.', cell_before_style),
        Paragraph('<b>Levenshtein & Homoglyph Engine:</b> Computes character distance against 20+ top brands (PayPal, Netflix, Microsoft, Google, SBI, Apple) to catch subtle typosquats.', cell_after_style)
    ],
    [
        Paragraph('DGA & Algorithmic Domains', cell_cat_style),
        Paragraph('No mathematical or algorithmic domain inspection.', cell_before_style),
        Paragraph('<b>Shannon Entropy Analysis:</b> Measures domain name character entropy (bits). Detects machine-generated botnet DGA domains.', cell_after_style)
    ],
    [
        Paragraph('TLD Risk & Abuse Tiering', cell_cat_style),
        Paragraph('Only checked standard HTTP vs HTTPS protocol.', cell_before_style),
        Paragraph('<b>TLD Abuse Classification:</b> Evaluates high-risk abusive TLDs (.tk, .top, .xyz, .click, .ru, .pw, .fit) and assigns weighted risk multipliers.', cell_after_style)
    ],
    [
        Paragraph('SOC Explainability & UI', cell_cat_style),
        Paragraph('Displayed generic risk score with brief text.', cell_before_style),
        Paragraph('<b>Dedicated DNS Forensics Panel:</b> Displays resolved IP, Host Type, Entropy bits, TLD Risk Tier, and Brand Target details.', cell_after_style)
    ]
]
t_url = Table(url_data, colWidths=[1.4*inch, 2.7*inch, 3.2*inch])
t_url.setStyle(TableStyle([
    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6366f1')),
    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ('TOPPADDING', (0, 0), (-1, -1), 4),
    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
]))
story.append(t_url)
story.append(Spacer(1, 10))

# ----------------- SECTION 2: IMAGE FORENSICS -----------------
story.append(Paragraph('2. Image Authenticity & Content Safety Forensics', section_heading))
img_data = [
    [Paragraph('Category', table_header_style), Paragraph('Earlier Capability (Before)', table_header_style), Paragraph('Upgraded Advanced Capability (After)', table_header_style)],
    [
        Paragraph('Adult / NSFW Content Detection', cell_cat_style),
        Paragraph('<b>Zero Content Safety:</b> An unedited nude photo scored only 25/100 (Likely Authentic) because camera noise was natural.', cell_before_style),
        Paragraph('<b>AI Anatomical Skin Exposure Engine:</b> Dual-color space (HSV + YCrCb) skin segmentation + contour density. Over 30% unclad skin triggers <b>98% Critical Risk</b> & Policy Violation.', cell_after_style)
    ],
    [
        Paragraph('Steganography & Trailing Payloads', cell_cat_style),
        Paragraph('No file structure or end-of-frame inspection.', cell_before_style),
        Paragraph('<b>EOF Boundary Dissection:</b> Scans past JPEG FF D9 and PNG IEND markers. Detects appended ZIP archives, PowerShell scripts, and PE (.exe) binaries with <b>94% Critical Risk</b>.', cell_after_style)
    ],
    [
        Paragraph('EXIF Metadata & Tampering', cell_cat_style),
        Paragraph('Camera firmware was occasionally misflagged as photo editing software.', cell_before_style),
        Paragraph('<b>Smart Provenance Engine:</b> Distinguishes legitimate camera firmware from software editing suites (Photoshop, GIMP, Canva, Lightroom).', cell_after_style)
    ],
    [
        Paragraph('1-Click Test Scenarios', cell_cat_style),
        Paragraph('Limited static samples without specific attack scenarios.', cell_before_style),
        Paragraph('<b>5 Interactive Scenarios:</b> Explicit Adult Demo, Steganography Payload Demo, AI Deepfake, Altered ID, and Authentic Media.', cell_after_style)
    ],
    [
        Paragraph('SOC UI Telemetry', cell_cat_style),
        Paragraph('Displayed only basic manipulation percentage.', cell_before_style),
        Paragraph('<b>Content Safety & Stego Cards:</b> Shows Skin Exposure %, Policy Threshold %, Largest Patch %, and Embedded Payload byte size.', cell_after_style)
    ]
]
t_img = Table(img_data, colWidths=[1.4*inch, 2.7*inch, 3.2*inch])
t_img.setStyle(TableStyle([
    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#8b5cf6')),
    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ('TOPPADDING', (0, 0), (-1, -1), 4),
    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
]))
story.append(t_img)
story.append(Spacer(1, 10))

# ----------------- SECTION 3: VIDEO FORENSICS -----------------
story.append(Paragraph('3. Video Stream & Deepfake Forensics Engine', section_heading))
vid_data = [
    [Paragraph('Category', table_header_style), Paragraph('Earlier Capability (Before)', table_header_style), Paragraph('Upgraded Advanced Capability (After)', table_header_style)],
    [
        Paragraph('Keyframe Sampling', cell_cat_style),
        Paragraph('Read only file metadata without processing temporal video frames.', cell_before_style),
        Paragraph('<b>Multi-Keyframe Temporal Sampling:</b> Extracts 12 dynamic keyframes across video timeline via OpenCV for deep forensic analysis.', cell_after_style)
    ],
    [
        Paragraph('Deepfake Face-Swap Detection', cell_cat_style),
        Paragraph('No temporal motion flow or jitter inspection.', cell_before_style),
        Paragraph('<b>Temporal Motion Flow Jitter Engine:</b> Measures standard deviation of frame-to-frame pixel differences (diff_std) to catch AI face-swap flickering.', cell_after_style)
    ],
    [
        Paragraph('Video Splicing & Cuts', cell_cat_style),
        Paragraph('Could not identify splices or video cut transitions.', cell_before_style),
        Paragraph('<b>Histogram Correlation (min_corr):</b> Detects abrupt color distribution drops indicating digital scene seams or spliced clips.', cell_after_style)
    ],
    [
        Paragraph('Optical Blur Stability', cell_cat_style),
        Paragraph('No temporal sharpness variance analysis.', cell_before_style),
        Paragraph('<b>Laplacian Sharpness Tracking:</b> Analyzes intra-frame blur stability to detect selective facial blurring artifacts.', cell_after_style)
    ],
    [
        Paragraph('1-Click Video Demos & Telemetry', cell_cat_style),
        Paragraph('Placeholder state with no live sample files.', cell_before_style),
        Paragraph('<b>Interactive Video Panel:</b> Integrated with AI Deepfake Video, Spliced Clip, and Authentic Video with comprehensive live metrics.', cell_after_style)
    ]
]
t_vid = Table(vid_data, colWidths=[1.4*inch, 2.7*inch, 3.2*inch])
t_vid.setStyle(TableStyle([
    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#7c3aed')),
    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ('TOPPADDING', (0, 0), (-1, -1), 4),
    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
]))
story.append(t_vid)
story.append(Spacer(1, 10))

# Executive Summary
summary_box = [
    [Paragraph('<b>EXECUTIVE CONCLUSION:</b> CyberGuard-X has evolved from a basic static-checking tool into an enterprise-grade <b>Multi-Vector AI Threat Defense Platform</b>. By combining socket DNS lookups, Shannon entropy, dual HSV/YCrCb anatomical skin segmentation, EOF file boundary steganography scanning, and temporal OpenCV motion flow heuristics, the platform delivers zero-trust security intelligence with verifiable forensic proofs.', ParagraphStyle('Summary', parent=styles['Normal'], fontSize=8, leading=11, textColor=colors.HexColor('#1e1b4b')))]
]
t_sum = Table(summary_box, colWidths=[7.3*inch])
t_sum.setStyle(TableStyle([
    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#ede9fe')),
    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#8b5cf6')),
    ('TOPPADDING', (0, 0), (-1, -1), 6),
    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
]))
story.append(t_sum)

doc.build(story)
print("PDF generated successfully:", os.path.abspath(pdf_filename), "Size:", os.path.getsize(pdf_filename))

# Also copy to frontend/public for download
shutil.copyfile(pdf_filename, os.path.join("frontend", "public", pdf_filename))
print("Copied to frontend/public for public web access!")

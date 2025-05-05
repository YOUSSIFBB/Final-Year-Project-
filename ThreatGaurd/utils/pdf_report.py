from fpdf import FPDF
import os


def export_report_to_pdf(
    file_name, stats, hashes, vendor_detections, verdict, output_path
):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.set_title("ThreatGuard Scan Report")

    pdf.cell(200, 10, txt="📄 ThreatGuard - Scan Report", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", style="B", size=12)
    pdf.cell(200, 10, txt=f"Scanned File: {file_name}", ln=True)
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt=f"Scan Verdict: {verdict}", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", style="B", size=11)
    pdf.cell(200, 10, txt="Detection Statistics:", ln=True)
    pdf.set_font("Arial", size=11)
    for k, v in stats.items():
        pdf.cell(200, 8, txt=f"- {k.title()}: {v}", ln=True)

    pdf.ln(5)
    pdf.set_font("Arial", style="B", size=11)
    pdf.cell(200, 10, txt="File Hashes:", ln=True)
    pdf.set_font("Arial", size=11)
    for k, v in hashes.items():
        pdf.multi_cell(200, 8, txt=f"- {k.upper()}: {v}")

    pdf.ln(5)
    pdf.set_font("Arial", style="B", size=11)
    pdf.cell(200, 10, txt="Top Vendor Detections:", ln=True)
    pdf.set_font("Arial", size=11)
    if vendor_detections:
        for line in vendor_detections:
            pdf.cell(200, 8, txt=f"- {line}", ln=True)
    else:
        pdf.cell(200, 8, txt="- No malicious detections reported.", ln=True)

    # Save
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)
    return output_path

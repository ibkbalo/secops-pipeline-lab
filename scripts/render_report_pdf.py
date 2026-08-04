#!/usr/bin/env python3
"""Render a simple Markdown report to PDF (headings, bullets, tables, code blocks)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from fpdf import FPDF


class ReportPDF(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, "Sentinel Stacks | Security Engineer Hands P1-P7", align="C")
        self.ln(10)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


def _strip_md_inline(text: str) -> str:
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[(.+?)\]\(.+?\)", r"\1", text)
    return _ascii_safe(text.strip())


def _ascii_safe(text: str) -> str:
    """Helvetica core fonts are latin-1 only — normalize common Unicode punctuation."""
    repl = {
        "\u2014": "-",
        "\u2013": "-",
        "\u2192": "->",
        "\u2022": "*",
        "\u201c": '"',
        "\u201d": '"',
        "\u2018": "'",
        "\u2019": "'",
        "\u2190": "<-",
        "\u2502": "|",
        "\u25bc": "v",
        "\u2500": "-",
        "\u251c": "+",
        "\u2514": "+",
        "\u250c": "+",
        "\u2510": "+",
    }
    for src, dst in repl.items():
        text = text.replace(src, dst)
    return text.encode("ascii", "replace").decode("ascii")


def render_md_to_pdf(md_path: Path, pdf_path: Path) -> None:
    lines = md_path.read_text(encoding="utf-8").splitlines()
    pdf = ReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    pdf.set_margins(18, 18, 18)

    in_code = False
    code_buf: list[str] = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()

        if line.strip().startswith("```"):
            if not in_code:
                in_code = True
                code_buf = []
            else:
                in_code = False
                pdf.set_x(pdf.l_margin)
                pdf.set_font("Courier", "", 8)
                pdf.set_fill_color(245, 245, 245)
                block = _ascii_safe("\n".join(code_buf))
                pdf.multi_cell(0, 4.5, block, fill=True)
                pdf.ln(2)
                code_buf = []
            i += 1
            continue

        if in_code:
            code_buf.append(line)
            i += 1
            continue

        if not line.strip():
            pdf.ln(3)
            i += 1
            continue

        if re.match(r"^-{3,}$", line.strip()):
            pdf.ln(2)
            y = pdf.get_y()
            pdf.set_draw_color(200, 200, 200)
            pdf.line(18, y, pdf.w - 18, y)
            pdf.ln(4)
            i += 1
            continue

        if line.startswith("# "):
            pdf.ln(2)
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 16)
            pdf.set_text_color(20, 20, 20)
            pdf.multi_cell(0, 8, _strip_md_inline(line[2:]))
            pdf.ln(2)
            i += 1
            continue

        if line.startswith("## "):
            pdf.ln(2)
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(30, 30, 30)
            pdf.multi_cell(0, 7, _strip_md_inline(line[3:]))
            pdf.ln(1)
            i += 1
            continue

        if line.startswith("### "):
            pdf.ln(1)
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(40, 40, 40)
            pdf.multi_cell(0, 6, _strip_md_inline(line[4:]))
            pdf.ln(1)
            i += 1
            continue

        if line.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[-:\s|]+\|$", lines[i + 1].strip()):
            headers = [c.strip() for c in line.strip("|").split("|")]
            i += 2
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append([_strip_md_inline(c.strip()) for c in lines[i].strip("|").split("|")])
                i += 1
            ncols = max(len(headers), 1)
            usable = pdf.w - pdf.l_margin - pdf.r_margin
            col_w = usable / ncols
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 7)
            for h in headers:
                pdf.cell(col_w, 6, h[:32], border=1)
            pdf.ln()
            pdf.set_font("Helvetica", "", 7)
            for row in rows:
                pdf.set_x(pdf.l_margin)
                for j, cell in enumerate(row):
                    w = col_w if j < ncols else col_w
                    pdf.cell(w, 6, cell[:36], border=1)
                pdf.ln()
            pdf.ln(2)
            continue

        if line.lstrip().startswith("- ") or line.lstrip().startswith("* "):
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(30, 30, 30)
            indent = "  " * ((len(line) - len(line.lstrip())) // 2)
            bullet = _strip_md_inline(line.lstrip()[2:])
            pdf.multi_cell(0, 5, f"{indent}* {bullet}")
            i += 1
            continue

        if line.lstrip().startswith(">"):
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(80, 80, 80)
            pdf.multi_cell(0, 5, _strip_md_inline(line.lstrip().lstrip("> ").strip()))
            i += 1
            continue

        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(30, 30, 30)
        pdf.multi_cell(0, 5, _strip_md_inline(line))
        i += 1

    pdf.output(str(pdf_path))


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: python scripts/render_report_pdf.py <input.md> <output.pdf>")
        sys.exit(1)
    md_path = Path(sys.argv[1])
    pdf_path = Path(sys.argv[2])
    render_md_to_pdf(md_path, pdf_path)
    print(f"Wrote {pdf_path}")


if __name__ == "__main__":
    main()

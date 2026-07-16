"""HexaCore reporting engine (Brain/01 §3.7). Turns an EngagementReport into a branded
client-ready document: HTML, PDF (xhtml2pdf, pure-Python), and DOCX (python-docx).
"""
from .report import build_docx, build_html, build_pdf, render

__all__ = ["build_html", "build_pdf", "build_docx", "render"]

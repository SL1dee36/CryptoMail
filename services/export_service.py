# Description: Export service for archiving messages into JSON and PDF formats with Cyrillic font support.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import datetime
import io
import json
import os
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session
from models.message import Message
from models.user import User
from services.message_service import decrypt_message_content

# Register Russian Cyrillic Font
FONT_NAME = "Helvetica"
CYRILLIC_FONT_PATH = "C:\\Windows\\Fonts\\arial.ttf"
if os.path.exists(CYRILLIC_FONT_PATH):
    try:
        pdfmetrics.registerFont(TTFont("ArialRussian", CYRILLIC_FONT_PATH))
        FONT_NAME = "ArialRussian"
    except Exception:
        pass


def collect_user_messages_data(db: Session, user: User) -> List[Dict[str, Any]]:
    """Gathers all messages for the user with both encrypted and decrypted representations."""
    msgs = db.query(Message).filter(
        (Message.sender_id == user.id) | (Message.recipient_id == user.id)
    ).order_by(Message.created_at.desc()).all()

    data = []
    for m in msgs:
        sender = db.query(User).filter(User.id == m.sender_id).first()
        recipient = db.query(User).filter(User.id == m.recipient_id).first()
        decrypted_body, sig_valid, sig_status = decrypt_message_content(db, m, user)

        data.append({
            "id": m.id,
            "timestamp": m.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "sender": sender.username if sender else f"User#{m.sender_id}",
            "sender_email": sender.email if sender else "",
            "recipient": recipient.username if recipient else f"User#{m.recipient_id}",
            "recipient_email": recipient.email if recipient else "",
            "subject": m.subject,
            "encryption_algorithm": m.encryption_type,
            "decrypted_content": decrypted_body or "(Ошибка расшифрования)",
            "encrypted_ciphertext": m.ciphertext,
            "ecp_signature": m.ecp_signature or "",
            "ecp_status": sig_status,
            "ecp_valid": sig_valid,
        })
    return data


def collect_admin_messages_data(db: Session, target_user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Gathers messages for all users or a specific user in decrypted format for Admin."""
    query = db.query(Message)
    if target_user_id:
        query = query.filter((Message.sender_id == target_user_id) | (Message.recipient_id == target_user_id))
    msgs = query.order_by(Message.created_at.desc()).all()

    # Fake admin user context for decryption
    admin_user = User(role="admin", id=999999)

    data = []
    for m in msgs:
        sender = db.query(User).filter(User.id == m.sender_id).first()
        recipient = db.query(User).filter(User.id == m.recipient_id).first()
        decrypted_body, sig_valid, sig_status = decrypt_message_content(db, m, admin_user)

        data.append({
            "id": m.id,
            "timestamp": m.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "sender": sender.username if sender else f"User#{m.sender_id}",
            "recipient": recipient.username if recipient else f"User#{m.recipient_id}",
            "subject": m.subject,
            "encryption_algorithm": m.encryption_type,
            "decrypted_content": decrypted_body or "(Не удалось расшифровать)",
            "ecp_status": sig_status,
            "ecp_valid": sig_valid,
        })
    return data


def export_to_json_bytes(data: List[Dict[str, Any]], export_title: str) -> bytes:
    payload = {
        "report_title": export_title,
        "exported_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total_messages": len(data),
        "messages": data,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def export_to_pdf_bytes(data: List[Dict[str, Any]], export_title: str, is_user_export: bool = False) -> bytes:
    """Generates styled PDF document with tables, Russian font, and status badges."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName=FONT_NAME,
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=8,
    )
    meta_style = ParagraphStyle(
        "MetaInfo",
        parent=styles["Normal"],
        fontName=FONT_NAME,
        fontSize=9,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=14,
    )
    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName=FONT_NAME,
        fontSize=8,
        leading=10,
    )
    header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName=FONT_NAME,
        fontSize=8,
        leading=10,
        textColor=colors.white,
    )

    elements = [
        Paragraph(export_title, title_style),
        Paragraph(
            f"Сформировано: {datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')} | Всего сообщений: {len(data)}",
            meta_style,
        ),
        Spacer(1, 10),
    ]

    if not data:
        elements.append(Paragraph("В данной выборке нет сообщений.", cell_style))
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

    for item in data:
        sig_color = "#10b981" if item.get("ecp_valid") else "#ef4444"
        table_rows = [
            [
                Paragraph("<b>Параметр</b>", header_style),
                Paragraph("<b>Значение</b>", header_style),
            ],
            [Paragraph("<b>ID / Дата</b>", cell_style), Paragraph(f"#{item['id']} от {item['timestamp']}", cell_style)],
            [Paragraph("<b>Отправитель &rarr; Получатель</b>", cell_style), Paragraph(f"{item['sender']} &rarr; {item['recipient']}", cell_style)],
            [Paragraph("<b>Тема</b>", cell_style), Paragraph(item.get("subject", "(Без темы)"), cell_style)],
            [Paragraph("<b>Шифрование</b>", cell_style), Paragraph(item.get("encryption_algorithm", "-"), cell_style)],
            [
                Paragraph("<b>Статус ЭЦП</b>", cell_style),
                Paragraph(f"<font color='{sig_color}'><b>{item.get('ecp_status', '-')}</b></font>", cell_style),
            ],
            [Paragraph("<b>Расшифрованный текст</b>", cell_style), Paragraph(item.get("decrypted_content", ""), cell_style)],
        ]

        if is_user_export and "encrypted_ciphertext" in item:
            ct_sample = item["encrypted_ciphertext"]
            if len(ct_sample) > 200:
                ct_sample = ct_sample[:200] + "... [сокращено]"
            table_rows.append([
                Paragraph("<b>Шифротекст (исходный)</b>", cell_style),
                Paragraph(f"<font color='#6b7280'>{ct_sample}</font>", cell_style),
            ])

        t = Table(table_rows, colWidths=[140, 400])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 14))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()

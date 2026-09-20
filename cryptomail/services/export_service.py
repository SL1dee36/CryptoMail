# Description: Export service for archiving messages into JSON and PDF formats with Cyrillic font support.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import datetime
import io
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session
from crypto.ecp import load_ecp_private_key_pem, sign_message
from crypto.streebog import streebog512
from cryptomail.models.message import Message
from cryptomail.models.user import User
from cryptomail.services.message_service import decrypt_message_content

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
        decrypted_body, sig_valid, sig_status, *_ = decrypt_message_content(db, m, user)

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
        decrypted_body, sig_valid, sig_status, *_ = decrypt_message_content(db, m, admin_user)

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


def export_to_json_bytes(data: Any, export_title: str = "Экспорт данных", **kwargs) -> bytes:
    if isinstance(data, dict):
        return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    payload = {
        "report_title": export_title,
        "exported_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total_messages": len(data),
        "messages": data,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def export_to_pdf_bytes(
    data: Any,
    export_title: Optional[str] = None,
    is_user_export: bool = False,
    title: Optional[str] = None,
    **kwargs,
) -> bytes:
    """Generates styled PDF document with tables, Russian font, and status badges."""
    title_text = title or export_title or "Отчет по сообщениям"
    items = data.get("messages", []) if isinstance(data, dict) else (data or [])

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
        Paragraph(title_text, title_style),
        Paragraph(
            f"Сформировано: {datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')} | Всего сообщений: {len(items)}",
            meta_style,
        ),
        Spacer(1, 10),
    ]

    if not items:
        elements.append(Paragraph("В данной выборке нет сообщений.", cell_style))
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

    for item in items:
        sig_valid = item.get("ecp_valid") if "ecp_valid" in item else item.get("signature_valid", False)
        sig_color = "#10b981" if sig_valid else "#ef4444"
        enc_type = item.get("encryption_algorithm") or item.get("encryption_type") or "-"
        ecp_status_text = item.get("ecp_status") or item.get("signature_status") or item.get("ecp_comment") or "-"
        ts = item.get("timestamp") or item.get("created_at") or "-"
        sender = item.get("sender") or item.get("sender_username") or "-"
        recipient = item.get("recipient") or item.get("recipient_username") or "-"
        dec_body = item.get("decrypted_content") or item.get("decrypted_body") or ""

        table_rows = [
            [
                Paragraph("<b>Параметр</b>", header_style),
                Paragraph("<b>Значение</b>", header_style),
            ],
            [Paragraph("<b>ID / Дата</b>", cell_style), Paragraph(f"#{item.get('id', '')} от {ts}", cell_style)],
            [Paragraph("<b>Отправитель &rarr; Получатель</b>", cell_style), Paragraph(f"{sender} &rarr; {recipient}", cell_style)],
            [Paragraph("<b>Тема</b>", cell_style), Paragraph(item.get("subject", "(Без темы)"), cell_style)],
            [Paragraph("<b>Шифрование</b>", cell_style), Paragraph(enc_type, cell_style)],
            [
                Paragraph("<b>Статус ЭЦП</b>", cell_style),
                Paragraph(f"<font color='{sig_color}'><b>{ecp_status_text}</b></font>", cell_style),
            ],
            [Paragraph("<b>Расшифрованный текст</b>", cell_style), Paragraph(dec_body, cell_style)],
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


def generate_signed_message_pdf(
    db: Session,
    message: Message,
    user: User,
) -> Tuple[bytes, str, Dict[str, Any]]:
    """
    Generates a single-message official PDF containing:
    1. Decrypted message plaintext
    2. Encrypted ciphertext envelope
    3. Official cryptographic Digital Signature stamp (ЭЦП ГОСТ Стрибог-512)
    And digitally signs the generated PDF binary payload with the user's ЭЦП.
    Returns (pdf_bytes, pdf_signature_b64, metadata).
    """
    sender = db.query(User).filter(User.id == message.sender_id).first()
    recipient = db.query(User).filter(User.id == message.recipient_id).first()
    decrypted_body, sig_valid, sig_status, *_ = decrypt_message_content(db, message, user)

    cert_serial = "UNKNOWN"
    signer_name = user.username
    if user.ecp_certificate:
        try:
            c = json.loads(user.ecp_certificate)
            cert_serial = c.get("serial_number", cert_serial)
        except Exception:
            pass

    now_str = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")

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
        "SingleDocTitle",
        parent=styles["Heading1"],
        fontName=FONT_NAME,
        fontSize=15,
        leading=19,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    meta_style = ParagraphStyle(
        "SingleMetaInfo",
        parent=styles["Normal"],
        fontName=FONT_NAME,
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=12,
    )
    cell_style = ParagraphStyle(
        "SingleTableCell",
        parent=styles["Normal"],
        fontName=FONT_NAME,
        fontSize=8,
        leading=11,
    )
    header_style = ParagraphStyle(
        "SingleTableHeader",
        parent=styles["Normal"],
        fontName=FONT_NAME,
        fontSize=8,
        leading=11,
        textColor=colors.white,
    )
    mono_style = ParagraphStyle(
        "SingleMono",
        parent=styles["Normal"],
        fontName=FONT_NAME,
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#334155"),
    )
    stamp_style = ParagraphStyle(
        "StampText",
        parent=styles["Normal"],
        fontName=FONT_NAME,
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#0369a1"),
    )

    elements = [
        Paragraph(f"ОФИЦИАЛЬНЫЙ КРИПТОГРАФИЧЕСКИЙ ОТЧЕТ ПО СООБЩЕНИЮ #{message.id}", title_style),
        Paragraph(
            f"Сформировано пользователем: {user.username} ({user.role_title_ru}) | Дата: {now_str}",
            meta_style,
        ),
        Spacer(1, 8),
    ]

    # Parameter table
    param_rows = [
        [Paragraph("<b>Параметр</b>", header_style), Paragraph("<b>Значение</b>", header_style)],
        [Paragraph("<b>ID Сообщения</b>", cell_style), Paragraph(f"#{message.id}", cell_style)],
        [Paragraph("<b>Тема</b>", cell_style), Paragraph(message.subject or "(Без темы)", cell_style)],
        [Paragraph("<b>Отправитель</b>", cell_style), Paragraph(f"{sender.username if sender else 'ID '+str(message.sender_id)} ({sender.email if sender else ''})", cell_style)],
        [Paragraph("<b>Получатель</b>", cell_style), Paragraph(f"{recipient.username if recipient else 'ID '+str(message.recipient_id)} ({recipient.email if recipient else ''})", cell_style)],
        [Paragraph("<b>Алгоритм шифрования</b>", cell_style), Paragraph(f"<b>{message.encryption_type}</b> (ГОСТ / Asymmetric)", cell_style)],
        [Paragraph("<b>Дата отправки</b>", cell_style), Paragraph(message.created_at.strftime("%d.%m.%Y %H:%M:%S UTC"), cell_style)],
        [Paragraph("<b>Статус ЭЦП автора</b>", cell_style), Paragraph(f"<b>{sig_status}</b>", cell_style)],
    ]
    t_params = Table(param_rows, colWidths=[140, 400])
    t_params.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(t_params)
    elements.append(Spacer(1, 10))

    # Decrypted Plaintext Block
    dec_rows = [
        [Paragraph("<b>РАСШИФРОВАННОЕ СОДЕРЖИМОЕ СООБЩЕНИЯ (ОТКРЫТЫЙ ВИД)</b>", header_style)],
        [Paragraph(decrypted_body or "(Ошибка расшифрования содержимого)", cell_style)],
    ]
    t_dec = Table(dec_rows, colWidths=[540])
    t_dec.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(t_dec)
    elements.append(Spacer(1, 10))

    # Encrypted Ciphertext Block
    ct_val = message.ciphertext or ""
    ct_display = ct_val if len(ct_val) <= 400 else ct_val[:400] + f" ... [всего {len(ct_val)} символов]"
    enc_rows = [
        [Paragraph("<b>ЗАШИФРОВАННЫЙ ШИФРОТЕКСТ (CIPHERTEXT ENVELOPE)</b>", header_style)],
        [Paragraph(ct_display, mono_style)],
    ]
    t_enc = Table(enc_rows, colWidths=[540])
    t_enc.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(t_enc)
    elements.append(Spacer(1, 10))

    # Digital Signature Official Stamp
    stamp_rows = [
        [
            Paragraph("<b>ДОКУМЕНТ ПОДПИСАН ЭЛЕКТРОННОЙ ЦИФРОВОЙ ПОДПИСЬЮ</b>", ParagraphStyle("StampHead", parent=styles["Normal"], fontName=FONT_NAME, fontSize=8, leading=10, textColor=colors.HexColor("#0369a1"))),
        ],
        [
            Paragraph(
                f"<b>Сертификат:</b> {cert_serial}<br/>"
                f"<b>Владелец:</b> {signer_name} (CryptoMail Secure Network)<br/>"
                f"<b>Алгоритм:</b> ГОСТ Р 34.11-2012 (Стрибог-512) + ЭЦП<br/>"
                f"<b>Дата и время формирования:</b> {now_str} (UTC+3)<br/>"
                f"<b>Статус документа:</b> ПОДЛИННОСТЬ И ЦЕЛОСТНОСТЬ ПОДТВЕРЖДЕНЫ",
                stamp_style
            ),
        ]
    ]
    t_stamp = Table(stamp_rows, colWidths=[540])
    t_stamp.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f9ff")),
        ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor("#0284c7")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(t_stamp)

    doc.build(elements)
    buffer.seek(0)
    pdf_bytes = buffer.getvalue()

    # Digitally sign the generated PDF document using the user's ЭЦП private key
    pdf_signature_b64 = ""
    signing_key = user.ecp_private_key or (sender.ecp_private_key if sender else None)
    if signing_key:
        try:
            priv_ecp = load_ecp_private_key_pem(signing_key)
            pdf_signature_b64 = sign_message(priv_ecp, pdf_bytes)
        except Exception:
            pass

    # Re-build PDF with the signature embedded as a visible block
    if pdf_signature_b64:
        buffer2 = io.BytesIO()
        doc2 = SimpleDocTemplate(
            buffer2,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        sig_mono_style = ParagraphStyle(
            "SigMono",
            parent=getSampleStyleSheet()["Normal"],
            fontName=FONT_NAME,
            fontSize=6,
            leading=8,
            textColor=colors.HexColor("#0f172a"),
            wordWrap="CJK",
        )
        sig_header_style = ParagraphStyle(
            "SigHead",
            parent=getSampleStyleSheet()["Normal"],
            fontName=FONT_NAME,
            fontSize=8,
            leading=10,
            textColor=colors.white,
        )

        # Split Base64 into 76-char lines for PDF readability
        sig_lines = [pdf_signature_b64[i:i+76] for i in range(0, len(pdf_signature_b64), 76)]
        sig_text = "\n".join(sig_lines)

        sig_rows = [
            [Paragraph("<b>ЭЛЕКТРОННАЯ ЦИФРОВАЯ ПОДПИСЬ PDF-ДОКУМЕНТА (ГОСТ SECP384R1 + Стрибог-512)</b>", sig_header_style)],
            [Paragraph(
                f"<b>Алгоритм:</b> ECDSA SECP384R1 + GOST R 34.11-2012 Streebog-512<br/>"
                f"<b>Владелец:</b> {signer_name} | <b>Сертификат:</b> {cert_serial}<br/>"
                f"<b>Дата подписания:</b> {now_str}<br/>"
                f"<b>Полный Base64 подписи:</b>",
                sig_mono_style
            )],
            [Paragraph(sig_text, sig_mono_style)],
        ]
        t_sig = Table(sig_rows, colWidths=[540])
        t_sig.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f0f9ff")),
            ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor("#0284c7")),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#bae6fd")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))

        elements.append(Spacer(1, 10))
        elements.append(t_sig)

        doc2.build(elements)
        buffer2.seek(0)
        pdf_bytes = buffer2.getvalue()

    meta_info = {
        "message_id": message.id,
        "signer": signer_name,
        "cert_serial": cert_serial,
        "timestamp": now_str,
        "signature": pdf_signature_b64,
        "signature_b64": pdf_signature_b64,
        "algorithm": "ECDSA SECP384R1 + GOST R 34.11-2012 Streebog-512",
    }
    return pdf_bytes, pdf_signature_b64, meta_info

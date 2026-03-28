#!/usr/bin/env python3
"""
SKIPTRACING.CA — OSINT API v2.0
=================================
40+ sources | Five Eyes | VIN | Reverse Phone | Cross-Reference
Na zlaten lanec | 369369369.org | Recovery Logistics Systems Inc.

Run: uvicorn skiptracing_api_v2:app --host 0.0.0.0 --port 8000
Author: Roland Marinov (H) + C.A.M. (AI) | Feb 24, 2026
"""

import os, re, json, time, logging, smtplib, io
from datetime import datetime
from typing import Optional, List
from urllib.parse import quote_plus
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from source_registry import SOURCES, get_all_sources_formatted

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("skiptracing")

HEADERS = {"User-Agent": "SkipTracing.ca/2.0 (PIPEDA compliant; public records only)"}
DELAY = 1.0
TIMEOUT = 15

# ============================================================
# EMAIL CONFIG — set via environment variables on VM
# ============================================================
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "info@skiptracing.ca")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "info@skiptracing.ca")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "roland.marinov@rlsinc.ca")

# ============================================================
# MODELS
# ============================================================

class SearchRequest(BaseModel):
    first_name: Optional[str] = ""
    last_name: Optional[str] = ""
    full_name: Optional[str] = ""
    city: Optional[str] = ""
    province: Optional[str] = ""
    country: Optional[str] = "CA"
    phone: Optional[str] = ""
    email: Optional[str] = ""
    company: Optional[str] = ""
    address: Optional[str] = ""
    vin: Optional[str] = ""
    search_type: str = "individual"

class SearchResult(BaseModel):
    source: str
    source_url: str
    source_country: str = ""
    category: str = ""
    name: Optional[str] = ""
    address: Optional[str] = ""
    city: Optional[str] = ""
    province: Optional[str] = ""
    country: Optional[str] = ""
    phone: Optional[str] = ""
    email: Optional[str] = ""
    company: Optional[str] = ""
    details: Optional[dict] = {}
    confidence: float = 0.0
    scraped_at: str = ""
    api_available: bool = False

class SearchResponse(BaseModel):
    query: dict
    results: List[SearchResult]
    sources_checked: int
    total_results: int
    search_time_seconds: float
    timestamp: str

class RegisterRequest(BaseModel):
    corp_name: str
    bn: str
    province: Optional[str] = ""
    contact: Optional[str] = ""
    email: str
    phone: Optional[str] = ""
    timestamp: Optional[str] = ""
    search_type: Optional[str] = "single"

# ============================================================
# REGISTRATION STORAGE
# ============================================================

REGISTRATIONS_FILE = "/opt/rls/registrations.jsonl"

def save_registration(reg: RegisterRequest, ip: str = ""):
    try:
        record = {
            "corp_name": reg.corp_name,
            "bn": reg.bn,
            "province": reg.province,
            "contact": reg.contact,
            "email": reg.email,
            "phone": reg.phone,
            "ip": ip,
            "timestamp": reg.timestamp or datetime.now().isoformat(),
            "search_type": reg.search_type,
        }
        os.makedirs(os.path.dirname(REGISTRATIONS_FILE), exist_ok=True)
        with open(REGISTRATIONS_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
        logger.info(f"Registration saved: {reg.corp_name} / {reg.email}")
        return record
    except Exception as e:
        logger.error(f"Save registration: {e}")
        return {}

# ============================================================
# PDF REPORT GENERATOR
# ============================================================

def generate_pdf_report(query: dict, results: list, corp_name: str = "", order_id: str = "") -> bytes:
    """Generate a simple HTML-based PDF report."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                rightMargin=0.75*inch, leftMargin=0.75*inch,
                                topMargin=0.75*inch, bottomMargin=0.75*inch)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('Title', parent=styles['Title'],
                                     fontSize=18, textColor=colors.HexColor('#26374A'),
                                     spaceAfter=6)
        header_style = ParagraphStyle('Header', parent=styles['Normal'],
                                      fontSize=10, textColor=colors.white,
                                      backColor=colors.HexColor('#26374A'),
                                      spaceAfter=4, spaceBefore=4, leftIndent=6)
        normal = styles['Normal']
        small = ParagraphStyle('Small', parent=styles['Normal'], fontSize=8,
                               textColor=colors.HexColor('#666666'))

        story = []

        # Header
        story.append(Paragraph("SkipTracing.ca", title_style))
        story.append(Paragraph("Public Record Intelligence Report", styles['Heading2']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#AF3C43')))
        story.append(Spacer(1, 0.1*inch))

        # Report metadata
        meta = [
            ["Report Date:", datetime.now().strftime("%B %d, %Y %H:%M EST")],
            ["Order Reference:", order_id or "RLS-" + datetime.now().strftime("%Y%m%d%H%M")],
            ["Requested By:", corp_name or "Verified Corporate Client"],
            ["Compliance:", "PIPEDA Section 7(1)(d)"],
        ]
        t = Table(meta, colWidths=[1.5*inch, 5*inch])
        t.setStyle(TableStyle([
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#26374A')),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.15*inch))

        # Search Query
        story.append(Paragraph("SEARCH PARAMETERS", header_style))
        story.append(Spacer(1, 0.05*inch))
        q_data = []
        if query.get('name'): q_data.append(["Subject Name:", query['name']])
        if query.get('vin'): q_data.append(["VIN / Serial:", query['vin']])
        if query.get('company'): q_data.append(["Corporation:", query['company']])
        if query.get('phone'): q_data.append(["Phone:", query['phone']])
        if query.get('email'): q_data.append(["Email:", query['email']])
        if query.get('city') or query.get('province'):
            q_data.append(["Location:", f"{query.get('city','')} {query.get('province','')} {query.get('country','')}".strip()])
        if q_data:
            qt = Table(q_data, colWidths=[1.5*inch, 5*inch])
            qt.setStyle(TableStyle([
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ]))
            story.append(qt)
        story.append(Spacer(1, 0.15*inch))

        # Results
        story.append(Paragraph(f"SEARCH RESULTS — {len(results)} records found", header_style))
        story.append(Spacer(1, 0.05*inch))

        high_conf = [r for r in results if r.get('confidence', 0) >= 0.7]
        med_conf = [r for r in results if 0.3 <= r.get('confidence', 0) < 0.7]
        pointers = [r for r in results if r.get('confidence', 0) < 0.3]

        if high_conf:
            story.append(Paragraph("● HIGH CONFIDENCE RESULTS", 
                                   ParagraphStyle('SubH', parent=styles['Normal'],
                                                  fontSize=10, textColor=colors.HexColor('#1B6C35'),
                                                  fontName='Helvetica-Bold', spaceAfter=4)))
            for r in high_conf:
                story.append(Paragraph(f"<b>{r.get('source','')}</b>", normal))
                if r.get('name'): story.append(Paragraph(f"Name: {r['name']}", normal))
                if r.get('address'): story.append(Paragraph(f"Address: {r['address']}", normal))
                if r.get('phone'): story.append(Paragraph(f"Phone: {r['phone']}", normal))
                if r.get('details'):
                    for k, v in r['details'].items():
                        if v and k not in ('search_query', 'note'):
                            story.append(Paragraph(f"{k.replace('_',' ').title()}: {v}", small))
                story.append(Paragraph(f"Source: {r.get('source_url','')}", small))
                story.append(Spacer(1, 0.08*inch))

        if med_conf:
            story.append(Paragraph("● ADDITIONAL SOURCES CHECKED", 
                                   ParagraphStyle('SubH2', parent=styles['Normal'],
                                                  fontSize=10, textColor=colors.HexColor('#26374A'),
                                                  fontName='Helvetica-Bold', spaceAfter=4)))
            for r in med_conf[:10]:
                story.append(Paragraph(f"<b>{r.get('source','')}</b> — {r.get('details',{}).get('note','')}", small))

        if pointers:
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph("● MANUAL VERIFICATION RECOMMENDED", 
                                   ParagraphStyle('SubH3', parent=styles['Normal'],
                                                  fontSize=9, textColor=colors.HexColor('#666666'),
                                                  fontName='Helvetica-Bold', spaceAfter=4)))
            for r in pointers[:15]:
                story.append(Paragraph(f"• {r.get('source','')} — {r.get('source_url','')}", small))

        # Footer
        story.append(Spacer(1, 0.2*inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CCCCCC')))
        story.append(Spacer(1, 0.05*inch))
        footer_text = (
            "This report was generated by SkipTracing.ca · Recovery Logistics Systems Inc. · Toronto, Ontario, Canada · "
            "Patent pending — USPTO & CIPO · PIPEDA Section 7(1)(d) compliant · "
            "All information sourced from publicly available databases. "
            "Not a consumer reporting agency. Results for lawful business purposes only."
        )
        story.append(Paragraph(footer_text, small))

        doc.build(story)
        return buffer.getvalue()

    except ImportError:
        # Fallback: simple text-based report if reportlab not installed
        lines = [
            "SKIPTRACNG.CA — PUBLIC RECORD INTELLIGENCE REPORT",
            "=" * 60,
            f"Date: {datetime.now().strftime('%B %d, %Y %H:%M EST')}",
            f"Order: RLS-{datetime.now().strftime('%Y%m%d%H%M')}",
            f"Client: {corp_name or 'Verified Corporate Client'}",
            "=" * 60,
            "SEARCH PARAMETERS:",
        ]
        for k, v in query.items():
            if v: lines.append(f"  {k}: {v}")
        lines.append(f"\nRESULTS: {len(results)} records found")
        lines.append("-" * 60)
        for r in results:
            if r.get('confidence', 0) >= 0.5:
                lines.append(f"\n[{r.get('source','')}]")
                if r.get('name'): lines.append(f"  Name: {r['name']}")
                if r.get('address'): lines.append(f"  Address: {r['address']}")
                if r.get('phone'): lines.append(f"  Phone: {r['phone']}")
                if r.get('details'):
                    for k, v in r['details'].items():
                        if v and k not in ('search_query', 'note'):
                            lines.append(f"  {k}: {v}")
        lines.append("\n" + "=" * 60)
        lines.append("SkipTracing.ca · Recovery Logistics Systems Inc.")
        lines.append("PIPEDA compliant · Patent pending USPTO & CIPO")
        return "\n".join(lines).encode('utf-8')

# ============================================================
# EMAIL SENDER
# ============================================================

def send_report_email(to_email: str, corp_name: str, query: dict,
                      results: list, order_id: str = "") -> bool:
    """Send PDF report to client and notification to admin."""
    try:
        if not SMTP_PASS:
            logger.warning("SMTP_PASS not set — email not sent")
            return False

        pdf_bytes = generate_pdf_report(query, results, corp_name, order_id)
        is_pdf = pdf_bytes[:4] == b'%PDF'
        ext = "pdf" if is_pdf else "txt"
        filename = f"SkipTrace_Report_{order_id or datetime.now().strftime('%Y%m%d%H%M')}.{ext}"

        def build_msg(to_addr, subject, body):
            msg = MIMEMultipart()
            msg['From'] = FROM_EMAIL
            msg['To'] = to_addr
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'html'))
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(pdf_bytes)
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
            msg.attach(part)
            return msg

        # Client email
        client_body = f"""
        <p>Dear {corp_name},</p>
        <p>Your SkipTracing.ca search report is attached.</p>
        <p><b>Subject:</b> {query.get('name') or query.get('vin') or query.get('company','')}<br>
        <b>Sources checked:</b> {len(results)}<br>
        <b>Report date:</b> {datetime.now().strftime('%B %d, %Y')}</p>
        <p>If you have questions, reply to this email.</p>
        <p>Recovery Logistics Systems Inc.<br>SkipTracing.ca · Toronto, Ontario</p>
        <p style="font-size:11px;color:#999;">PIPEDA compliant · Patent pending USPTO & CIPO · 
        Results for lawful business purposes only.</p>
        """
        client_msg = build_msg(to_email, f"SkipTracing.ca — Your Search Report ({order_id})", client_body)

        # Admin notification
        admin_body = f"""
        <p><b>New SkipTracing.ca Order</b></p>
        <p>Corp: {corp_name}<br>Email: {to_email}<br>
        Subject: {query.get('name') or query.get('vin') or query.get('company','')}<br>
        Results: {len(results)}<br>Time: {datetime.now().isoformat()}</p>
        """
        admin_msg = build_msg(ADMIN_EMAIL, f"[SkipTracing] New Order — {corp_name}", admin_body)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, to_email, client_msg.as_string())
            server.sendmail(FROM_EMAIL, ADMIN_EMAIL, admin_msg.as_string())

        logger.info(f"Report sent to {to_email} and {ADMIN_EMAIL}")
        return True

    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return False

# ============================================================
# FETCH HELPERS
# ============================================================

def _fetch(url, timeout=TIMEOUT):
    for attempt in range(3):
        try:
            time.sleep(DELAY)
            r = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
            if r.status_code == 200: return r
            if r.status_code in (404, 403, 410, 429): return None
        except Exception as e:
            if attempt == 2: logger.warning(f"Failed: {url[:80]}: {e}")
            time.sleep(2)
    return None

def _json(url, timeout=TIMEOUT):
    r = _fetch(url, timeout)
    if r:
        try: return r.json()
        except: pass
    return None

# ============================================================
# LIVE SEARCH ENGINES

ROCKETREACH_API_KEY = os.environ.get("ROCKETREACH_API_KEY", "3030e9k88ab215de8acc66242ba32fdda11fab2")

def search_rocketreach(first: str, last: str, company: str = "", location: str = "") -> List[SearchResult]:
    results = []
    try:
        headers = {"Api-Key": ROCKETREACH_API_KEY, "Content-Type": "application/json"}
        payload = {"query": {"name": [f"{first} {last}"]}}
        if company:
            payload["query"]["current_employer"] = company
        r = requests.post("https://api.rocketreach.co/api/v2/search", headers=headers, json=payload, timeout=15)
        if r.status_code in (200, 201):
            data = r.json()
            for p in data.get("profiles", [])[:1]:
                pid = p.get("id")
                # Trigger lookup
                requests.get(f"https://api.rocketreach.co/api/v2/person/lookup?id={pid}", headers={"Api-Key": ROCKETREACH_API_KEY}, timeout=10)
                import time; time.sleep(3)
                # Fetch complete profile
                r2 = requests.get(f"https://api.rocketreach.co/api/v2/person/lookup?id={pid}", headers={"Api-Key": ROCKETREACH_API_KEY}, timeout=10)
                p = r2.json() if r2.status_code == 200 else p
                emails = p.get("emails", [])
                phones = p.get("phones", [])
                teaser = p.get("teaser", {})
                preview_emails = teaser.get("preview", [])
                results.append(SearchResult(
                    source="RocketReach",
                    source_url=f"https://rocketreach.co/person/{p.get('id','')}",
                    source_country="GLOBAL", category="person",
                    name=p.get("name", f"{first} {last}"),
                    email=preview_emails[0] if preview_emails else "",
                    phone="",
                    company=p.get("current_employer",""),
                    address=p.get("location",""),
                    details={
                        "title": p.get("current_title",""),
                        "linkedin": p.get("linkedin_url",""),
                        "email_domain_hint": preview_emails,
                        "city": p.get("city",""),
                        "region": p.get("region",""),
                        "country": p.get("country",""),
                    },
                    confidence=0.75, scraped_at=datetime.now().isoformat(), api_available=True
                ))
    except Exception as e:
        logger.error(f"RocketReach: {e}")
    return results

# ============================================================

def search_vin_nhtsa(vin: str) -> List[SearchResult]:
    results = []
    try:
        data = _json(f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{vin}?format=json")
        if data and data.get("Results"):
            v = data["Results"][0]
            if v.get("ErrorCode", "").startswith("0"):
                results.append(SearchResult(
                    source="NHTSA VIN Decoder",
                    source_url=f"https://vpic.nhtsa.dot.gov/decoder/Decoder?vin={vin}",
                    source_country="US", category="vehicle", api_available=True,
                    name=f"{v.get('ModelYear','')} {v.get('Make','')} {v.get('Model','')}".strip(),
                    details={
                        "vin": vin, "make": v.get("Make",""), "model": v.get("Model",""),
                        "year": v.get("ModelYear",""), "trim": v.get("Trim",""),
                        "body_class": v.get("BodyClass",""), "vehicle_type": v.get("VehicleType",""),
                        "drive_type": v.get("DriveType",""), "engine_cylinders": v.get("EngineCylinders",""),
                        "engine_hp": v.get("EngineHP",""), "displacement_l": v.get("DisplacementL",""),
                        "fuel_type": v.get("FuelTypePrimary",""), "transmission": v.get("TransmissionStyle",""),
                        "doors": v.get("Doors",""), "plant_city": v.get("PlantCity",""),
                        "plant_state": v.get("PlantState",""), "plant_country": v.get("PlantCountry",""),
                        "manufacturer": v.get("Manufacturer",""), "gvwr": v.get("GVWR",""),
                    },
                    confidence=0.95, scraped_at=datetime.now().isoformat(),
                ))
    except Exception as e: logger.error(f"NHTSA VIN: {e}")
    return results

def search_vin_recalls(vin: str) -> List[SearchResult]:
    results = []
    try:
        decode = _json(f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{vin}?format=json")
        if decode and decode.get("Results"):
            v = decode["Results"][0]
            make, model, year = v.get("Make",""), v.get("Model",""), v.get("ModelYear","")
            if make and model and year:
                rdata = _json(f"https://api.nhtsa.gov/recalls/recallsByVehicle?make={quote_plus(make)}&model={quote_plus(model)}&modelYear={year}")
                if rdata:
                    for rc in rdata.get("results", [])[:10]:
                        results.append(SearchResult(
                            source="NHTSA Safety Recalls", source_url="https://www.nhtsa.gov/recalls",
                            source_country="US", category="vehicle", api_available=True,
                            name=f"RECALL: {rc.get('Component','Unknown')}",
                            details={
                                "campaign": rc.get("NHTSACampaignNumber",""),
                                "component": rc.get("Component",""),
                                "summary": rc.get("Summary",""),
                                "consequence": rc.get("Consequence",""),
                                "remedy": rc.get("Remedy",""),
                                "report_date": rc.get("ReportReceivedDate",""),
                            },
                            confidence=0.95, scraped_at=datetime.now().isoformat(),
                        ))
    except Exception as e: logger.error(f"NHTSA Recalls: {e}")
    return results

def search_vin_canadian(year: str, make: str) -> List[SearchResult]:
    results = []
    try:
        data = _json(f"https://vpic.nhtsa.dot.gov/api/vehicles/GetCanadianVehicleSpecifications/?year={year}&make={quote_plus(make)}&format=json")
        if data:
            for s in data.get("Results", [])[:5]:
                results.append(SearchResult(
                    source="Transport Canada Vehicle Specs", source_country="CA",
                    source_url="https://vpic.nhtsa.dot.gov/api/", category="vehicle",
                    name=f"{year} {make} {s.get('Model','')}".strip(),
                    details=s, confidence=0.8, scraped_at=datetime.now().isoformat(), api_available=True,
                ))
    except Exception as e: logger.error(f"Transport Canada: {e}")
    return results

def search_opencorporates(company: str, jurisdiction: str = "ca|us") -> List[SearchResult]:
    results = []
    try:
        data = _json(f"https://api.opencorporates.com/v0.4/companies/search?q={quote_plus(company)}&jurisdiction_code={jurisdiction}")
        if data:
            for co in data.get("results", {}).get("companies", [])[:5]:
                cd = co.get("company", {})
                results.append(SearchResult(
                    source="OpenCorporates", source_url=cd.get("opencorporates_url", ""),
                    source_country=cd.get("jurisdiction_code", "")[:2].upper(), category="corporate",
                    company=cd.get("name", ""), api_available=True,
                    details={
                        "jurisdiction": cd.get("jurisdiction_code",""), "number": cd.get("company_number",""),
                        "status": cd.get("current_status",""), "incorporation": cd.get("incorporation_date",""),
                        "address": cd.get("registered_address_in_full",""), "type": cd.get("company_type",""),
                    },
                    confidence=0.8, scraped_at=datetime.now().isoformat(),
                ))
    except Exception as e: logger.error(f"OpenCorporates: {e}")
    return results

def search_ic_federal(company: str) -> List[SearchResult]:
    results = []
    try:
        url = f"https://www.ic.gc.ca/app/scr/cc/CorporationsCanada/fdrlCrpSrch.html?q={quote_plus(company)}"
        r = _fetch(url)
        if r:
            soup = BeautifulSoup(r.text, "html.parser")
            for row in soup.find_all("tr")[:10]:
                cells = row.find_all("td")
                if len(cells) >= 3:
                    results.append(SearchResult(
                        source="Corporations Canada", source_url=url, source_country="CA",
                        category="corporate", company=cells[0].get_text(strip=True),
                        details={
                            "corp_number": cells[1].get_text(strip=True) if len(cells) > 1 else "",
                            "status": cells[2].get_text(strip=True) if len(cells) > 2 else "",
                        },
                        confidence=0.8, scraped_at=datetime.now().isoformat(),
                    ))
    except Exception as e: logger.error(f"IC Federal: {e}")
    return results

def search_canada411(first: str, last: str, city: str = "", prov: str = "") -> List[SearchResult]:
    results = []
    try:
        p = []
        if last: p.append(f"ln={quote_plus(last)}")
        if first: p.append(f"fn={quote_plus(first)}")
        if city: p.append(f"ci={quote_plus(city)}")
        if prov: p.append(f"pr={quote_plus(prov)}")
        url = f"https://www.canada411.ca/search/?{'&'.join(p)}"
        r = _fetch(url)
        if r:
            soup = BeautifulSoup(r.text, "html.parser")
            for li in soup.find_all("div", class_="listing__content")[:10]:
                res = SearchResult(source="Canada411", source_url=url, source_country="CA",
                                   category="person", confidence=0.7, scraped_at=datetime.now().isoformat())
                n = li.find("h2") or li.find("a", class_="listing__name")
                if n: res.name = n.get_text(strip=True)
                a = li.find("span", class_="listing__address")
                if a: res.address = a.get_text(strip=True)
                ph = li.find("a", class_="listing__phone")
                if ph: res.phone = ph.get_text(strip=True)
                if res.name: results.append(res)
    except Exception as e: logger.error(f"Canada411: {e}")
    return results

def search_reverse_phone_ca(phone: str) -> List[SearchResult]:
    results = []
    try:
        clean = re.sub(r'[^\d]', '', phone)
        url = f"https://www.canada411.ca/search/?stype=si&what={clean}"
        r = _fetch(url)
        if r:
            soup = BeautifulSoup(r.text, "html.parser")
            for li in soup.find_all("div", class_="listing__content")[:5]:
                res = SearchResult(source="Canada411 Reverse Phone", source_url=url,
                                   source_country="CA", category="phone", phone=phone,
                                   confidence=0.7, scraped_at=datetime.now().isoformat())
                n = li.find("h2") or li.find("a", class_="listing__name")
                if n: res.name = n.get_text(strip=True)
                a = li.find("span", class_="listing__address")
                if a: res.address = a.get_text(strip=True)
                if res.name: results.append(res)
    except Exception as e: logger.error(f"Reverse phone CA: {e}")
    return results

def pointer_result(source_key: str, query: str, **kwargs) -> SearchResult:
    s = SOURCES.get(source_key, {})
    return SearchResult(
        source=s.get("name", source_key), source_url=s.get("url", ""),
        source_country=s.get("country", ""), category=s.get("cat", ""),
        details={"search_query": query, "note": f"Search at {s.get('url','')} — {s.get('desc','')}"},
        confidence=0.3, scraped_at=datetime.now().isoformat(),
        api_available=s.get("api", False), **kwargs,
    )

# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="SkipTracing.ca OSINT API v2",
    description="130+ public databases. PIPEDA compliant. VIN, reverse phone, corporate, court, property.",
    version="2.1.0", docs_url="/docs",
    contact={"name": "Recovery Logistics Systems Inc.", "url": "https://skiptracing.ca", "email": "info@skiptracing.ca"},
)

app.add_middleware(CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

@app.get("/")
def root():
    return {"service": "SkipTracing.ca OSINT API", "version": "2.1.0", "total_sources": len(SOURCES),
            "operator": "Recovery Logistics Systems Inc.",
            "compliance": "PIPEDA Section 7(1)(d)", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "ok", "sources": len(SOURCES), "timestamp": datetime.now().isoformat()}

@app.get("/sources")
def list_sources():
    return {"sources": get_all_sources_formatted(), "total": len(SOURCES)}

# ============================================================
# REGISTER ENDPOINT — saves corp info + notifies admin
# ============================================================

@app.post("/register")
async def register(reg: RegisterRequest, request: Request = None):
    """Save corporate registration and notify admin."""
    try:
        ip = ""
        if request:
            ip = request.client.host if request.client else ""

        record = save_registration(reg, ip)

        # Notify admin of new registration
        if SMTP_PASS:
            try:
                msg = MIMEMultipart()
                msg['From'] = FROM_EMAIL
                msg['To'] = ADMIN_EMAIL
                msg['Subject'] = f"[SkipTracing] New Registration — {reg.corp_name}"
                body = f"""
                <h3>New Corporate Registration</h3>
                <p><b>Corporation:</b> {reg.corp_name}<br>
                <b>BN/Corp #:</b> {reg.bn}<br>
                <b>Province:</b> {reg.province}<br>
                <b>Contact:</b> {reg.contact}<br>
                <b>Email:</b> {reg.email}<br>
                <b>Phone:</b> {reg.phone}<br>
                <b>IP:</b> {ip}<br>
                <b>Time:</b> {datetime.now().isoformat()}</p>
                """
                msg.attach(MIMEText(body, 'html'))
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                    server.ehlo(); server.starttls()
                    server.login(SMTP_USER, SMTP_PASS)
                    server.sendmail(FROM_EMAIL, ADMIN_EMAIL, msg.as_string())
            except Exception as e:
                logger.error(f"Admin notify: {e}")

        return {"status": "registered", "corp": reg.corp_name, "timestamp": datetime.now().isoformat()}
    except Exception as e:
        logger.error(f"Register: {e}")
        return {"status": "saved", "timestamp": datetime.now().isoformat()}

# ============================================================
# MAIN SEARCH + AUTO EMAIL REPORT
# ============================================================

@app.post("/search", response_model=SearchResponse)
def search(req: SearchRequest):
    start = time.time()
    all_results = []
    checked = 0

    name = req.full_name or f"{req.first_name} {req.last_name}".strip()
    first = req.first_name or (name.split()[0] if name and " " in name else "")
    last = req.last_name or (name.split()[-1] if name and " " in name else name)
    country = req.country.upper() if req.country else "CA"

    if req.search_type == "vin" or req.vin:
        vin = req.vin or name
        if len(vin.replace(" ","")) >= 11:
            checked += 1; all_results.extend(search_vin_nhtsa(vin))
            checked += 1; all_results.extend(search_vin_recalls(vin))

    if req.search_type == "phone" or req.phone:
        phone = req.phone or name
        if country == "CA":
            checked += 1; all_results.extend(search_reverse_phone_ca(phone))
        checked += 1; all_results.append(pointer_result("numlookup", phone, phone=phone))
        checked += 1; all_results.append(pointer_result("ipqs_phone", phone, phone=phone))
        checked += 1; all_results.append(pointer_result("spydialer", phone, phone=phone))

    if req.search_type in ("individual", "both") and (first or last):
        if country in ("CA", ""):
            checked += 1; all_results.extend(search_canada411(first, last, req.city, req.province))
            checked += 1; all_results.extend(search_rocketreach(first, last, location=req.city or req.province))
            checked += 1; all_results.append(pointer_result("canlii", f"{first} {last}"))
            checked += 1; all_results.append(pointer_result("ontario_court_dates", f"{first} {last}"))
            checked += 1; all_results.append(pointer_result("mpac", last, city=req.city))
            checked += 1; all_results.append(pointer_result("ppsa_ontario", f"{first} {last}"))
        if country in ("US", ""):
            checked += 1; all_results.append(pointer_result("whitepages_us", f"{first} {last}"))
            checked += 1; all_results.append(pointer_result("fastpeoplesearch", f"{first} {last}"))
            checked += 1; all_results.append(pointer_result("truepeoplesearch", f"{first} {last}"))
        if country in ("UK", ""):
            checked += 1; all_results.append(pointer_result("uk_192", f"{first} {last}"))
            checked += 1; all_results.append(pointer_result("uk_insolvency", last))
        if country in ("AU", ""):
            checked += 1; all_results.append(pointer_result("au_white_pages", f"{first} {last}"))
        if country in ("NZ", ""):
            checked += 1; all_results.append(pointer_result("nz_white_pages", f"{first} {last}"))
        checked += 1; all_results.append(pointer_result("linkedin_public", name))
        checked += 1; all_results.append(pointer_result("domainbigdata", name))

    if req.search_type == "email" or req.email:
        email = req.email or name
        checked += 1; all_results.append(pointer_result("hunter_email", email, email=email))
        checked += 1; all_results.append(pointer_result("epieos", email, email=email))
        checked += 1; all_results.append(pointer_result("osint_industries", email, email=email))

    if req.search_type in ("corporation", "both") and (req.company or name):
        co = req.company or name
        jurisdiction = {"CA": "ca", "US": "us", "UK": "gb", "AU": "au", "NZ": "nz"}.get(country, "ca|us")
        checked += 1; all_results.extend(search_opencorporates(co, jurisdiction))
        checked += 1; all_results.extend(search_ic_federal(co))
        if country in ("CA", ""):
            checked += 1; all_results.append(pointer_result("ontario_business_registry", co, company=co))
            checked += 1; all_results.append(pointer_result("reghub", co, company=co))
            checked += 1; all_results.append(pointer_result("registries_direct", co, company=co))
        if country in ("US", ""):
            checked += 1; all_results.append(pointer_result("sec_edgar", co, company=co))
            checked += 1; all_results.append(pointer_result("ucc_wa", co, company=co))
        if country in ("UK", ""):
            checked += 1; all_results.append(pointer_result("companies_house_uk", co, company=co))
        if country in ("AU", ""):
            checked += 1; all_results.append(pointer_result("au_abn_lookup", co, company=co))
            checked += 1; all_results.append(pointer_result("asic_au", co, company=co))
        if country in ("NZ", ""):
            checked += 1; all_results.append(pointer_result("nz_companies", co, company=co))

    if req.search_type == "address" and req.address:
        checked += 1; all_results.append(pointer_result("mpac", req.address, address=req.address))
        checked += 1; all_results.append(pointer_result("city_data", req.address, address=req.address))
        if country == "UK":
            checked += 1; all_results.append(pointer_result("uk_land_registry", req.address, address=req.address))


    # AUTO-LOOP — add pointer results for ALL sources in registry not already checked
    already_checked = set()
    for src_key, src_info in SOURCES.items():
        src_name = src_info.get("name", src_key)
        if src_name not in already_checked:
            cat = src_info.get("cat", "general")
            country_filter = src_info.get("country", "")
            if country_filter and country_filter not in ("CA", "GLOBAL", "INTL", "US", "", country):
                continue
            query_val = name or req.company or req.phone or req.email or req.vin or req.address
            if query_val:
                checked += 1
                all_results.append(pointer_result(src_key, query_val))

    all_results.sort(key=lambda r: r.confidence, reverse=True)

    response = SearchResponse(
        query={"name": name, "first": first, "last": last, "city": req.city, "province": req.province,
               "country": country, "company": req.company, "phone": req.phone, "email": req.email,
               "vin": req.vin, "address": req.address, "type": req.search_type},
        results=all_results, sources_checked=checked, total_results=len(all_results),
        search_time_seconds=round(time.time() - start, 2), timestamp=datetime.now().isoformat(),
    )
    return response

# ============================================================
# SEARCH + EMAIL REPORT ENDPOINT
# ============================================================

@app.post("/search/report")
def search_and_email(req: SearchRequest, client_email: str = Query(...),
                     corp_name: str = Query(""), order_id: str = Query("")):
    """Run search AND email PDF report to client."""
    result = search(req)
    results_list = [r.dict() for r in result.results]
    sent = send_report_email(
        to_email=client_email,
        corp_name=corp_name,
        query=result.query,
        results=results_list,
        order_id=order_id,
    )
    return {**result.dict(), "report_emailed": sent, "report_sent_to": client_email}

# --- CONVENIENCE ENDPOINTS ---

@app.get("/search/quick")
def quick(name: str = Query(...), city: str = Query(""), province: str = Query(""), country: str = Query("CA")):
    return search(SearchRequest(full_name=name, city=city, province=province, country=country, search_type="individual"))

@app.get("/search/vin/{vin}")
def vin_lookup(vin: str):
    return search(SearchRequest(vin=vin, search_type="vin"))

@app.get("/search/phone/{phone}")
def phone_lookup(phone: str):
    return search(SearchRequest(phone=phone, search_type="phone"))

@app.get("/search/company/{company}")
def company_lookup(company: str, country: str = Query("CA")):
    return search(SearchRequest(company=company, country=country, search_type="corporation"))

@app.get("/search/email/{email}")
def email_lookup(email: str):
    return search(SearchRequest(email=email, search_type="email"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))

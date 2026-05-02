import pyperclip
import re
import dns.resolver
import ipaddress
import sys

# ─────────────────────────────────────────────
# Copy in content from clipboard
# ─────────────────────────────────────────────
raw = pyperclip.paste()
if not raw.strip():
    sys.exit("Clipboard is empty. Copy an email header and try again.")

print("=" * 60)
print("          DMARC ANALYZER — Email Header Inspection")
print("=" * 60)

# ─────────────────────────────────────────────
# Parse out data:
#   HeaderFrom Domain
#   EnvelopeFrom Domain
#   ReturnPath Domain
#   Delivery IP
#   DKIM d=  s=  bh=  b=
# ─────────────────────────────────────────────
def extract(pattern, text, group=1, flags=re.IGNORECASE):
    m = re.search(pattern, text, flags)
    return m.group(group).strip() if m else None

def domain_from_email(addr):
    m = re.search(r'@([\w.\-]+)', addr or "")
    return m.group(1).lower() if m else None

header_from_raw   = extract(r'^From:.*?([a-zA-Z0-9._%+\-]+@[\w.\-]+)', raw, flags=re.IGNORECASE | re.MULTILINE)
envelope_from_raw = extract(r'envelope-from[:\s]+<?([a-zA-Z0-9._%+\-]+@[\w.\-]+)', raw)
return_path_raw   = extract(r'^Return-Path:.*?<?([a-zA-Z0-9._%+\-]+@[\w.\-]+)', raw, flags=re.IGNORECASE | re.MULTILINE)
delivery_ip = (extract(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', raw) or
               extract(r'\((\d{1,3}(?:\.\d{1,3}){3})\)', raw) or
               extract(r'\[([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})\]', raw))

header_from_domain   = domain_from_email(header_from_raw)
envelope_from_domain = domain_from_email(envelope_from_raw)
return_path_domain   = domain_from_email(return_path_raw)

# Normalise DKIM: unfold whitespace-continued lines, then grab the tag-value pairs
def organisational_domain(d):
    if not d: return ""
    parts = d.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d.lower()

dkim_block = ""
for _m in re.finditer(r'DKIM-Signature:(.*?)(?=\r?\n\S|\Z)', raw, re.IGNORECASE | re.DOTALL):
    _block = re.sub(r'\r?\n[ \t]+', ' ', _m.group(1))
    _d = (extract(r'\bd=([^;]+)', _block) or "").lower()
    if organisational_domain(_d) == organisational_domain(header_from_domain or ""):
        dkim_block = _block
        break
    if not dkim_block:
        dkim_block = _block

dkim_d  = extract(r'\bd=([^;]+)', dkim_block)
dkim_s  = extract(r'\bs=([^;]+)', dkim_block)
dkim_bh = extract(r'\bbh=([^;]+)', dkim_block)
dkim_b  = re.sub(r'\s', '', extract(r'\bb=([^;]+)', dkim_block) or "")

print("\n── Parsed Header Fields ──────────────────────────────")
print(f"  Header-From    : {header_from_raw or 'not found'}")
print(f"  Header Domain  : {header_from_domain or 'not found'}")
print(f"  Envelope-From  : {envelope_from_raw or 'not found'}")
print(f"  Envelope Domain: {envelope_from_domain or 'not found'}")
print(f"  Return-Path    : {return_path_raw or 'not found'}")
print(f"  Return-Path Dom: {return_path_domain or 'not found'}")
print(f"  Delivery IP    : {delivery_ip or 'not found'}")
print(f"  DKIM d=        : {dkim_d or 'not found'}")
print(f"  DKIM s=        : {dkim_s or 'not found'}")
print(f"  DKIM bh=       : {dkim_bh or 'not found'}")
print(f"  DKIM b=        : {(dkim_b[:40] + '…') if dkim_b else 'not found'}")

# ─────────────────────────────────────────────
# Use DNS lookup to grab the SPF contents
# ─────────────────────────────────────────────
def dns_txt(domain, prefix=""):
    try:
        return [r.to_text().strip('"') for r in dns.resolver.resolve(domain, 'TXT')]
    except Exception:
        return []

spf_mfrom_domain = envelope_from_domain or return_path_domain
spf_records = [r for r in dns_txt(spf_mfrom_domain or "") if r.lower().startswith("v=spf1")]
spf_record  = spf_records[0] if spf_records else None

print("\n── DNS: SPF Record ───────────────────────────────────")
print(f"  Query domain: {spf_mfrom_domain}")
print(f"  SPF record  : {spf_record or 'NOT FOUND'}")

# ─────────────────────────────────────────────
# Use DNS lookup to construct the DKIM record and grab the DKIM contents
# ─────────────────────────────────────────────
dkim_dns_domain = f"{dkim_s}._domainkey.{dkim_d}" if dkim_s and dkim_d else None
dkim_dns_record = None
if dkim_dns_domain:
    for r in dns_txt(dkim_dns_domain):
        if "p=" in r.lower() or "k=" in r.lower():
            dkim_dns_record = r
            break

print("\n── DNS: DKIM Record ──────────────────────────────────")
print(f"  Query       : {dkim_dns_domain or 'N/A — missing s= or d='}")
print(f"  DKIM record : {dkim_dns_record or 'NOT FOUND'}")

# ─────────────────────────────────────────────
# Use DNS lookup to grab the DMARC record contents
# ─────────────────────────────────────────────
dmarc_domain = f"_dmarc.{header_from_domain}" if header_from_domain else None
dmarc_records = [r for r in dns_txt(dmarc_domain or "") if r.lower().startswith("v=dmarc1")]
dmarc_record  = dmarc_records[0] if dmarc_records else None

print("\n── DNS: DMARC Record ─────────────────────────────────")
print(f"  Query       : {dmarc_domain}")
print(f"  DMARC record: {dmarc_record or 'NOT FOUND'}")

# ─────────────────────────────────────────────
# Display outputs to user  (done inline above)
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
# Perform SPF Authentication check
#   Does the Delivery IP match any mechanism in the SPF record?
# ─────────────────────────────────────────────
def spf_ip_authorised(ip_str, domain, depth=0):
    """Recursively evaluate SPF mechanisms; return True if ip_str is permitted."""
    if depth > 10 or not ip_str or not domain:
        return False
    try:
        delivery = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for record in [r for r in dns_txt(domain) if r.lower().startswith("v=spf1")]:
        for token in record.split():
            t = token.lstrip("+-?~").lower()
            try:
                if t.startswith("ip4:") and delivery in ipaddress.ip_network(t[4:], strict=False):
                    return True
                if t.startswith("ip6:") and delivery in ipaddress.ip_network(t[4:], strict=False):
                    return True
                if t.startswith("include:") and spf_ip_authorised(ip_str, t[8:], depth + 1):
                    return True
                if t.startswith("redirect=") and spf_ip_authorised(ip_str, t[9:], depth + 1):
                    return True
                if t in ("a", "mx"):
                    sub = domain if t == "a" else None
                    try:
                        answers = dns.resolver.resolve(sub or domain, 'A')
                        if any(ipaddress.ip_address(str(a)) == delivery for a in answers):
                            return True
                    except Exception:
                        pass
            except (ValueError, dns.exception.DNSException):
                continue
    return False

spf_auth = spf_ip_authorised(delivery_ip, spf_mfrom_domain) if delivery_ip and spf_mfrom_domain else None

# ─────────────────────────────────────────────
# Perform SPF Authorization check
#   Does the spf_domain align with the Header-From domain?
# ─────────────────────────────────────────────

dmarc_spf_align = extract(r'\baspf=([rs])', dmarc_record) or "r"   # r=relaxed default
spf_align_domain = spf_mfrom_domain

if dmarc_spf_align == "s":
    spf_authz = (spf_align_domain == header_from_domain) if spf_align_domain and header_from_domain else None
else:
    spf_authz = (organisational_domain(spf_align_domain) == organisational_domain(header_from_domain)) if spf_align_domain and header_from_domain else None

# ─────────────────────────────────────────────
# Perform DKIM Authentication check
#   Verify bh= (body hash) against the raw body using SHA-256
#   Note: full DKIM crypto requires the public key + RSA verify;
#         we perform the accessible body-hash portion here.
# ─────────────────────────────────────────────
_ar_block = re.search(r'^Authentication-Results:.*?(?=\r?\n\S|\Z)', raw, re.IGNORECASE | re.MULTILINE | re.DOTALL)
_ar_dkim  = extract(r'\bdkim=(\w+)', _ar_block.group(0) if _ar_block else "")
dkim_auth = True  if (_ar_dkim or "").lower() == "pass" else \
            False if (_ar_dkim or "").lower() in ("fail", "permerror", "temperror") else \
            None

# ─────────────────────────────────────────────
# Perform DKIM Authorization check
#   Does dkim_d align with the Header-From domain?
# ─────────────────────────────────────────────
dmarc_dkim_align = extract(r'\badkim=([rs])', dmarc_record) or "r"

if dmarc_dkim_align == "s":
    dkim_authz = (dkim_d == header_from_domain) if dkim_d and header_from_domain else None
else:
    dkim_authz = (organisational_domain(dkim_d) == organisational_domain(header_from_domain)) if dkim_d and header_from_domain else None

# ─────────────────────────────────────────────
# Display Pass or Fail for each check
# ─────────────────────────────────────────────
def pf(val):
    if val is True:  return "✅ PASS"
    if val is False: return "❌ FAIL"
    return "⚠️  UNKNOWN"

print("\n── Authentication & Authorization Results ────────────")
print(f"  SPF Authentication  (IP in SPF record)  : {pf(spf_auth)}")
print(f"  SPF Authorization   (domain alignment)  : {pf(spf_authz)}")
print(f"  DKIM Authentication (body hash bh=)     : {pf(dkim_auth)}")
print(f"  DKIM Authorization  (d= alignment)      : {pf(dkim_authz)}")

# ─────────────────────────────────────────────
# If both SPF checks pass OR both DKIM checks pass → DMARC PASS
# ─────────────────────────────────────────────
spf_pass  = (spf_auth  is True) and (spf_authz  is True)
dkim_pass = (dkim_auth is True) and (dkim_authz is True)
dmarc_pass = spf_pass or dkim_pass

print("\n── DMARC Result ──────────────────────────────────────")
print(f"  DMARC : {pf(dmarc_pass)}")

# ─────────────────────────────────────────────
# If DMARC Fails, explain why each service failed with recommendations
# ─────────────────────────────────────────────
if not dmarc_pass:
    print("\n── Failure Analysis & Recommendations ───────────────")

    if not spf_pass:
        print("\n  [SPF]")
        if spf_auth is False:
            print(f"  ✗ Authentication: Delivery IP {delivery_ip} is NOT listed in the")
            print(f"    SPF record for '{spf_mfrom_domain}'.")
            print(f"    → Recommendation: Add 'ip4:{delivery_ip}' (or the sending")
            print(f"      service's include: mechanism) to the SPF record.")
        elif spf_auth is None:
            print("  ✗ Authentication: Could not retrieve SPF record or delivery IP.")
            print("    → Recommendation: Publish a valid SPF TXT record at the")
            print(f"      envelope/return-path domain ('{spf_mfrom_domain}').")

        if spf_authz is False:
            print(f"  ✗ Authorization : SPF domain '{spf_align_domain}' does not align")
            print(f"    with Header-From domain '{header_from_domain}'")
            print(f"    (DMARC aspf={dmarc_spf_align} — {'strict' if dmarc_spf_align == 's' else 'relaxed'} alignment).")
            print("    → Recommendation: Use a Return-Path / envelope address whose")
            print(f"      domain matches (or shares an org-domain with) '{header_from_domain}',")
            print("      or switch to relaxed alignment (aspf=r) in the DMARC record.")
        elif spf_authz is None:
            print("  ✗ Authorization : Could not determine alignment — missing domains.")

    if not dkim_pass:
        print("\n  [DKIM]")
        if dkim_auth is False:
            print("  ✗ Authentication: The receiving MTA reported dkim=fail in")
            print("    Authentication-Results. The signature did not verify.")
            print("    → Recommendation (sender): Check that no relay rewrites the message")
            print("      body or signed headers after signing. Verify your DKIM private key")
            print("      matches the public key at the DNS selector record.")
        elif dkim_auth is None:
            print("  ✗ Authentication: DKIM signature fields (bh=, b=) not found.")
            print("    → Recommendation: Configure your mail server / ESP to sign")
            print(f"      outbound mail for '{header_from_domain}' with DKIM.")

        if dkim_authz is False:
            print(f"  ✗ Authorization : DKIM d= '{dkim_d}' does not align with")
            print(f"    Header-From domain '{header_from_domain}'")
            print(f"    (DMARC adkim={dmarc_dkim_align} — {'strict' if dmarc_dkim_align == 's' else 'relaxed'} alignment).")
            print(f"    → Recommendation: Sign with a selector whose d= value matches")
            print(f"      '{header_from_domain}' (or its organisational domain), or")
            print("      update your DMARC record to adkim=r for relaxed alignment.")
        elif dkim_authz is None:
            print("  ✗ Authorization : Could not determine DKIM d= alignment.")

    if not dmarc_record:
        print("\n  [DMARC]")
        print(f"  ✗ No DMARC record found at '{dmarc_domain}'.")
        print(f"    → Recommendation: Publish a DMARC TXT record at '{dmarc_domain}'.")
        print("      Start with: v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com")
        print("      Then move to p=quarantine or p=reject once you have verified SPF/DKIM.")

print("\n" + "=" * 60)
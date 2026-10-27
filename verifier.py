"""Email verification engine.

Pipeline per address:
  1. Syntax check
  2. Domain existence check
  3. MX record check
  4. Catch-all domain check (per-domain, cached)
  5. SMTP ping (RCPT TO handshake, no email is ever sent)

Final status: valid | invalid | risky | unknown
"""
import random
import re
import smtplib
import socket
import string
import threading

import dns.exception
import dns.resolver

# ---------- 1. Syntax ----------
LOCAL_ALLOWED = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.\-]+$")
LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def check_syntax(email: str):
    """Return (ok, reason)."""
    if not email or len(email) > 254:
        return False, "Empty or too long"
    if email.count("@") != 1:
        return False, "Must contain exactly one @"
    local, domain = email.rsplit("@", 1)
    if not local or len(local) > 64:
        return False, "Local part empty or over 64 chars"
    if not LOCAL_ALLOWED.match(local):
        return False, "Invalid characters in local part"
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False, "Misplaced dot in local part"
    if "." not in domain:
        return False, "Domain has no dot"
    labels = domain.split(".")
    if any(not LABEL.match(l) for l in labels):
        return False, "Invalid domain format"
    if not re.match(r"^[A-Za-z]{2,}$", labels[-1]) and not labels[-1].startswith("xn--"):
        return False, "Invalid top-level domain"
    return True, "ok"


# ---------- DNS helpers ----------
_resolver = dns.resolver.Resolver()
_resolver.timeout = 4
_resolver.lifetime = 6


def lookup_mx(domain: str):
    """Return (domain_exists, [mx hosts sorted by priority], reason)."""
    try:
        answers = _resolver.resolve(domain, "MX")
        hosts = sorted(
            ((r.preference, str(r.exchange).rstrip(".")) for r in answers)
        )
        hosts = [h for _, h in hosts if h]
        if hosts == [] or hosts == ["."]:
            return True, [], "Null MX (domain does not accept mail)"
        return True, hosts, "ok"
    except dns.resolver.NXDOMAIN:
        return False, [], "Domain does not exist"
    except dns.resolver.NoAnswer:
        # Domain exists but has no MX; RFC falls back to A record
        try:
            _resolver.resolve(domain, "A")
            return True, [domain], "No MX, using A record"
        except Exception:
            return True, [], "Domain exists but no MX/A record"
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return None, [], "DNS timeout"
    except Exception as e:  # noqa
        return None, [], f"DNS error: {e.__class__.__name__}"


# ---------- SMTP helpers ----------
def smtp_rcpt(mx_host: str, address: str, helo: str, mail_from: str, timeout=10):
    """Return (code, message) of RCPT TO, or (None, reason) on connection failure."""
    try:
        s = smtplib.SMTP(timeout=timeout)
        s.connect(mx_host, 25)
        s.ehlo_or_helo_if_needed()
        s.helo(helo)
        s.mail(mail_from)
        code, msg = s.rcpt(address)
        try:
            s.quit()
        except Exception:
            pass
        return code, msg.decode(errors="ignore") if isinstance(msg, bytes) else str(msg)
    except (socket.timeout, TimeoutError):
        return None, "SMTP timeout"
    except (ConnectionRefusedError, OSError) as e:
        return None, f"SMTP connection failed: {e.__class__.__name__}"
    except smtplib.SMTPException as e:
        return None, f"SMTP error: {e.__class__.__name__}"


def port25_open(test_host="gmail-smtp-in.l.google.com", timeout=6) -> bool:
    try:
        with socket.create_connection((test_host, 25), timeout=timeout):
            return True
    except Exception:
        return False


def _random_local():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=18))


class Verifier:
    def __init__(self, helo="verifier.local", mail_from="check@verifier.local",
                 smtp_enabled=True):
        self.helo = helo
        self.mail_from = mail_from
        self._domain_cache = {}   # domain -> dict(mx info + catch_all)
        self._lock = threading.Lock()
        self.smtp_enabled = smtp_enabled
        self.smtp_available = port25_open() if smtp_enabled else False
        # Sanity check: if DNS can't resolve a domain that certainly exists,
        # the network is blocking DNS and we must not label emails "invalid".
        self.dns_ok = lookup_mx("gmail.com")[0] is True

    def _domain_info(self, domain):
        with self._lock:
            info = self._domain_cache.get(domain)
            if info is None:
                info = {"lock": threading.Lock(), "done": False}
                self._domain_cache[domain] = info
        with info["lock"]:
            if info["done"]:
                return info
            exists, mx, reason = lookup_mx(domain)
            info.update(exists=exists, mx=mx, dns_reason=reason, catch_all=None)
            # 4. Catch-all check: probe a random address that cannot exist
            if exists and mx and self.smtp_available:
                code, _ = smtp_rcpt(mx[0], f"{_random_local()}@{domain}",
                                    self.helo, self.mail_from)
                if code is not None:
                    info["catch_all"] = 200 <= code < 300
            info["done"] = True
            return info

    def verify(self, raw: str) -> dict:
        email = (raw or "").strip().lower()
        res = {"email": raw, "status": "unknown", "reason": "",
               "syntax": False, "domain": None, "mx": None,
               "catch_all": None, "smtp": None}

        # 1. syntax
        ok, why = check_syntax(email)
        res["syntax"] = ok
        if not ok:
            res.update(status="invalid", reason=f"Syntax: {why}")
            return res

        domain = email.rsplit("@", 1)[1]
        if not self.dns_ok:
            res.update(status="unknown",
                       reason="Syntax OK; DNS unreachable from this network, domain not checked")
            return res
        info = self._domain_info(domain)

        # 2. domain
        if info["exists"] is None:
            res.update(reason=info["dns_reason"])
            return res
        res["domain"] = info["exists"]
        if not info["exists"]:
            res.update(status="invalid", reason="Domain does not exist")
            return res

        # 3. MX
        res["mx"] = bool(info["mx"])
        if not info["mx"]:
            res.update(status="invalid", reason=info["dns_reason"])
            return res
        res["catch_all"] = info["catch_all"]

        if not self.smtp_available:
            res.update(status="unknown",
                       reason="Syntax, domain and MX OK; SMTP unchecked (port 25 blocked)")
            return res

        # 5. SMTP ping
        code, msg = None, ""
        for host in info["mx"][:2]:
            code, msg = smtp_rcpt(host, email, self.helo, self.mail_from)
            if code is not None:
                break
        if code is None:
            res.update(smtp=None, reason=msg)
            return res
        if 200 <= code < 300:
            res["smtp"] = True
            if info["catch_all"]:
                res.update(status="risky", reason="Catch-all domain: cannot confirm mailbox")
            else:
                res.update(status="valid", reason="Mailbox accepted")
        elif 500 <= code < 600:
            res["smtp"] = False
            res.update(status="invalid", reason=f"Mailbox rejected ({code})")
        else:  # 4xx greylisting / temp
            res.update(reason=f"Temporary SMTP response ({code})")
        return res

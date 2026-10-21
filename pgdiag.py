#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mariusz Bak <dev@mariuszbak.eu>
"""
pgdiag - konsolowe narzedzie diagnostyczne PostgreSQL (WYLACZNIE ODCZYT)

Autor:     Mariusz Bak <dev@mariuszbak.eu>
Licencja:  MIT – pelny tekst w stalej LICENSE_TEXT ponizej, w programie pod F7
           oraz: python3 pgdiag.py --license

Pokazuje:
  * bazy danych w instancji (rozmiar, wlasciciel, kodowanie, kto ma prawo CONNECT),
  * reguly dostepu pg_hba.conf - skad (adres), dokad (bazy), kto (role), jak (metoda),
    z ocena ryzyka i wykrywaniem regul przeslonietych,
  * role: atrybuty, typ hasla, czlonkostwa, uprawnienia do baz, pasujace reguly pg_hba.
  * siec i firewall: na jakich adresach serwer nasluchuje, test polaczenia TCP, stan
    nftables / iptables / firewalld / ufw, czy port bazy jest otwarty z sieci oraz czy
    firewall nie blokuje sieci dopuszczonych w pg_hba.

Gwarancje "tylko odczyt":
  * wylacznie zapytania SELECT do katalogow systemowych (tekst zapytan jest staly),
  * kazde zapytanie w transakcji BEGIN READ ONLY ... ROLLBACK,
  * psql uruchamiany z -X (bez ~/.psqlrc) i -w (nigdy nie pyta o haslo),
  * program nie zmienia niczego w systemie; jedyny zapisywany plik to wlasne ustawienia
    interfejsu (~/.config/pgdiag/pgdiag.conf) – tylko gdy uzytkownik zmieni motyw (F9)
    lub jezyk (F8). Jezyk interfejsu: angielski (domyslny) lub polski.
  * siec i firewall: odczyt /proc/net i wylacznie polecenia listujace (nft list ruleset,
    iptables-save, firewall-cmd --state/--list-all, ufw status); moduly jadra firewalla nie
    sa ladowane; test TCP tylko otwiera i zamyka polaczenie, nic nie wysylajac.

Wymagania: Python 3.6+, klient psql. Bez dodatkowych bibliotek.
Uzycie:    sudo python3 pgdiag.py       (komplet danych: firewall jako root, psql jako postgres)
           python3 pgdiag.py            (interfejs pelnoekranowy)
           python3 pgdiag.py --report   (raport tekstowy na stdout)
"""

import argparse
import curses
import getpass
import glob
import ipaddress
import json
import locale
import os
import platform
import queue
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
import traceback
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "1.5"

AUTHOR = "Mariusz Bak"
AUTHOR_EMAIL = "dev@mariuszbak.eu"
COPYRIGHT_YEAR = "2026"
COPYRIGHT = "Copyright (c) %s %s <%s>" % (COPYRIGHT_YEAR, AUTHOR, AUTHOR_EMAIL)

LICENSE_TEXT = """MIT License

Copyright (c) 2026 Mariusz Bak <dev@mariuszbak.eu>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

OK, INFO, WARN, CRIT = 0, 1, 2, 3
SEV_LABEL = {OK: "OK", INFO: "info", WARN: "UWAGA", CRIT: "KRYTYCZNE"}


def sev_label(sev):
    return tr(SEV_LABEL[sev])

SSL_MODES = ["prefer", "disable", "allow", "require", "verify-ca", "verify-full"]

# =============================================================================
#  Tekst: znaki, szerokosc, przycinanie
# =============================================================================

UNICODE = True  # ustawiane w main() na podstawie locale

# --- jezyk interfejsu: "en" (domyslny) lub "pl". Teksty w kodzie sa po polsku i przechodza przez tr();
#     tlumaczenia angielskie sa w slowniku TR_EN na koncu pliku.
LANG = "en"
LANGS = [("en", "English"), ("pl", "Polski")]


def tr(s):
    if LANG == "en":
        return TR_EN.get(s, s)
    return s


def set_lang(code):
    global LANG
    LANG = code if code in ("en", "pl") else "en"


def ldec(s):
    """Separator dziesietny zalezny od jezyka."""
    return s.replace(".", ",") if LANG == "pl" else s

_PL = str.maketrans("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ", "acelnoszzACELNOSZZ")
_ASCII = {"…": "~", "—": "-", "–": "-", "→": "->", "←": "<-", "↑": "^", "↓": "v",
          "•": "*", "▾": "v", "↵": "|", "·": "-", "„": '"', "”": '"', "“": '"',
          "×": "x", "©": "(c)", "≥": ">=", "≤": "<=", "■": "#", "▸": ">"}


def U(s):
    """Tekst do wyswietlenia; w terminalu bez UTF-8 zamienia znaki na ASCII."""
    if s is None:
        return ""
    s = str(s)
    if UNICODE:
        return s
    s = s.translate(_PL)
    for a, b in _ASCII.items():
        s = s.replace(a, b)
    return s.encode("ascii", "replace").decode("ascii")


def chw(c):
    o = ord(c)
    if o < 32 or 0x7f <= o < 0xa0:
        return 0
    if unicodedata.combining(c):
        return 0
    return 2 if unicodedata.east_asian_width(c) in ("W", "F") else 1


def sw(s):
    """Szerokosc wyswietlanego tekstu w kolumnach terminala."""
    return sum(chw(c) for c in s)


def clip(s, w):
    out, n = [], 0
    for c in s:
        cw = chw(c)
        if n + cw > w:
            break
        out.append(c)
        n += cw
    return "".join(out), n


def fit(s, w, align="l"):
    """Dopasowuje tekst do szerokosci w (przycina z wielokropkiem, dopelnia spacjami)."""
    s = U(s)
    if w <= 0:
        return ""
    n = sw(s)
    if n > w:
        t, n2 = clip(s, w - 1)
        s = t + ("…" if UNICODE else "~")
        n = n2 + 1
    pad = w - n
    if align == "r":
        return " " * pad + s
    if align == "c":
        return " " * (pad // 2) + s + " " * (pad - pad // 2)
    return s + " " * pad


def wrap(text, width):
    width = max(8, width)
    out = []
    for para in U(text).split("\n"):
        out.extend(textwrap.wrap(para, width, break_long_words=True,
                                 break_on_hyphens=False) or [""])
    return out


def cell(v):
    """Wartosc z bazy -> jednowierszowy tekst do komorki tabeli."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return tr("tak") if v else tr("nie")
    if isinstance(v, (list, tuple)):
        return ", ".join(cell(x) for x in v)
    s = str(v)
    if "\n" in s or "\t" in s or "\r" in s:
        s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\t", " ").replace("\n", " ↵ ")
    return s


def yn(b):
    return tr("tak") if b else tr("nie")


def plural(n, one, few, many):
    n = abs(int(n))
    if n == 1:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def fmt_int(n):
    return "{:,}".format(int(n)).replace(",", " " if LANG == "pl" else ",")


def fmt_bytes(n):
    if n is None:
        return ""
    n = float(n)
    for unit in ("B", "kB", "MB", "GB", "TB", "PB"):
        if n < 1024 or unit == "PB":
            if unit == "B":
                return "%d B" % n
            return ldec("%.1f %s" % (n, unit))
        n /= 1024.0


def fmt_ts(s):
    if not s:
        return ""
    return str(s)[:19].replace("T", " ")


def fmt_interval(s):
    """Interwal PostgreSQL ('3 days 04:05:06') -> po polsku."""
    if not s:
        return ""
    s = str(s)

    def rep(m):
        n, unit = int(m.group(1)), m.group(2)
        if unit.startswith("year"):
            return "%d %s" % (n, plural(n, tr("rok"), tr("lata"), tr("lat")))
        if unit.startswith("mon"):
            return tr("%d mies.") % n
        return "%d %s" % (n, plural(n, tr("dzień"), tr("dni"), tr("dni")))
    s = re.sub(r"(\d+) (years?|mons?|days?)", rep, s)
    return re.sub(r"\.\d+$", "", s)


# =============================================================================
#  Dostep do PostgreSQL przez psql (tylko odczyt)
# =============================================================================

class PgError(Exception):
    def __init__(self, message, hint=None, kind="query"):
        Exception.__init__(self, message)
        self.message = message
        self.hint = hint
        self.kind = kind


def find_psql(explicit=None):
    if explicit:
        return explicit if os.path.isfile(explicit) and os.access(explicit, os.X_OK) else None
    p = shutil.which("psql")
    if p:
        return p
    cands = []
    for pat in ("/usr/lib/postgresql/*/bin/psql", "/usr/pgsql-*/bin/psql",
                "/usr/local/pgsql/bin/psql", "/opt/homebrew/opt/postgresql*/bin/psql",
                "/usr/local/opt/postgresql*/bin/psql"):
        cands.extend(c for c in glob.glob(pat) if os.access(c, os.X_OK))
    if not cands:
        return None
    return sorted(cands, key=lambda c: [int(x) for x in re.findall(r"\d+", c)])[-1]


_PG_ENV_DROP = ("PGHOST", "PGHOSTADDR", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE",
                "PGSSLMODE", "PGOPTIONS", "PGSERVICE", "PGTARGETSESSIONATTRS", "PGREQUIRESSL")


def clean_err(err):
    out = []
    for ln in err.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        ln = re.sub(r"^psql:\s*(<stdin>|-):\d+:\s*", "", ln)
        ln = re.sub(r"^psql:\s*(error:\s*)?", "", ln)
        ln = re.sub(r"^(ERROR|BŁĄD|BLAD):\s+", "", ln)
        if ln.startswith(("LINE ", "LINIA ")) or set(ln) <= set(" ^"):
            continue
        ln = re.sub(r"\s+", " ", ln).strip()
        if ln not in out:
            out.append(ln)
    return " ".join(out).strip()


def connection_hint(msg):
    m = msg.lower()
    prog = os.path.basename(sys.argv[0]) or "pgdiag.py"
    if ("peer authentication failed" in m or "ident authentication failed" in m) and os.geteuid() == 0:
        return (tr("Metoda peer wymaga, aby konto systemowe miało tę samą nazwę co rola. W polu „psql jako” "
                "wybierz postgres (albo konto o nazwie roli) lub wpisz Host 127.0.0.1 i hasło."))
    if "peer authentication failed" in m or "ident authentication failed" in m:
        return (tr("Połączenie przez gniazdo lokalne metodą peer wymaga, aby nazwa użytkownika systemu "
                "była taka sama jak nazwa roli. Uruchom program jako ten użytkownik, np. "
                "„sudo -u postgres python3 %s”, albo wpisz Host 127.0.0.1 i hasło.") % prog)
    if "no password supplied" in m:
        return tr("Serwer wymaga hasła. Wpisz je w polu Hasło albo dodaj wpis do pliku ~/.pgpass.")
    if "password authentication failed" in m:
        return tr("Nieprawidłowe hasło lub nazwa użytkownika.")
    if "no pg_hba.conf entry" in m:
        return (tr("Serwer nie ma reguły pg_hba.conf dopuszczającej takie połączenie (adres, rola, baza, SSL). "
                "Spróbuj połączenia lokalnego (puste pole Host) jako postgres albo zmień tryb SSL."))
    if "connection refused" in m or "no such file or directory" in m:
        return (tr("Serwer nie działa albo nie nasłuchuje pod tym adresem/portem. Sprawdź Host, Port "
                "oraz parametr listen_addresses."))
    if "timeout expired" in m or "timed out" in m:
        return tr("Serwer nie odpowiada – sprawdź adres i zaporę sieciową.")
    if "could not translate host name" in m:
        return tr("Nieznana nazwa hosta – sprawdź pole Host.")
    if "database" in m and "does not exist" in m:
        return tr("Podana baza nie istnieje. Wpisz w polu Baza np. postgres albo template1.")
    if "role" in m and "does not exist" in m:
        if 'role "root"' in m and os.geteuid() == 0:
            return (tr("Na serwerze nie ma roli root. W polu „psql jako” wybierz postgres albo wpisz właściwą rolę "
                    "w polu Użytkownik."))
        if 'role "root"' in m:
            return (tr("Program działa jako root, a na serwerze nie ma roli root. Wpisz właściwą rolę w polu "
                    "Użytkownik albo uruchom program jako postgres: „sudo -u postgres python3 %s”.") % prog)
        return tr("Taka rola nie istnieje na serwerze. Popraw pole Użytkownik.")
    if "server does not support ssl" in m:
        return tr("Serwer nie obsługuje SSL – zmień tryb SSL na prefer albo disable.")
    if "certificate" in m or "root.crt" in m:
        return (tr("Problem z certyfikatem SSL. Użyj trybu require/prefer albo skonfiguruj certyfikat CA "
                "(~/.postgresql/root.crt lub PGSSLROOTCERT)."))
    return None


class Connection(object):
    """Wykonuje stale zapytania SELECT przez psql w transakcji READ ONLY."""

    def __init__(self, psql, params):
        self.psql = psql
        self.p = dict(params)

    def _run_as(self):
        """Gdy program dziala jako root, psql moze dzialac jako inne konto systemowe (np. postgres)."""
        name = self.p.get("os_user")
        if not name or os.geteuid() != 0:
            return None
        import pwd
        try:
            pw = pwd.getpwnam(name)
        except KeyError:
            raise PgError(tr("Nie ma konta systemowego „%s”.") % name, kind="psql")
        if pw.pw_uid == 0:
            return None
        return pw

    def _env(self):
        env = dict((k, v) for k, v in os.environ.items() if k not in _PG_ENV_DROP)
        for key, var in (("host", "PGHOST"), ("port", "PGPORT"), ("user", "PGUSER"),
                         ("password", "PGPASSWORD"), ("dbname", "PGDATABASE"),
                         ("sslmode", "PGSSLMODE")):
            v = self.p.get(key)
            if v:
                env[var] = v
        env.setdefault("PGCONNECT_TIMEOUT", "10")
        env["PGAPPNAME"] = "pgdiag (read-only)"
        env["PGCLIENTENCODING"] = "UTF8"
        env["LC_MESSAGES"] = "C"
        return env

    def query(self, sql, timeout=90):
        script = ("BEGIN TRANSACTION READ ONLY;\n"
                  "SET LOCAL statement_timeout = '60s';\n"
                  "SET LOCAL lock_timeout = '5s';\n"
                  "SELECT coalesce(replace(json_agg(q)::text, E'\\n', ' '), '[]') FROM (\n"
                  + sql + "\n) q;\n"
                  "ROLLBACK;\n")
        args = [self.psql, "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-f", "-"]
        env, kw = self._env(), {}
        pw = self._run_as()
        if pw is not None:
            env.update({"HOME": pw.pw_dir, "USER": pw.pw_name, "LOGNAME": pw.pw_name})
            kw["cwd"] = "/"
            groups = os.getgrouplist(pw.pw_name, pw.pw_gid)
            if sys.version_info >= (3, 9):
                kw.update(user=pw.pw_uid, group=pw.pw_gid, extra_groups=groups)
            else:
                def demote(pw=pw, groups=groups):
                    os.setgroups(groups)
                    os.setgid(pw.pw_gid)
                    os.setuid(pw.pw_uid)
                kw["preexec_fn"] = demote
        try:
            p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env, start_new_session=True, **kw)
        except OSError as e:
            raise PgError(tr("Nie można uruchomić psql (%s): %s") % (self.psql, e), kind="psql")
        try:
            out, err = p.communicate(script.encode("utf-8"), timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            raise PgError(tr("Brak odpowiedzi serwera w ciągu %d s.") % timeout, kind="timeout")
        out = out.decode("utf-8", "replace")
        err = err.decode("utf-8", "replace")
        if p.returncode != 0:
            msg = clean_err(err) or (tr("psql zakończył się kodem %d") % p.returncode)
            if p.returncode == 2:
                raise PgError(msg, connection_hint(msg), kind="connect")
            raise PgError(msg, kind="query")
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("["):
                return json.loads(line)
        raise PgError(tr("Nieoczekiwana odpowiedź psql: %s") % (out.strip()[:200] or err.strip()[:200]))


# ----------------------------------------------------------------------------- SQL
# Wszystkie zapytania sa stalymi tekstami SELECT – bez wstawiania danych uzytkownika.

SQL_PROBE = """
SELECT version() AS version,
       current_setting('server_version_num')::int AS vnum,
       current_setting('server_version') AS server_version,
       current_user AS cur_user, session_user AS sess_user,
       current_database() AS cur_db,
       (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) AS is_super,
       host(inet_server_addr()) AS server_addr, inet_server_port() AS server_port,
       host(inet_client_addr()) AS client_addr,
       pg_postmaster_start_time() AS started,
       date_trunc('second', now() - pg_postmaster_start_time())::text AS uptime,
       pg_is_in_recovery() AS in_recovery,
       has_table_privilege('pg_catalog.pg_authid', 'SELECT') AS can_authid,
       (SELECT count(*) FROM pg_catalog.pg_stat_activity) AS sessions
"""

SETTINGS_NAMES = ["data_directory", "config_file", "hba_file", "ident_file", "listen_addresses",
                  "port", "unix_socket_directories", "max_connections",
                  "superuser_reserved_connections", "ssl", "ssl_min_protocol_version",
                  "password_encryption", "log_connections", "log_disconnections",
                  "authentication_timeout", "shared_buffers", "server_encoding", "TimeZone"]

SQL_SETTINGS = ("SELECT name, setting, unit, source, sourcefile, sourceline, pending_restart "
                "FROM pg_catalog.pg_settings WHERE name IN (%s)"
                % ", ".join("'%s'" % n for n in SETTINGS_NAMES))


def sql_databases(vnum):
    stats = "pg_has_role('pg_read_all_stats', 'USAGE')" if vnum >= 100000 else "false"
    return """
SELECT d.oid::bigint AS oid, d.datname, pg_get_userbyid(d.datdba) AS owner,
       pg_encoding_to_char(d.encoding) AS encoding, d.datcollate, d.datctype,
       d.datistemplate, d.datallowconn, d.datconnlimit, t.spcname AS tablespace,
       CASE WHEN d.datconnlimit <> -2
             AND (has_database_privilege(d.oid, 'CONNECT') OR {stats})
            THEN pg_database_size(d.oid) END AS size,
       (SELECT count(*) FROM pg_catalog.pg_stat_activity a WHERE a.datid = d.oid) AS sessions,
       d.datacl::text AS acl,
       shobj_description(d.oid, 'pg_database') AS comment
FROM pg_catalog.pg_database d
LEFT JOIN pg_catalog.pg_tablespace t ON t.oid = d.dattablespace
ORDER BY d.datname""".format(stats=stats)


SQL_DB_ACL = """
SELECT d.datname,
       CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
       pg_get_userbyid(a.grantor) AS grantor, a.privilege_type AS priv,
       a.is_grantable AS grantable, (d.datacl IS NULL) AS is_default
FROM pg_catalog.pg_database d,
     aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
"""


def sql_roles(can_authid):
    if can_authid:
        pwd = ("CASE WHEN a.rolpassword IS NULL THEN 'brak' "
               "WHEN a.rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'SCRAM' "
               "WHEN a.rolpassword LIKE 'md5%' THEN 'MD5' ELSE 'inne' END")
        join = "LEFT JOIN pg_catalog.pg_authid a ON a.oid = r.oid"
    else:
        pwd, join = "NULL::text", ""
    return """
SELECT r.oid::bigint AS oid, r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole,
       r.rolcreatedb, r.rolcanlogin, r.rolreplication, r.rolbypassrls, r.rolconnlimit,
       r.rolvaliduntil::text AS validuntil,
       (r.rolvaliduntil IS NOT NULL AND r.rolvaliduntil < now()) AS expired,
       {pwd} AS pwd,
       r.rolconfig,
       shobj_description(r.oid, 'pg_authid') AS comment,
       (SELECT count(*) FROM pg_catalog.pg_stat_activity s WHERE s.usename = r.rolname) AS sessions
FROM pg_catalog.pg_roles r {join}
ORDER BY r.rolname""".format(pwd=pwd, join=join)


SQL_MEMBERS = """
SELECT pg_get_userbyid(m.roleid) AS role_name, pg_get_userbyid(m.member) AS member_name,
       pg_get_userbyid(m.grantor) AS grantor_name, m.*
FROM pg_catalog.pg_auth_members m
"""

SQL_ROLE_DB = """
SELECT * FROM (
  SELECT r.rolname, d.datname,
         has_database_privilege(r.oid, d.oid, 'CONNECT') AS c,
         has_database_privilege(r.oid, d.oid, 'CREATE') AS cr,
         has_database_privilege(r.oid, d.oid, 'TEMPORARY') AS t
  FROM pg_catalog.pg_roles r CROSS JOIN pg_catalog.pg_database d
  WHERE r.rolname !~ '^pg_' AND d.datconnlimit <> -2
) x WHERE c OR cr OR t
"""

SQL_ROLE_SETTINGS = """
SELECT r.rolname, d.datname, s.setconfig
FROM pg_catalog.pg_db_role_setting s
LEFT JOIN pg_catalog.pg_roles r ON r.oid = s.setrole
LEFT JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase
"""

SQL_MYSSL = "SELECT ssl, version, cipher, bits FROM pg_catalog.pg_stat_ssl WHERE pid = pg_backend_pid()"
SQL_HBA = "SELECT * FROM pg_catalog.pg_hba_file_rules"
SQL_IDENT = "SELECT * FROM pg_catalog.pg_ident_file_mappings"


# ----------------------------------------------------------------------------- pg_hba.conf (plik)

HBA_TYPES = ("local", "host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc")
HBA_METHODS = ("trust", "reject", "scram-sha-256", "md5", "password", "gss", "sspi", "ident",
               "peer", "ldap", "radius", "cert", "pam", "bsd", "oauth")
HBA_KEYWORDS = ("all", "sameuser", "samerole", "samegroup", "replication")


def _tokenize_hba(line):
    """Dzieli linie pg_hba.conf na pola; pole = lista tokenow (tekst, czy_w_cudzyslowie)."""
    fields, cur, i, n = [], [], 0, len(line)
    while i < n:
        while i < n and line[i] in " \t":
            i += 1
        if i >= n or line[i] == "#":
            break
        tok, quoted, in_q = [], False, False
        while i < n:
            c = line[i]
            if in_q:
                if c == '"':
                    if i + 1 < n and line[i + 1] == '"':
                        tok.append('"')
                        i += 2
                        continue
                    in_q = False
                    i += 1
                    continue
                tok.append(c)
                i += 1
                continue
            if c == '"':
                in_q = quoted = True
                i += 1
                continue
            if c in " \t#,":
                break
            tok.append(c)
            i += 1
        if in_q:
            raise ValueError(tr("niezamknięty cudzysłów"))
        cur.append(("".join(tok), quoted))
        if i < n and line[i] == ",":
            i += 1
            continue
        fields.append(cur)
        cur = []
    if cur:
        fields.append(cur)
    return fields


def _tok_disp(tok):
    text, quoted = tok
    if quoted and (text in HBA_KEYWORDS or text[:1] in "+@/" or not text):
        return '"%s"' % text.replace('"', '""')
    return text


def _hba_row(fields, lineno, path):
    d = {"line_number": lineno, "file_name": path, "type": None, "database": None,
         "user_name": None, "address": None, "netmask": None, "auth_method": None,
         "options": None, "error": None}

    def fail(msg):
        d.update({"type": None, "database": None, "user_name": None, "address": None,
                  "netmask": None, "auth_method": None, "options": None, "error": msg})
        return d

    typ = fields[0][0][0]
    if len(fields[0]) > 1 or typ not in HBA_TYPES:
        return fail(tr('nieprawidłowy typ połączenia "%s"') % typ)
    d["type"] = typ
    idx = 1
    if idx >= len(fields):
        return fail(tr("brak nazwy bazy"))
    d["database"] = [_tok_disp(t) for t in fields[idx]]
    idx += 1
    if idx >= len(fields):
        return fail(tr("brak nazwy roli"))
    d["user_name"] = [_tok_disp(t) for t in fields[idx]]
    idx += 1
    if typ != "local":
        if idx >= len(fields):
            return fail(tr("brak adresu IP"))
        if len(fields[idx]) > 1:
            return fail(tr("lista adresów jest niedozwolona"))
        a = fields[idx][0][0]
        idx += 1
        if a in ("all", "samehost", "samenet"):
            d["address"] = a
        elif "/" in a:
            try:
                net = ipaddress.ip_network(a, strict=False)
            except ValueError:
                return fail(tr('nieprawidłowy adres IP "%s"') % a)
            d["address"], d["netmask"] = str(net.network_address), str(net.netmask)
        else:
            try:
                ipaddress.ip_address(a)
                is_ip = True
            except ValueError:
                is_ip = False
            if is_ip:
                if idx >= len(fields):
                    return fail(tr("po adresie IP brakuje maski"))
                mask = fields[idx][0][0]
                try:
                    ipaddress.ip_address(mask)
                except ValueError:
                    return fail(tr('nieprawidłowa maska "%s"') % mask)
                idx += 1
                d["address"], d["netmask"] = a, mask
            else:
                d["address"] = a
    if idx >= len(fields):
        return fail(tr("brak metody uwierzytelniania"))
    meth = fields[idx][0][0]
    idx += 1
    if meth not in HBA_METHODS:
        return fail(tr('nieprawidłowa metoda uwierzytelniania "%s"') % meth)
    d["auth_method"] = meth
    opts = [",".join(t[0] for t in f) for f in fields[idx:]]
    d["options"] = opts or None
    return d


def parse_hba_file(path, depth=0):
    """Czyta (tylko do odczytu) plik pg_hba.conf razem z dyrektywami include."""
    if depth > 10:
        raise PgError(tr("Zbyt głębokie zagnieżdżenie dyrektyw include"))
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read().splitlines()
    except PermissionError:
        raise PgError(tr("Brak uprawnień do odczytu pliku %s (uruchom jako postgres lub przez sudo).") % path)
    except OSError as e:
        raise PgError(tr("Nie można odczytać pliku %s: %s") % (path, e.strerror or e))
    rows, i = [], 0
    base = os.path.dirname(os.path.abspath(path))
    while i < len(raw):
        lineno, line = i + 1, raw[i]
        i += 1
        while line.rstrip().endswith("\\") and i < len(raw):
            line = line.rstrip()[:-1] + " " + raw[i]
            i += 1
        if not line.strip() or line.strip().startswith("#"):
            continue
        try:
            fields = _tokenize_hba(line)
        except ValueError as e:
            rows.append({"line_number": lineno, "file_name": path, "error": str(e)})
            continue
        if not fields:
            continue
        first = fields[0][0][0]
        if first in ("include", "include_if_exists", "include_dir") and not fields[0][0][1]:
            if len(fields) < 2:
                rows.append({"line_number": lineno, "file_name": path,
                             "error": tr("dyrektywa %s bez nazwy pliku") % first})
                continue
            target = fields[1][0][0]
            if not os.path.isabs(target):
                target = os.path.join(base, target)
            targets = [target]
            if first == "include_dir":
                targets = sorted(p for p in glob.glob(os.path.join(target, "*.conf"))
                                 if not os.path.basename(p).startswith("."))
            elif first == "include_if_exists" and not os.path.exists(target):
                continue
            for t in targets:
                try:
                    rows.extend(parse_hba_file(t, depth + 1))
                except PgError as e:
                    rows.append({"line_number": lineno, "file_name": path, "error": e.message})
            continue
        rows.append(_hba_row(fields, lineno, path))
    return rows


def user_exists(name):
    try:
        import pwd
        pwd.getpwnam(name)
        return True
    except (KeyError, ImportError):
        return False


def is_local_host(h):
    if not h or h.startswith("/"):
        return True
    if h in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return h in (socket.gethostname(), socket.getfqdn())
    except Exception:
        return False


def guess_local_hba(host, server_hba, vnum):
    """Szuka czytelnego pliku pg_hba.conf, gdy brak uprawnien do widoku pg_hba_file_rules."""
    base = (tr("Brak uprawnień do widoku pg_hba_file_rules (wymaga superużytkownika lub nadania "
            "uprawnień). "))
    if not is_local_host(host):
        return None, base + (tr("Serwer jest zdalny – połącz się jako superużytkownik albo wpisz "
                             "w polu pg_hba.conf ścieżkę lokalnej kopii pliku."))
    if server_hba:
        if os.path.isfile(server_hba) and os.access(server_hba, os.R_OK):
            return server_hba, None
        return None, base + (tr("Nie można też odczytać pliku %s – uruchom program jako postgres "
                             "(sudo -u postgres) lub root.") % server_hba)
    cands = []
    for pat in ("/etc/postgresql/*/*/pg_hba.conf", "/var/lib/pgsql/*/data/pg_hba.conf",
                "/var/lib/pgsql/data/pg_hba.conf", "/var/lib/postgres/data/pg_hba.conf",
                "/var/lib/postgresql/*/main/pg_hba.conf", "/usr/local/pgsql/data/pg_hba.conf",
                "/var/lib/postgresql/data/pg_hba.conf"):
        cands.extend(sorted(glob.glob(pat)))
    major = str(vnum // 10000) if vnum >= 100000 else "%d.%d" % (vnum // 10000, vnum // 100 % 100)
    same = [c for c in cands if ("/%s/" % major) in c]
    if same:
        cands = same
    readable = [c for c in cands if os.path.isfile(c) and os.access(c, os.R_OK)]
    if len(readable) == 1:
        return readable[0], tr("plik wykryty automatycznie – upewnij się, że należy do tego klastra")
    if len(readable) > 1:
        return None, base + (tr("Znaleziono kilka plików: %s – wpisz właściwy w polu pg_hba.conf.")
                             % ", ".join(readable))
    if cands:
        return None, base + (tr("Pliki %s istnieją, ale bieżący użytkownik nie może ich czytać – "
                             "uruchom program jako postgres lub root.") % ", ".join(cands))
    return None, base + tr("Wpisz ścieżkę pliku w polu pg_hba.conf albo połącz się jako postgres.")


def local_clusters():
    exe = shutil.which("pg_lsclusters")
    if not exe:
        return None
    try:
        r = subprocess.run([exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
    except Exception:
        return None
    out = []
    for line in r.stdout.decode("utf-8", "replace").splitlines()[1:]:
        parts = line.split(None, 6)
        if len(parts) >= 6:
            out.append({"ver": parts[0], "cluster": parts[1], "port": parts[2],
                        "status": parts[3], "owner": parts[4], "datadir": parts[5],
                        "log": parts[6] if len(parts) > 6 else ""})
    return out


# =============================================================================
#  Siec i firewall – zbieranie danych (WYLACZNIE ODCZYT)
#  Zrodla: /proc/net/*, ioctl SIOCGIFADDR, polecenia listujace: nft list ruleset,
#  iptables-save, firewall-cmd --state/--list-all, ufw status. Test TCP tylko
#  otwiera i zamyka polaczenie (bez wysylania danych).
# =============================================================================

SBIN_DIRS = ("/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin")


def find_exe(name):
    p = shutil.which(name)
    if p:
        return p
    for d in SBIN_DIRS:
        c = os.path.join(d, name)
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def run_cmd(args, timeout=10):
    """Uruchamia polecenie TYLKO DO ODCZYTU. Zwraca (kod, stdout, stderr) lub None, gdy brak programu."""
    exe = find_exe(args[0])
    if not exe:
        return None
    env = dict(os.environ)
    env["LC_ALL"] = env["LANG"] = "C"
    try:
        r = subprocess.run([exe] + list(args[1:]), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return (-1, "", tr("przekroczony czas oczekiwania"))
    except OSError as e:
        return (-1, "", str(e))
    return (r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"))


def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _hex_ip(h):
    b = bytes.fromhex(h)
    if sys.byteorder == "little":
        b = b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))
    if len(b) == 4:
        return str(ipaddress.IPv4Address(b))
    a = ipaddress.IPv6Address(b)
    return str(a.ipv4_mapped) if a.ipv4_mapped else str(a)


def socket_owners(inodes, limit_s=2.0):
    """inode gniazda -> (pid, nazwa procesu); widoczne tylko procesy, do ktorych mamy dostep."""
    res = {}
    if not inodes:
        return res
    t0 = time.time()
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return res
    for pid in pids:
        if time.time() - t0 > limit_s or len(res) == len(inodes):
            break
        fd_dir = "/proc/%s/fd" % pid
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                link = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if link.startswith("socket:[") and link[8:-1] in inodes and link[8:-1] not in res:
                comm = (_read("/proc/%s/comm" % pid) or "?").strip()
                res[link[8:-1]] = (int(pid), comm)
    return res


def read_listen_sockets(port):
    out, readable = [], False
    for fname, fam in (("/proc/net/tcp", 4), ("/proc/net/tcp6", 6)):
        text = _read(fname)
        if text is None:
            continue
        readable = True
        for ln in text.splitlines()[1:]:
            p = ln.split()
            if len(p) < 10 or p[3] != "0A":
                continue
            addr, prt = p[1].rsplit(":", 1)
            if int(prt, 16) != int(port):
                continue
            ip = _hex_ip(addr)
            out.append({"family": 6 if ":" in ip else 4, "addr": ip, "port": int(prt, 16),
                        "uid": int(p[7]), "inode": p[9]})
    if not readable:
        return None
    owners = socket_owners(set(s["inode"] for s in out))
    for s in out:
        s["proc"] = owners.get(s["inode"])
    return out


def pg_unix_ports():
    """Porty lokalnych serwerow PostgreSQL wg gniazd Unix .s.PGSQL.<port>."""
    text = _read("/proc/net/unix") or ""
    return sorted(set(int(m) for m in re.findall(r"\.s\.PGSQL\.(\d+)$", text, re.M)))


def read_unix_sockets(port):
    text = _read("/proc/net/unix")
    if text is None:
        return None
    suffix = ".s.PGSQL.%d" % int(port)
    paths = []
    for ln in text.splitlines()[1:]:
        p = ln.split()
        if len(p) >= 8 and p[-1].endswith(suffix) and p[-1] not in paths:
            paths.append(p[-1])
    return paths


def local_addresses():
    """Adresy IP interfejsow tego komputera: lista (interfejs, adres)."""
    res = []
    r = run_cmd(["ip", "-o", "addr", "show"], timeout=5)
    if r and r[0] == 0:
        for ln in r[1].splitlines():
            m = re.match(r"\d+:\s+(\S+)\s+(inet6?)\s+([0-9a-fA-F:.]+)/(\d+)", ln)
            if m and "scope link" not in ln:
                res.append((m.group(1).split("@")[0], m.group(3)))
        if res:
            return res
    try:
        import fcntl
        import struct
        names = [n for _, n in socket.if_nameindex()]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for n in names:
                try:
                    data = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", n[:15].encode()))  # SIOCGIFADDR
                    res.append((n, socket.inet_ntoa(data[20:24])))
                except OSError:
                    pass
        finally:
            s.close()
    except Exception:
        pass
    text = _read("/proc/net/if_inet6")
    for ln in (text or "").splitlines():
        p = ln.split()
        if len(p) >= 6:
            try:
                a = ipaddress.IPv6Address(bytes.fromhex(p[0]))
            except ValueError:
                continue
            if not a.is_link_local:
                res.append((p[5], str(a)))
    return res


def tcp_test(addr, port, timeout=2.0):
    """Otwiera i od razu zamyka polaczenie TCP – nic nie jest wysylane."""
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((addr, int(port)))
        return {"result": "open", "ms": (time.time() - t0) * 1000.0}
    except socket.timeout:
        return {"result": "timeout", "timeout": timeout}
    except ConnectionRefusedError:
        return {"result": "refused"}
    except OSError as e:
        return {"result": "error", "error": e.strerror or str(e)}
    finally:
        s.close()


def module_state(name):
    """'loaded' / 'builtin' – mozna pytac; 'absent' – modul nie jest zaladowany (nie ladujemy go)."""
    if os.path.isdir("/sys/module/%s" % name):
        return "loaded"
    mods = _read("/proc/modules")
    if mods is None:
        return "builtin"                       # jadro bez obslugi modulow
    if re.search(r"^%s\s" % re.escape(name), mods, re.M):
        return "loaded"
    rel = os.uname().release
    builtin = _read("/lib/modules/%s/modules.builtin" % rel)
    if builtin is not None and ("/%s.ko" % name) in builtin:
        return "builtin"
    if builtin is None and not os.path.isdir("/lib/modules/%s" % rel):
        return "builtin"                       # nie da sie sprawdzic – zakladamy wbudowany
    return "absent"


def _perm_denied(err):
    e = (err or "").lower()
    return ("permission denied" in e or "not permitted" in e or "you need to be root" in e
            or "must be root" in e or "authorization failed" in e or "not authorized" in e)


def gather_firewall():
    fw = {"euid": os.geteuid()}
    # --- nftables
    d = {"exe": find_exe("nft")}
    if d["exe"]:
        if module_state("nf_tables") == "absent":
            d["state"] = "inactive"
        else:
            r = run_cmd(["nft", "-j", "list", "ruleset"])
            if r and r[0] == 0:
                d["state"], d["json"] = "ok", r[1]
                r2 = run_cmd(["nft", "-a", "list", "ruleset"])
                d["text"] = r2[1] if r2 and r2[0] == 0 else ""
            else:
                d["state"] = "denied" if r and _perm_denied(r[2]) else "error"
                d["error"] = (r[2] if r else "").strip()
    fw["nft"] = d
    # --- iptables / ip6tables
    for base, fam, names_file in (("iptables", 4, "/proc/net/ip_tables_names"),
                                  ("ip6tables", 6, "/proc/net/ip6_tables_names")):
        d = {"exe": find_exe(base + "-save"), "family": fam}
        if d["exe"]:
            v = run_cmd([base, "--version"], timeout=5)
            vt = (v[1] + v[2]) if v else ""
            d["backend"] = "nf_tables" if "nf_tables" in vt else "legacy"
            names = _read(names_file)
            d["legacy_tables"] = None if names is None else names.split()
            legacy_exe = base + "-legacy-save" if find_exe(base + "-legacy-save") else (
                base + "-save" if d["backend"] == "legacy" else None)
            if d["legacy_tables"] and legacy_exe:
                r = run_cmd([legacy_exe])
                if r and r[0] == 0:
                    d["legacy_text"] = r[1]
                elif r:
                    d["legacy_error"] = r[2].strip()
                    d["legacy_denied"] = _perm_denied(r[2])
            if d["backend"] == "nf_tables" and module_state("nf_tables") != "absent":
                r = run_cmd([base + "-save"])
                if r and r[0] == 0:
                    d["text"] = r[1]
                elif r:
                    d["error"] = r[2].strip()
                    d["denied"] = _perm_denied(r[2])
        fw[base] = d
    # --- firewalld
    d = {"exe": find_exe("firewall-cmd")}
    if d["exe"]:
        r = run_cmd(["firewall-cmd", "--state"], timeout=8)
        st = ((r[1] + r[2]) if r else "").strip()
        d["state"] = "running" if st.startswith("running") else ("not running" if "not running" in st else st or "?")
        if d["state"] == "running":
            r = run_cmd(["firewall-cmd", "--get-default-zone"], timeout=8)
            d["default"] = r[1].strip() if r and r[0] == 0 else ""
            r = run_cmd(["firewall-cmd", "--get-active-zones"], timeout=8)
            d["active"] = r[1] if r and r[0] == 0 else ""
            if r and r[0] != 0:
                d["error"] = r[2].strip()
                d["denied"] = _perm_denied(r[2])
            zones = [ln.split()[0] for ln in d["active"].splitlines() if ln and not ln[0].isspace()]
            if d["default"] and d["default"] not in zones:
                zones.append(d["default"])
            d["zones"] = {}
            for z in zones:
                r = run_cmd(["firewall-cmd", "--zone=%s" % z, "--list-all"], timeout=8)
                if r and r[0] == 0:
                    d["zones"][z] = r[1]
            d["services"] = firewalld_service_ports()
    fw["firewalld"] = d
    # --- ufw
    d = {"exe": find_exe("ufw")}
    if d["exe"]:
        conf = _read("/etc/ufw/ufw.conf") or ""
        m = re.search(r"^\s*ENABLED\s*=\s*(\w+)", conf, re.M)
        d["enabled_conf"] = m.group(1).lower() if m else None
        if os.geteuid() == 0:
            r = run_cmd(["ufw", "status", "verbose"], timeout=10)
            if r and r[0] == 0:
                d["text"] = r[1]
            elif r:
                d["error"] = (r[1] + r[2]).strip()
        else:
            d["denied"] = True
        d["profiles"] = ufw_app_profiles()
    fw["ufw"] = d
    return fw


def firewalld_service_ports():
    """Porty uslug firewalld z plikow XML (tylko odczyt)."""
    import xml.etree.ElementTree as ET
    res = {}
    for d in ("/usr/lib/firewalld/services", "/etc/firewalld/services"):   # /etc nadpisuje /usr/lib
        for p in glob.glob(os.path.join(d, "*.xml")):
            try:
                root = ET.parse(p).getroot()
            except Exception:
                continue
            ports = []
            for el in root.findall("port"):
                ports.append((el.get("port") or "", (el.get("protocol") or "").lower()))
            res[os.path.basename(p)[:-4]] = ports
    return res


def ufw_app_profiles():
    import configparser
    res = {}
    for p in glob.glob("/etc/ufw/applications.d/*"):
        cp = configparser.RawConfigParser(strict=False)
        try:
            cp.read(p, encoding="utf-8")
        except Exception:
            continue
        for sec in cp.sections():
            ports = cp.get(sec, "ports", fallback="")
            res[sec] = ports
    return res


def gather_network(host, port, timeout=2.0):
    t0 = time.time()
    port = int(port or 5432)
    net = {"host": host or "", "port": port}
    ifaces = local_addresses()
    net["ifaces"] = ifaces
    local = is_local_host(host) or (host in [ip for _, ip in ifaces])
    net["local"] = local
    targets = []
    if local:
        net["listen"] = read_listen_sockets(port)
        net["unix"] = read_unix_sockets(port)
        net["pg_ports"] = pg_unix_ports()
        seen = set()
        cand = [("lo", "127.0.0.1")]
        if os.path.exists("/proc/net/if_inet6"):
            cand.append(("lo", "::1"))
        cand += [(n, ip) for n, ip in ifaces]
        for n, ip in cand:
            if ip not in seen:
                seen.add(ip)
                targets.append({"addr": ip, "label": n})
    else:
        try:
            infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
            seen = set()
            for fam, _, _, _, sa in infos:
                if sa[0] not in seen:
                    seen.add(sa[0])
                    targets.append({"addr": sa[0], "label": host})
        except socket.gaierror as e:
            net["resolve_error"] = str(e)
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [(t, ex.submit(tcp_test, t["addr"], port, timeout)) for t in targets]
        for t, f in futs:
            t.update(f.result())
    net["tests"] = targets
    try:
        net["fw"] = gather_firewall()
    except Exception as e:
        net["fw"] = {"error": "%s: %s" % (type(e).__name__, e), "euid": os.geteuid()}
    net["elapsed"] = time.time() - t0
    return net


def collect(params, psql, hba_file="", skip_net=False):
    """Pobiera wszystkie dane diagnostyczne. Rzuca PgError, gdy nie da sie polaczyc."""
    t0 = time.time()
    conn = Connection(psql, params)
    rep = {"params": dict((k, v) for k, v in params.items() if k != "password"),
           "errors": {}}
    ex_net = ThreadPoolExecutor(max_workers=1)
    fnet = None if skip_net else ex_net.submit(gather_network, params.get("host") or "", params.get("port") or 5432)
    try:
        rows = conn.query(SQL_PROBE)
        if not rows:
            raise PgError(tr("Serwer nie zwrócił danych."))
    except PgError as e:
        # diagnostyka sieci przydaje sie najbardziej wlasnie wtedy, gdy nie da sie polaczyc
        e.net = None
        if fnet is not None:
            try:
                e.net = fnet.result()
            except Exception:
                pass
        ex_net.shutdown(wait=False)
        raise
    probe = rows[0]
    rep["probe"] = probe
    v = int(probe.get("vnum") or 0)
    tasks = [("settings", SQL_SETTINGS), ("databases", sql_databases(v)), ("db_acl", SQL_DB_ACL),
             ("roles", sql_roles(bool(probe.get("can_authid")))), ("members", SQL_MEMBERS),
             ("role_db", SQL_ROLE_DB), ("role_settings", SQL_ROLE_SETTINGS)]
    if v >= 90500:
        tasks.append(("myssl", SQL_MYSSL))
    if v >= 100000 and not hba_file:
        tasks.append(("hba", SQL_HBA))
    if v >= 150000:
        tasks.append(("ident", SQL_IDENT))
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = dict((ex.submit(conn.query, sql), name) for name, sql in tasks)
        for f in as_completed(futs):
            name = futs[f]
            try:
                rep[name] = f.result()
            except PgError as e:
                rep[name] = None
                rep["errors"][name] = e.message
    if fnet is None:
        rep["net_skipped"] = True
    else:
        try:
            rep["net"] = fnet.result()
        except Exception as e:
            rep["net"] = None
            rep["errors"]["net"] = "%s: %s" % (type(e).__name__, e)
    ex_net.shutdown(wait=False)
    settings = dict((r["name"], r) for r in (rep.get("settings") or []))
    server_hba = (settings.get("hba_file") or {}).get("setting")
    rep["hba_main_file"] = server_hba
    rep["hba_rows"] = None
    rep["hba_source"] = None
    rep["hba_note"] = None
    if hba_file:
        try:
            rep["hba_rows"] = parse_hba_file(hba_file)
            rep["hba_source"] = "file"
            rep["hba_main_file"] = hba_file
        except PgError as e:
            rep["errors"]["hba_file"] = e.message
    elif rep.get("hba") is not None:
        rep["hba_rows"] = rep["hba"]
        rep["hba_source"] = "view"
    else:
        path, note = guess_local_hba(params.get("host"), server_hba, v)
        if path:
            try:
                rep["hba_rows"] = parse_hba_file(path)
                rep["hba_source"] = "file-auto"
                rep["hba_main_file"] = path
                rep["hba_note"] = note
            except PgError as e:
                rep["errors"]["hba_file"] = e.message
        else:
            rep["errors"]["hba_file"] = note
    rep["clusters"] = local_clusters()
    rep["elapsed"] = time.time() - t0
    rep["when"] = time.strftime("%H:%M:%S")
    return rep


# =============================================================================
#  Analiza: reguly pg_hba, role
# =============================================================================

TYPE_DESC = {
    "local": "gniazdo Unix (połączenie z tego samego komputera)",
    "host": "TCP/IP – z SSL lub bez",
    "hostssl": "TCP/IP – tylko połączenia szyfrowane SSL",
    "hostnossl": "TCP/IP – tylko połączenia BEZ SSL",
    "hostgssenc": "TCP/IP – tylko z szyfrowaniem GSSAPI",
    "hostnogssenc": "TCP/IP – tylko bez szyfrowania GSSAPI",
}

METHOD_DESC = {
    "trust": "brak uwierzytelniania – każdy pasujący do reguły loguje się bez hasła",
    "reject": "połączenie jest odrzucane",
    "scram-sha-256": "hasło weryfikowane metodą SCRAM-SHA-256 (zalecane)",
    "md5": "hasło MD5 (dla haseł zapisanych jako SCRAM użyje SCRAM) – przestarzałe",
    "password": "hasło przesyłane jawnym tekstem",
    "peer": "nazwa użytkownika systemu operacyjnego musi odpowiadać roli (tylko lokalnie)",
    "ident": "nazwa użytkownika podana przez serwer ident komputera klienta",
    "gss": "Kerberos / GSSAPI",
    "sspi": "Windows SSPI",
    "ldap": "hasło sprawdzane w serwerze LDAP",
    "radius": "hasło sprawdzane w serwerze RADIUS",
    "cert": "certyfikat klienta SSL",
    "pam": "PAM (moduły uwierzytelniania systemu)",
    "bsd": "BSD Authentication",
    "oauth": "OAuth",
}

TYPE_COVER = {"host": ("host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc")}


def _literal(tok):
    if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
        return tok[1:-1].replace('""', '"'), True
    return tok, False


class HbaRule(object):
    def __init__(self, d, main_file=None):
        self.line = d.get("line_number")
        self.rule_no = d.get("rule_number")
        self.file = d.get("file_name") or main_file
        self.main_file = main_file
        self.type = d.get("type") or ""
        self.databases = [str(x) for x in (d.get("database") or [])]
        self.users = [str(x) for x in (d.get("user_name") or [])]
        self.address = d.get("address")
        self.netmask = d.get("netmask")
        self.method = d.get("auth_method") or ""
        self.options = [str(x) for x in (d.get("options") or [])]
        self.error = d.get("error")
        self.issues = []
        self.severity = OK
        self.shadowed_by = None
        self.kind, self.net = self._net()

    def _net(self):
        if self.error:
            return "none", None
        if self.type == "local":
            return "local", None
        a = self.address
        if not a:
            return "none", None
        if a in ("all", "samehost", "samenet"):
            return a, None
        try:
            if self.netmask:
                bits = bin(int(ipaddress.ip_address(self.netmask))).count("1")
                return "net", ipaddress.ip_network("%s/%d" % (a, bits), strict=False)
            return "net", ipaddress.ip_network(a, strict=False)
        except ValueError:
            return "hostname", None

    @property
    def tcp(self):
        return self.type != "local"

    def is_loopback(self):
        return self.kind == "net" and self.net.is_loopback

    def is_world(self):
        return self.kind == "all" or (self.kind == "net" and self.net.prefixlen == 0)

    def ref(self):
        if self.file and self.main_file and os.path.abspath(self.file) != os.path.abspath(self.main_file):
            return "%s:%s" % (os.path.basename(self.file), self.line)
        return tr("linia %s") % self.line

    def line_label(self):
        if self.file and self.main_file and os.path.abspath(self.file) != os.path.abspath(self.main_file):
            return "%s:%s" % (os.path.basename(self.file), self.line)
        return str(self.line)

    def addr_text(self):
        if self.kind == "local":
            return tr("(lokalnie)")
        if self.kind == "net":
            n = self.net
            return str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n)
        return self.address or ""

    def short(self):
        """Krotki opis: 'host 10.0.0.0/8 → scram-sha-256'."""
        if self.type == "local":
            return "%s → %s" % (self.type, self.method)
        return "%s %s → %s" % (self.type, self.addr_text(), self.method)

    def top_issue(self):
        if not self.issues:
            return ""
        if self.shadowed_by is not None:
            return self.issues[0][1]
        best = max(self.issues, key=lambda x: x[0])
        return best[1]


def addr_desc(r):
    k = r.kind
    if k == "local":
        return tr("połączenia lokalne przez gniazdo Unix")
    if k == "all":
        return tr("dowolny adres IP (IPv4 i IPv6) – cały świat")
    if k == "samehost":
        return tr("dowolny z adresów IP tego serwera")
    if k == "samenet":
        return tr("dowolny adres z podsieci, do których bezpośrednio podłączony jest serwer")
    if k == "hostname":
        a = r.address or ""
        if a.startswith("."):
            return tr("dowolny host z domeny %s (sprawdzane przez DNS)") % a
        return tr("host o nazwie %s (sprawdzane przez DNS)") % a
    if k == "net":
        n = r.net
        ver = "IPv%d" % n.version
        if n.prefixlen == 0:
            return tr("dowolny adres %s – cały świat") % ver
        if n.is_loopback:
            return tr("tylko ten komputer (loopback)")
        scope = tr("sieć prywatna") if n.is_private else tr("adresy publiczne")
        if n.num_addresses == 1:
            return tr("pojedynczy host %s (%s)") % (n.network_address, scope)
        cnt = n.num_addresses
        cnt_txt = (tr("2^%d adresów") % (n.max_prefixlen - n.prefixlen) if cnt > 10 ** 9 else
                   "%s %s" % (fmt_int(cnt), plural(cnt, tr("adres"), tr("adresy"), tr("adresów"))))
        return "%s: %s – %s (%s)" % (scope, n.network_address, n.broadcast_address, cnt_txt)
    return "—"


def user_tok_desc(tok):
    lit, q = _literal(tok)
    if q:
        return tr("rola %s") % lit
    if tok == "all":
        return tr("wszystkie role")
    if tok.startswith("+"):
        return tr("członkowie roli %s (także pośrednio)") % tok[1:]
    if tok.startswith("/"):
        return tr("role pasujące do wyrażenia %s") % tok[1:]
    if tok.startswith("@"):
        return tr("role wymienione w pliku %s") % tok[1:]
    return tr("rola %s") % tok


def db_tok_desc(tok):
    lit, q = _literal(tok)
    if q:
        return tr("baza %s") % lit
    if tok == "all":
        return tr("wszystkie bazy (bez połączeń replikacyjnych)")
    if tok == "sameuser":
        return tr("baza o nazwie takiej jak rola")
    if tok in ("samerole", "samegroup"):
        return tr("baza, której nazwa to rola, do której należy użytkownik")
    if tok == "replication":
        return tr("połączenia replikacyjne (fizyczne)")
    if tok.startswith("/"):
        return tr("bazy pasujące do wyrażenia %s") % tok[1:]
    if tok.startswith("@"):
        return tr("bazy wymienione w pliku %s") % tok[1:]
    return tr("baza %s") % tok


def hba_covers(r, s):
    """Czy wczesniejsza regula r obejmuje wszystkie polaczenia reguly s (s nigdy nie zadziala)."""
    if s.type not in TYPE_COVER.get(r.type, (r.type,)):
        return False
    for d in s.databases:
        if d in r.databases or ("all" in r.databases and d != "replication"):
            continue
        return False
    for u in s.users:
        if u in r.users or "all" in r.users:
            continue
        return False
    if r.type == "local" or r.kind == "all":
        return True
    if r.kind == "net" and s.kind == "net":
        a, b = r.net, s.net
        if a.version != b.version:
            return False
        return b.network_address in a and b.broadcast_address in a
    if r.kind == s.kind and r.kind in ("samehost", "samenet"):
        return True
    if r.kind == "hostname" and s.kind == "hostname":
        return r.address == s.address
    return False


# =============================================================================
#  Firewall – znormalizowany model regul i ocena, czy nowe polaczenie TCP
#  na port bazy z danej sieci zostanie przepuszczone
# =============================================================================

DEC_RES = {"accept": "dozwolone", "drop": "zablokowane (DROP)", "reject": "odrzucane (REJECT)"}
DEC_VERB = {"accept": "dopuszcza", "drop": "blokuje (DROP)", "reject": "odrzuca (REJECT)",
            "jump": "przechodzi do", "goto": "przechodzi do", "return": "wraca", "vmap": "mapa werdyktów"}
WORLD4 = ipaddress.ip_network("0.0.0.0/0")
WORLD6 = ipaddress.ip_network("::/0")


class FwRule(object):
    def __init__(self, backend, table, chain, text, family=None):
        self.backend, self.table, self.chain, self.text = backend, table, chain, text
        self.family = family
        self.proto, self.proto_neg = None, False       # zbior nazw protokolow
        self.dports, self.dports_neg = None, False     # lista (od, do)
        self.saddr, self.saddr_neg = None, False       # lista sieci
        self.iif, self.iif_neg = None, False           # zbior interfejsow
        self.ct, self.ct_neg = None, False             # zbior stanow conntrack
        self.verdict, self.target = None, None
        self.unknown = []
        self.handle = None

    def mentions_port(self, port):
        return (self.dports is not None and not self.dports_neg
                and any(lo <= port <= hi for lo, hi in self.dports))

    def where(self):
        return "%s/%s" % (self.table, self.chain) if self.table else self.chain


def verdict_verb(r):
    v = tr(DEC_VERB.get(r.verdict, r.verdict or "-"))
    return "%s %s" % (v, r.target) if r.verdict in ("jump", "goto") and r.target else v


class FwChain(object):
    def __init__(self, table, name, family=None, hook=None, policy=None, prio=0):
        self.table, self.name, self.family = table, name, family
        self.hook, self.policy, self.prio = hook, policy, prio
        self.rules = []

    def label(self):
        return "%s/%s" % (self.table, self.name) if self.table else self.name


class Verdict(object):
    def __init__(self, decision, chain=None, rule=None, partial=None, mech=""):
        self.decision, self.chain, self.rule = decision, chain, rule
        self.partial = partial or []
        self.mech = mech
        self.all = []

    def reason(self):
        if self.rule is not None:
            return tr("reguła: %s") % self.rule.text
        if self.chain is not None:
            return tr("polityka domyślna łańcucha %s (%s)") % (self.chain.label(), self.chain.policy or "accept")
        return ""


def _port_one(s):
    if isinstance(s, int):
        return s
    s = str(s).strip()
    if s.isdigit():
        return int(s)
    return socket.getservbyname(s, "tcp")


def _port_range(v):
    if isinstance(v, dict) and "range" in v:
        return (_port_one(v["range"][0]), _port_one(v["range"][1]))
    if isinstance(v, int):
        return (v, v)
    s = str(v).strip()
    for sep in (":", "-"):
        if sep in s:
            a, b = s.split(sep, 1)
            return (_port_one(a), _port_one(b))
    p = _port_one(s)
    return (p, p)


def _to_nets(v):
    if isinstance(v, dict) and "prefix" in v:
        p = v["prefix"]
        return [ipaddress.ip_network("%s/%s" % (p["addr"], p["len"]), strict=False)]
    if isinstance(v, dict) and "range" in v:
        a, b = v["range"]
        return list(ipaddress.summarize_address_range(ipaddress.ip_address(a), ipaddress.ip_address(b)))
    if isinstance(v, str):
        if "-" in v and "/" not in v:
            a, b = v.split("-", 1)
            return list(ipaddress.summarize_address_range(ipaddress.ip_address(a.strip()),
                                                          ipaddress.ip_address(b.strip())))
        return [ipaddress.ip_network(v.strip(), strict=False)]
    raise ValueError(v)


def _net_rel(net, nets):
    """Czy siec net zawiera sie w liscie: 'all' (cala), 'some' (czesc), 'none'."""
    rel = "none"
    for s in nets:
        if s.version != net.version:
            continue
        if net.network_address in s and net.broadcast_address in s:
            return "all"
        if net.overlaps(s):
            rel = "some"
    return rel


def _short_nets(nets, n=4):
    s = ", ".join(str(x) for x in nets[:n])
    return s + (", …" if len(nets) > n else "")


def rule_applies(r, net, port):
    """Czy regula dotyczy nowego polaczenia TCP na port z sieci net: ('yes'|'partial'|'no', powody)."""
    why = []
    if r.ct is not None:
        if ("new" in r.ct) == r.ct_neg:
            return "no", None
    if r.iif is not None:
        only_lo = all(x in ("lo", "loopback") for x in r.iif)
        if only_lo and not r.iif_neg:
            return "no", None
        if not r.iif_neg:
            why.append(tr("tylko interfejs %s") % ", ".join(sorted(r.iif)))
        elif not only_lo:
            why.append(tr("oprócz interfejsu %s") % ", ".join(sorted(r.iif)))
    if r.family and r.family != net.version:
        return "no", None
    if r.proto is not None:
        if bool(r.proto & {"tcp", "6"}) == r.proto_neg:
            return "no", None
    if r.dports is not None:
        inside = any(lo <= port <= hi for lo, hi in r.dports)
        if inside == r.dports_neg:
            return "no", None
    if r.saddr is not None:
        rel = _net_rel(net, r.saddr)
        if r.saddr_neg:
            rel = {"all": "none", "none": "all", "some": "some"}[rel]
        if rel == "none":
            return "no", None
        if rel == "some":
            why.append(tr("tylko część adresów (%s%s)") % (tr("poza ") if r.saddr_neg else "", _short_nets(r.saddr)))
    why.extend(r.unknown)
    return ("partial" if why else "yes"), why


def eval_chain(fw, ch, net, port, depth=0):
    partial = []
    for r in ch.rules:
        a, why = rule_applies(r, net, port)
        if a == "no" or r.verdict is None:
            continue
        if r.verdict in ("jump", "goto"):
            sub = fw.chains.get((ch.table, r.target))
            if sub is None or depth > 8:
                partial.append((r, (why or []) + [tr("łańcuch %s nieznany") % r.target]))
                continue
            v = eval_chain(fw, sub, net, port, depth + 1)
            if a == "partial":
                if v.decision is not None:
                    partial.append((r, why + ["→ %s" % tr(DEC_RES.get(v.decision, v.decision))]))
                continue
            partial.extend(v.partial)
            if v.decision is not None:
                return v
            continue
        if r.verdict == "return":
            if a == "yes":
                return Verdict(None, ch, None, partial)
            partial.append((r, why))
            continue
        if r.verdict not in ("accept", "drop", "reject"):
            partial.append((r, (why or []) + [tr(DEC_VERB.get(r.verdict, r.verdict))]))
            continue
        if a == "partial":
            partial.append((r, why))
            continue
        return Verdict(r.verdict, ch, r, partial)
    return Verdict(ch.policy if ch.hook else None, ch, None, partial)


SHORT_MECH = {"nftables": "nft", "iptables-legacy": "legacy", "ip6tables-legacy": "legacy6",
              "ufw": "ufw", "firewalld": "firewalld"}


class Firewall(object):
    """Reguly jednego mechanizmu (nftables, iptables-legacy, ufw)."""

    def __init__(self, backend, label):
        self.backend, self.label = backend, label
        self.chains = {}
        self.input_chains = []
        self.rule_count = 0
        self.tables = []
        self.raw = ""

    def add_chain(self, ch):
        self.chains[(ch.table, ch.name)] = ch
        if ch.hook == "input":
            self.input_chains.append(ch)

    def rules(self):
        for ch in self.chains.values():
            for r in ch.rules:
                yield r

    def filters(self):
        for ch in self.input_chains:
            if ch.policy in ("drop", "reject"):
                return True
            for r in ch.rules:
                if r.verdict in ("drop", "reject", "jump", "goto", "vmap"):
                    return True
        return False

    def evaluate(self, net, port):
        res = []
        for ch in sorted(self.input_chains, key=lambda c: c.prio):
            if ch.family and ch.family != net.version:
                continue
            v = eval_chain(self, ch, net, port)
            if v.decision is None:
                v.decision = ch.policy or "accept"
            v.mech = self.label
            res.append(v)
        if not res:
            return None
        for v in res:
            if v.decision in ("drop", "reject"):
                v.partial = [p for x in res for p in x.partial]
                return v
        v = res[0]
        v.partial = [p for x in res for p in x.partial]
        return v


# ----------------------------------------------------------------------------- nftables

def _nft_text_map(text):
    res, table, chain, in_block = {}, None, None, False
    for ln in text.splitlines():
        s = ln.strip()
        m = re.match(r"table (\S+) (\S+) \{", s)
        if m:
            table, chain = (m.group(1), m.group(2)), None
            continue
        m = re.match(r"chain (\S+) \{", s)
        if m and table:
            chain = m.group(1)
            continue
        if re.match(r"(set|map|flowtable|counter|quota|limit|secmark|synproxy|ct (helper|timeout|expectation)) \S+ \{", s):
            in_block = True
            continue
        if s.startswith("}"):
            if in_block:
                in_block = False
            elif chain:
                chain = None
            else:
                table = None
            continue
        m = re.search(r"\s*# handle (\d+)$", s)
        if m and table and chain and not in_block:
            res[(table[0], table[1], chain, int(m.group(1)))] = s[:m.start()].strip()
    return res


def _nft_vals(right, lookup):
    if isinstance(right, str) and right.startswith("@"):
        elems = lookup(right[1:])
        return None if elems is None else _nft_vals(elems, lookup)
    if isinstance(right, list):
        out = []
        for x in right:
            v = _nft_vals(x, lookup)
            if v is None:
                return None
            out.extend(v)
        return out
    if isinstance(right, dict):
        if "set" in right:
            return _nft_vals(right["set"], lookup)
        if "elem" in right:
            return _nft_vals(right["elem"].get("val"), lookup)
        if "range" in right or "prefix" in right:
            return [right]
        return None
    return [right]


def _nft_match(fr, m, lookup):
    op, left, right = m.get("op", "=="), m.get("left"), m.get("right")
    if op not in ("==", "!=", "in") or not isinstance(left, dict):
        fr.unknown.append(tr("warunek %s") % op)
        return
    neg = op == "!="
    vals = _nft_vals(right, lookup)
    if vals is None:
        fr.unknown.append(tr("nieznany zbiór"))
        return
    if "payload" in left:
        pl = left["payload"]
        proto, field = pl.get("protocol"), pl.get("field")
        if field == "dport" and proto in ("tcp", "udp", "sctp", "dccp", "th"):
            if proto != "th" and fr.proto is None:
                fr.proto = {proto}
            try:
                fr.dports, fr.dports_neg = [_port_range(x) for x in vals], neg
            except (ValueError, TypeError, OSError):
                fr.unknown.append(tr("port docelowy"))
            return
        if field == "saddr" and proto in ("ip", "ip6"):
            fr.family = 4 if proto == "ip" else 6
            try:
                nets = []
                for x in vals:
                    nets.extend(_to_nets(x))
                fr.saddr, fr.saddr_neg = nets, neg
            except (ValueError, TypeError, KeyError):
                fr.unknown.append(tr("adres źródłowy"))
            return
        if (proto, field) in (("ip", "protocol"), ("ip6", "nexthdr")):
            fr.family = 4 if proto == "ip" else 6
            fr.proto, fr.proto_neg = set(str(x).lower() for x in vals), neg
            return
        if proto in ("icmp", "icmpv6", "igmp"):
            fr.proto = {proto}
            return
        if field == "daddr":
            fr.unknown.append(tr("adres docelowy"))
            return
        fr.unknown.append("%s %s" % (proto, field))
        return
    if "meta" in left:
        key = left["meta"].get("key")
        if key == "l4proto":
            fr.proto, fr.proto_neg = set(str(x).lower() for x in vals), neg
        elif key == "nfproto":
            fr.family = 4 if "ipv4" in vals else 6
        elif key in ("iifname", "iif"):
            fr.iif, fr.iif_neg = set(str(x) for x in vals), neg
        elif key == "iiftype":
            fr.iif, fr.iif_neg = ({"lo"} if "loopback" in vals else set(str(x) for x in vals)), neg
        else:
            fr.unknown.append("meta %s" % key)
        return
    if "ct" in left and left["ct"].get("key") == "state":
        fr.ct, fr.ct_neg = set(str(x).lower() for x in vals), neg
        return
    fr.unknown.append(tr("warunek %s") % next(iter(left), "?"))


def _nft_expr(fr, e, lookup):
    if not isinstance(e, dict) or not e:
        return
    k = next(iter(e))
    v = e[k]
    if k == "match":
        _nft_match(fr, v, lookup)
    elif k in ("accept", "drop", "reject", "return"):
        fr.verdict = k
    elif k in ("jump", "goto"):
        fr.verdict, fr.target = k, (v or {}).get("target")
    elif k == "xt":
        typ, name = (v or {}).get("type"), (v or {}).get("name", "?")
        if typ == "target":
            if name.upper() in ("ACCEPT", "DROP", "REJECT"):
                fr.verdict = name.lower()
            elif name.upper() not in ("LOG", "NFLOG"):
                fr.unknown.append(tr("cel iptables %s") % name)
        elif name != "comment":
            fr.unknown.append(tr("dopasowanie iptables %s") % name)
    elif k == "vmap":
        fr.verdict = "vmap"
    elif k in ("limit", "quota", "meter"):
        fr.unknown.append("limit (%s)" % k)


def parse_nft(json_text, text, exclude_tables=()):
    fw = Firewall("nft", "nftables")
    fw.raw = text or ""
    data = json.loads(json_text).get("nftables", [])
    lines = _nft_text_map(text or "")
    fam_map = {"ip": 4, "ip6": 6, "inet": None}
    sets, tables = {}, []
    for it in data:
        if "set" in it:
            s = it["set"]
            sets[(s["family"], s["table"], s["name"])] = s.get("elem", [])
        elif "table" in it:
            t = it["table"]
            if (t["family"], t["name"]) not in exclude_tables:
                tables.append("%s %s" % (t["family"], t["name"]))
    fw.tables = tables
    for it in data:
        if "chain" not in it:
            continue
        c = it["chain"]
        if c["family"] not in fam_map or (c["family"], c["table"]) in exclude_tables:
            continue
        hook = c.get("hook") if c.get("type", "filter") == "filter" and c.get("hook") == "input" else None
        fw.add_chain(FwChain("%s %s" % (c["family"], c["table"]), c["name"], fam_map[c["family"]],
                             hook=hook, policy=c.get("policy") if c.get("hook") else None, prio=c.get("prio", 0)))
    for it in data:
        if "rule" not in it:
            continue
        r = it["rule"]
        ch = fw.chains.get(("%s %s" % (r["family"], r["table"]), r["chain"]))
        if ch is None:
            continue
        txt = lines.get((r["family"], r["table"], r["chain"], r.get("handle"))) or tr("(reguła #%s)") % r.get("handle")
        fr = FwRule("nft", ch.table, ch.name, txt, family=ch.family)
        fr.handle = r.get("handle")

        def lookup(name, f=r["family"], t=r["table"]):
            return sets.get((f, t, name))
        for e in r.get("expr", []):
            _nft_expr(fr, e, lookup)
        ch.rules.append(fr)
        fw.rule_count += 1
    return fw


# ----------------------------------------------------------------------------- iptables-save

IPT_TARGETS = {"ACCEPT": "accept", "DROP": "drop", "REJECT": "reject", "RETURN": "return"}
IPT_NOVERDICT = ("LOG", "NFLOG", "ULOG", "AUDIT", "MARK", "CONNMARK", "TRACE", "NOTRACK", "CT", "TCPMSS", "CLASSIFY")
IPT_OK_MODULES = ("tcp", "udp", "multiport", "state", "conntrack", "comment")


def parse_iptables_save(text, family, label):
    import shlex
    fw = Firewall("iptables", label)
    fw.raw = text
    table = None
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("*"):
            table = ln[1:]
            if table == "filter":
                fw.tables.append("filter")
            continue
        if table != "filter" or ln == "COMMIT":
            continue
        if ln.startswith(":"):
            parts = ln[1:].split()
            name, pol = parts[0], (parts[1] if len(parts) > 1 else "-")
            fw.add_chain(FwChain("filter", name, family, hook="input" if name == "INPUT" else None,
                                 policy=None if pol == "-" else pol.lower()))
            continue
        if not ln.startswith("-A "):
            continue
        try:
            toks = shlex.split(ln)
        except ValueError:
            toks = ln.split()
        ch = fw.chains.get(("filter", toks[1]))
        if ch is None:
            ch = FwChain("filter", toks[1], family)
            fw.add_chain(ch)
        fr = FwRule("iptables", "filter", toks[1], ln[3:], family=family)
        i, neg = 2, False
        while i < len(toks):
            t = toks[i]
            a = toks[i + 1] if i + 1 < len(toks) else ""
            if t == "!":
                neg = True
                i += 1
                continue
            step = 2
            try:
                if t in ("-s", "--source", "--src"):
                    fr.saddr = []
                    for x in a.split(","):
                        fr.saddr.extend(_to_nets(x))
                    fr.saddr_neg = neg
                elif t in ("-p", "--protocol"):
                    fr.proto, fr.proto_neg = {a.lower()}, neg
                elif t in ("-i", "--in-interface"):
                    fr.iif, fr.iif_neg = {a.rstrip("+") if a != "lo" else "lo"}, neg
                elif t in ("--dport", "--destination-port"):
                    fr.dports, fr.dports_neg = [_port_range(a)], neg
                elif t in ("--dports", "--destination-ports"):
                    fr.dports, fr.dports_neg = [_port_range(x) for x in a.split(",")], neg
                elif t in ("--state", "--ctstate"):
                    fr.ct, fr.ct_neg = set(x.lower() for x in a.split(",")), neg
                elif t in ("-m", "--match"):
                    if a not in IPT_OK_MODULES:
                        fr.unknown.append(tr("moduł %s") % a)
                elif t in ("-j", "--jump", "-g", "--goto"):
                    if a in IPT_TARGETS:
                        fr.verdict = IPT_TARGETS[a]
                    elif a in IPT_NOVERDICT:
                        pass
                    elif ("filter", a) in fw.chains:
                        fr.verdict, fr.target = ("goto" if t in ("-g", "--goto") else "jump"), a
                    else:
                        fr.unknown.append(tr("cel %s") % a)
                    break                                   # dalej sa juz opcje celu
                elif t in ("-d", "--destination", "--dst"):
                    fr.unknown.append(tr("adres docelowy %s") % a)
                elif t in ("-o", "--out-interface", "--comment"):
                    pass
                elif t.startswith("-"):
                    fr.unknown.append(t)
                    step = 2 if a and not a.startswith("-") and a != "!" else 1
                else:
                    step = 1
            except (ValueError, OSError):
                fr.unknown.append("%s %s" % (t, a))
            i += step
            neg = False
        ch.rules.append(fr)
        fw.rule_count += 1
    return fw


# ----------------------------------------------------------------------------- ufw

def _ufw_ports(spec, profiles):
    """'5432/tcp', '22,5432:5440/tcp', '5432', nazwa profilu aplikacji -> [(proto|None, [(od, do)])]"""
    if spec in profiles:
        out = []
        for part in profiles[spec].split("|"):
            out.extend(_ufw_ports(part.strip(), {}))
        return out
    m = re.match(r"^([\d,:]+)(?:/(tcp|udp))?$", spec)
    if not m:
        raise ValueError(spec)
    return [(m.group(2), [_port_range(x) for x in m.group(1).split(",")])]


def parse_ufw(text, profiles):
    fw = Firewall("ufw", "ufw")
    fw.raw = text
    fw.active = bool(re.search(r"Status:\s*active", text))
    m = re.search(r"Default:\s*(\w+)\s*\(incoming\)", text)
    pol = {"deny": "drop", "reject": "reject", "allow": "accept"}.get(m.group(1).lower() if m else "", "drop")
    ch = FwChain("ufw", tr("ruch przychodzący"), hook="input", policy=pol)
    fw.add_chain(ch)
    in_rules = False
    for ln in text.splitlines():
        s = ln.strip()
        if re.match(r"^-+\s+-+\s+-+", s):
            in_rules = True
            continue
        if not in_rules or not s:
            continue
        cols = re.split(r"\s{2,}", s)
        if len(cols) < 3:
            continue
        to, action, frm = cols[0], cols[1].split(), cols[2]
        if not action or (len(action) > 1 and action[1].upper() != "IN"):
            continue
        v6 = "(v6)" in to or "(v6)" in frm
        to, frm = to.replace("(v6)", "").strip(), frm.replace("(v6)", "").strip()
        fr = FwRule("ufw", "ufw", ch.name, re.sub(r"\s{2,}", "  ", s))
        fr.family = 6 if v6 else 4
        mi = re.search(r"\s+on\s+(\S+)$", to)
        if mi:
            fr.iif = {mi.group(1)}
            to = to[:mi.start()].strip()
        specs = []
        for p in to.split():
            if p == "Anywhere":
                continue
            try:
                ipaddress.ip_network(p, strict=False)
                fr.unknown.append(tr("adres docelowy %s") % p)
                continue
            except ValueError:
                pass
            specs.append(p)
        if specs:
            try:
                groups = _ufw_ports(" ".join(specs), profiles)
                protos = set(g[0] for g in groups if g[0])
                if protos and None not in [g[0] for g in groups]:
                    fr.proto = protos
                fr.dports = [r for g in groups for r in g[1] if g[0] in (None, "tcp")]
            except (ValueError, OSError):
                fr.unknown.append(tr("port/aplikacja %s") % " ".join(specs))
        fparts = frm.split()
        if fparts and fparts[0] != "Anywhere":
            try:
                fr.saddr = _to_nets(fparts[0])
                fr.family = fr.saddr[0].version
            except ValueError:
                fr.unknown.append(tr("źródło %s") % fparts[0])
        if len(fparts) > 1:
            fr.unknown.append(tr("port źródłowy %s") % fparts[1])
        act = action[0].upper()
        fr.verdict = {"ALLOW": "accept", "LIMIT": "accept", "DENY": "drop", "REJECT": "reject"}.get(act)
        if act == "LIMIT":
            fr.unknown.append(tr("LIMIT (ograniczenie liczby połączeń)"))
        ch.rules.append(fr)
        fw.rule_count += 1
    return fw


# ----------------------------------------------------------------------------- firewalld

def _fwd_listall(text):
    z = {"target": "default", "interfaces": [], "sources": [], "services": [], "ports": [], "rich": []}
    key = None
    for ln in text.splitlines():
        if not ln.strip():
            continue
        m = re.match(r"^\s+([a-z][a-z -]*):\s*(.*)$", ln)
        if m and not ln.strip().startswith("rule "):
            key, val = m.group(1).strip(), m.group(2).strip()
            if key in ("interfaces", "sources", "services", "ports"):
                z[key] = val.split()
            elif key == "target":
                z["target"] = val
            continue
        if key == "rich rules" and ln.strip().startswith("rule"):
            z["rich"].append(ln.strip())
    return z


def _fwd_rich(rule, svc_ports, zone):
    import shlex
    try:
        toks = shlex.split(rule)
    except ValueError:
        toks = rule.split()
    fr = FwRule("firewalld", tr("strefa %s") % zone, "rich", rule)
    sec, action = None, None
    for t in toks:
        k, _, v = t.partition("=")
        if t == "rule":
            continue
        if k == "family" and v:
            fr.family = 4 if v == "ipv4" else 6
        elif t in ("source", "destination", "port", "service", "log", "audit", "limit", "protocol",
                   "icmp-block", "icmp-type", "forward-port", "source-port", "masquerade", "mark"):
            sec = t
            if t in ("icmp-block", "icmp-type", "forward-port", "masquerade", "mark"):
                return None
            if t == "destination":
                fr.unknown.append(tr("adres docelowy"))
            if t == "source-port":
                fr.unknown.append(tr("port źródłowy"))
            if t == "limit" and sec in ("accept",):
                fr.unknown.append("limit")
        elif t == "NOT" and sec == "source":
            fr.saddr_neg = True
        elif k == "address" and sec == "source":
            try:
                fr.saddr = _to_nets(v)
                fr.family = fr.saddr[0].version
            except ValueError:
                fr.unknown.append(tr("źródło %s") % v)
        elif k == "ipset" and sec == "source":
            fr.unknown.append("ipset %s" % v)
        elif k == "port" and sec == "port":
            try:
                fr.dports = [_port_range(v)]
            except (ValueError, OSError):
                fr.unknown.append("port %s" % v)
        elif k == "protocol" and sec == "port":
            fr.proto = {v.lower()}
        elif k == "value" and sec == "protocol":
            fr.proto = {v.lower()}
        elif k == "name" and sec == "service":
            ports = svc_ports.get(v)
            if ports is None:
                fr.unknown.append(tr("usługa %s") % v)
            else:
                fr.dports = [_port_range(p) for p, pr in ports if pr in ("tcp", "") and p]
        elif t in ("accept", "reject", "drop"):
            action, sec = t, t
        elif t == "limit" or k == "value":
            if sec in ("accept", "reject", "drop") or t == "limit":
                pass
    if action is None:
        return None
    fr.verdict = action
    return fr


class FirewalldFw(object):
    backend, label = "firewalld", "firewalld"

    def __init__(self, d):
        self.default = d.get("default") or "public"
        self.raw = ""
        self.svc = d.get("services") or {}
        self.zones = {}
        for name, text in (d.get("zones") or {}).items():
            self.zones[name] = _fwd_listall(text)
            self.raw += text + "\n"
        self.chains, self.input_chains, self.rule_count = {}, [], 0
        for name, z in self.zones.items():
            ch = FwChain("firewalld", tr("strefa %s") % name, hook="input",
                         policy={"ACCEPT": "accept", "DROP": "drop"}.get(z["target"], "reject"))
            deny, allow = [], []
            for rt in z["rich"]:
                fr = _fwd_rich(rt, self.svc, name)
                if fr is not None:
                    (allow if fr.verdict == "accept" else deny).append(fr)
            for p in z["ports"]:
                pp, _, proto = p.partition("/")
                fr = FwRule("firewalld", ch.table, ch.name, "port %s" % p)
                try:
                    fr.dports = [_port_range(pp)]
                except (ValueError, OSError):
                    continue
                fr.proto, fr.verdict = {proto or "tcp"}, "accept"
                allow.append(fr)
            for s in z["services"]:
                ports = self.svc.get(s)
                fr = FwRule("firewalld", ch.table, ch.name, tr("usługa %s") % s)
                if ports is None:
                    if s == "postgresql":
                        ports = [("5432", "tcp")]
                    else:
                        continue
                fr.dports = []
                for p, pr in ports:
                    if pr in ("tcp", "") and p:
                        try:
                            fr.dports.append(_port_range(p))
                        except (ValueError, OSError):
                            pass
                if not fr.dports:
                    continue
                fr.proto, fr.verdict = {"tcp"}, "accept"
                fr.text = tr("usługa %s (%s)") % (s, ", ".join("%s/%s" % (p, pr) for p, pr in ports))
                allow.append(fr)
            ch.rules = deny + allow
            self.rule_count += len(ch.rules)
            self.chains[(ch.table, ch.name)] = ch
            self.input_chains.append(ch)
            ch.zone = z

    def filters(self):
        return True

    def rules(self):
        for ch in self.input_chains:
            for r in ch.rules:
                yield r

    def evaluate(self, net, port):
        # 1) strefy przypisane do zrodla (adresu klienta)
        partial = []
        for name, z in self.zones.items():
            nets = []
            for s in z["sources"]:
                try:
                    nets.extend(_to_nets(s))
                except ValueError:
                    pass
            rel = _net_rel(net, nets) if nets else "none"
            ch = self.chains[("firewalld", tr("strefa %s") % name)]
            if rel == "all":
                v = eval_chain(self, ch, net, port)
                v.mech = tr("firewalld (strefa %s – źródło)") % name
                return v
            if rel == "some":
                partial.append((FwRule("firewalld", ch.table, ch.name, tr("źródła strefy %s") % name),
                                [tr("część adresów należy do strefy %s") % name]))
        # 2) strefy przypisane do interfejsow (ruch z sieci)
        zs = [n for n, z in self.zones.items() if [i for i in z["interfaces"] if i != "lo"]]
        if not zs:
            zs = [self.default] if self.default in self.zones else list(self.zones)[:1]
        res = []
        for n in zs:
            v = eval_chain(self, self.chains[("firewalld", tr("strefa %s") % n)], net, port)
            v.mech = tr("firewalld (strefa %s)") % n
            res.append(v)
        if not res:
            return None
        decs = set(v.decision for v in res)
        v = res[0]
        v.partial = partial + [p for x in res for p in x.partial]
        if len(decs) > 1:
            v.partial.append((FwRule("firewalld", "", "", tr("strefy %s") % ", ".join(zs)),
                              [tr("wynik zależy od interfejsu sieciowego")]))
        return v


class Model(object):
    """Dane z serwera po analizie."""

    def __init__(self, rep):
        self.rep = rep
        self.p = rep.get("probe") or {}
        self.errors = rep.get("errors") or {}
        self.settings = dict((r["name"], r) for r in (rep.get("settings") or []))
        self.dbs = rep.get("databases")
        self.roles = rep.get("roles")
        self.members = rep.get("members") or []
        self.role_db = {}
        for r in rep.get("role_db") or []:
            self.role_db[(r["rolname"], r["datname"])] = r
        self.role_settings = rep.get("role_settings") or []
        self.ident = rep.get("ident") or []
        self.acl = {}
        for a in rep.get("db_acl") or []:
            self.acl.setdefault(a["datname"], []).append(a)
        self.parents, self.children = {}, {}
        for m in self.members:
            self.parents.setdefault(m["member_name"], []).append(m)
            self.children.setdefault(m["role_name"], []).append(m)
        self.role_names = set(r["rolname"] for r in (self.roles or []))
        self.role_by_name = dict((r["rolname"], r) for r in (self.roles or []))
        self.db_names = set(d["datname"] for d in (self.dbs or []))
        self._closure = {}
        rows = rep.get("hba_rows")
        main = rep.get("hba_main_file")
        self.hba = None if rows is None else [HbaRule(d, main) for d in rows]
        self.role_issues = {}
        self.db_issues = {}
        if self.hba is not None:
            self._analyze_hba()
        self._analyze_roles()
        self._analyze_dbs()
        self.net = None
        if rep.get("net") is not None:
            try:
                self.net = NetModel(self, rep["net"])
            except Exception as e:
                self.errors["net"] = tr("Analiza sieci nie powiodła się: %s: %s") % (type(e).__name__, e)

    # -- pomocnicze
    def setting(self, name):
        r = self.settings.get(name)
        return None if r is None else r.get("setting")

    def memberships(self, role):
        if role in self._closure:
            return self._closure[role]
        seen, stack = set(), [role]
        while stack:
            x = stack.pop()
            for m in self.parents.get(x, []):
                g = m["role_name"]
                if g not in seen:
                    seen.add(g)
                    stack.append(g)
        self._closure[role] = seen
        return seen

    def match_user(self, rule, role):
        """True – regula dotyczy roli, None – byc moze (plik @ / blad wyrazenia), False – nie."""
        res = False
        for tok in rule.users:
            lit, q = _literal(tok)
            if q:
                if lit == role:
                    return True
                continue
            if tok == "all":
                return True
            if tok.startswith("+"):
                g = tok[1:]
                if g == role or g in self.memberships(role):
                    return True
                continue
            if tok.startswith("/"):
                try:
                    if re.search(tok[1:], role):
                        return True
                except re.error:
                    res = None
                continue
            if tok.startswith("@"):
                res = None
                continue
            if tok == role:
                return True
        return res

    def match_db(self, rule, db, role=None):
        res = False
        for tok in rule.databases:
            lit, q = _literal(tok)
            if q:
                if lit == db:
                    return True
                continue
            if tok == "all":
                return True
            if tok == "replication":
                continue
            if tok == "sameuser":
                if role is None:
                    if db in self.role_names:
                        res = None
                elif db == role:
                    return True
                continue
            if tok in ("samerole", "samegroup"):
                if role is None:
                    res = None
                elif db == role or db in self.memberships(role):
                    return True
                continue
            if tok.startswith("/"):
                try:
                    if re.search(tok[1:], db):
                        return True
                except re.error:
                    res = None
                continue
            if tok.startswith("@"):
                res = None
                continue
            if tok == db:
                return True
        return res

    # -- analiza regul pg_hba
    def _analyze_hba(self):
        rules = self.hba
        for r in rules:
            iss = []
            if r.error:
                iss.append((CRIT, tr("błąd w pliku: %s") % r.error))
                r.issues = iss
                continue
            meth, loop, world = r.method, r.is_loopback(), r.is_world()
            if meth == "trust":
                if not r.tcp:
                    who = tr("jako dowolna rola") if "all" in r.users else tr("jako ") + ", ".join(r.users)
                    iss.append((WARN, tr("trust lokalnie: każdy użytkownik systemu zaloguje się %s bez hasła") % who))
                elif loop:
                    iss.append((WARN, tr("trust z localhost: każdy proces na serwerze loguje się bez hasła")))
                else:
                    iss.append((CRIT, tr("trust z sieci: logowanie BEZ HASŁA z adresów %s") % r.addr_text()))
            elif meth == "password":
                if r.tcp and not loop and r.type not in ("hostssl", "hostgssenc"):
                    iss.append((WARN, tr("hasło przesyłane przez sieć jawnym tekstem (SSL nie jest wymagany)")))
                else:
                    iss.append((INFO, tr("metoda password wysyła hasło jawnym tekstem – lepiej scram-sha-256")))
            elif meth == "md5":
                iss.append((INFO, tr("md5 jest przestarzałe – zalecane scram-sha-256")))
            elif meth == "ident" and r.tcp:
                iss.append((WARN, tr("ident przez TCP opiera się na deklaracji komputera klienta")))
            if r.tcp and meth != "reject":
                if world:
                    what = []
                    if "all" in r.databases:
                        what.append(tr("wszystkie bazy"))
                    if "all" in r.users:
                        what.append(tr("wszystkie role"))
                    iss.append((WARN, tr("dostęp z dowolnego adresu%s") % (
                        " (%s)" % ", ".join(what) if what else "")))
                elif r.kind == "net" and not loop and not r.net.is_private and not r.net.is_link_local:
                    iss.append((INFO, tr("obejmuje publiczne adresy IP")))
                if not loop and meth != "cert":
                    if r.type == "hostnossl":
                        iss.append((INFO, tr("reguła dotyczy wyłącznie połączeń bez SSL")))
                    elif r.type in ("host", "hostnogssenc"):
                        iss.append((INFO, tr("SSL nie jest wymagany – rozważ hostssl")))
                if "replication" in r.databases and world:
                    iss.append((WARN, tr("replikacja dozwolona z dowolnego adresu")))
            if meth == "reject":
                iss.insert(0, (OK, tr("blokuje pasujące połączenia")))
            if self.roles is not None:
                for tok in r.users:
                    lit, q = _literal(tok)
                    name = None
                    if q:
                        name = lit
                    elif tok.startswith("+"):
                        name = tok[1:]
                    elif tok not in HBA_KEYWORDS and not tok.startswith(("/", "@")):
                        name = tok
                    if name and name not in self.role_names:
                        iss.append((INFO, tr("rola %s nie istnieje") % name))
            if self.dbs is not None:
                for tok in r.databases:
                    lit, q = _literal(tok)
                    name = lit if q else (tok if tok not in HBA_KEYWORDS and not tok.startswith(("/", "@")) else None)
                    if name and name not in self.db_names:
                        iss.append((INFO, tr("baza %s nie istnieje") % name))
            r.issues = iss
        for i, s in enumerate(rules):
            if s.error:
                continue
            for r in rules[:i]:
                if not r.error and hba_covers(r, s):
                    s.shadowed_by = r
                    s.issues.insert(0, (WARN, tr("nigdy nie zadziała – wcześniejsza reguła (%s) "
                                              "obejmuje te same połączenia") % r.ref()))
                    break
        for r in rules:
            sev = max([x[0] for x in r.issues] or [OK])
            if r.shadowed_by is not None and sev > WARN:
                sev = WARN
            r.severity = sev

    # -- analiza rol
    def _analyze_roles(self):
        for r in self.roles or []:
            name, login, iss = r["rolname"], r["rolcanlogin"], []
            if r["rolsuper"]:
                if login and r.get("oid") == 10:
                    iss.append((INFO, tr("superużytkownik instalacyjny")))
                elif login:
                    iss.append((WARN, tr("superużytkownik z prawem logowania")))
                else:
                    iss.append((INFO, tr("superużytkownik (bez logowania)")))
            if login and r.get("expired"):
                iss.append((WARN, tr("hasło wygasło (VALID UNTIL %s)") % (r.get("validuntil") or "")[:10]))
            pwd = r.get("pwd")
            if pwd == "MD5":
                iss.append((WARN, tr("hasło zapisane jako MD5 (przestarzałe) – ustaw je ponownie jako SCRAM")))
            if login and pwd == "brak":
                iss.append((INFO, tr("brak hasła – logowanie tylko metodami bez hasła (peer, cert, trust…)")))
            if r["rolreplication"] and not r["rolsuper"]:
                iss.append((INFO, tr("uprawnienie REPLICATION")))
            if r.get("rolbypassrls") and not r["rolsuper"]:
                iss.append((INFO, tr("omija zabezpieczenia wierszy (BYPASSRLS)")))
            if r["rolcreaterole"] and not r["rolsuper"]:
                iss.append((INFO, tr("może tworzyć i zmieniać role (CREATEROLE)")))
            if login and not name.startswith("pg_"):
                if self.hba is not None:
                    ok = [h for h in self.hba if not h.error and h.method != "reject"
                          and h.shadowed_by is None and self.match_user(h, name) is not False]
                    if not ok:
                        iss.append((INFO, tr("żadna reguła pg_hba nie pozwala tej roli się zalogować")))
                if self.role_db and not r["rolsuper"]:
                    if not any(v["c"] for (rn, dn), v in self.role_db.items() if rn == name):
                        iss.append((INFO, tr("brak prawa CONNECT do jakiejkolwiek bazy")))
            self.role_issues[name] = iss

    def _analyze_dbs(self):
        for d in self.dbs or []:
            name, iss = d["datname"], []
            if d.get("datconnlimit") == -2:
                iss.append((WARN, tr("baza oznaczona jako nieprawidłowa (przerwane DROP DATABASE)")))
            elif not d.get("datallowconn"):
                iss.append((OK, tr("połączenia zablokowane (datallowconn = false)")))
            elif self.hba is not None and not d.get("datistemplate"):
                ok = [h for h in self.hba if not h.error and h.method != "reject"
                      and h.shadowed_by is None and self.match_db(h, name) is not False]
                if not ok:
                    iss.append((INFO, tr("żadna reguła pg_hba nie pozwala połączyć się z tą bazą")))
            self.db_issues[name] = iss

    def rules_for(self, role=None, db=None):
        out = []
        for h in self.hba or []:
            if h.error:
                continue
            mu = True if role is None else self.match_user(h, role)
            md = True if db is None else self.match_db(h, db, role)
            if mu is False or md is False:
                continue
            out.append((h, mu is None or md is None))
        return out


# =============================================================================
#  Model widoku: zakladki, kolumny, wiersze, dokumenty szczegolow
# =============================================================================

class Column(object):
    def __init__(self, key, title, align="l", minw=4, maxw=40, flex=False, pref=32, prio=0):
        self.key, self.title, self.align = key, title, align
        self.minw, self.maxw, self.flex, self.pref = minw, maxw, flex, pref
        self.prio = prio  # 0 = zawsze widoczna; wieksza liczba = ukrywana wczesniej na waskim ekranie


class Row(object):
    def __init__(self, cells, sev=None, sev_col=None, style=None, detail=None, selectable=True):
        self.cells = dict((k, cell(v)) for k, v in cells.items())
        self.sev, self.sev_col, self.style = sev, sev_col, style
        self.detail, self.selectable = detail, selectable
        self.search = " ".join(self.cells.values()).lower()


class Tab(object):
    def __init__(self, key, title):
        self.key, self.title = key, title
        self.columns, self.rows, self.info = [], [], []
        self.error = None          # (komunikat, podpowiedz)
        self.sel = self.top = 0
        self.filter = ""
        self.count = None
        self.badge = OK

    def visible(self, show_system=True):
        rows = self.rows
        if not show_system:
            rows = [r for r in rows if r.style != "system"]
        if self.filter:
            f = self.filter.lower()
            rows = [r for r in rows if r.selectable and f in r.search]
        return rows


class Doc(object):
    """Tresc okna szczegolow; renderowana do linii przy znanej szerokosci."""

    def __init__(self, title=""):
        self.title = title
        self.blocks = []

    def h(self, text):
        self.blocks.append(("h", text))
        return self

    def kv(self, key, value, sev=None, keyw=26):
        self.blocks.append(("kv", key, cell(value) if not isinstance(value, str) else value, sev, keyw))
        return self

    def p(self, text, role="text"):
        self.blocks.append(("p", text, role))
        return self

    def item(self, text, sev=None):
        self.blocks.append(("item", text, sev))
        return self

    def table(self, headers, rows, sevs=None, sevcol=None):
        self.blocks.append(("table", headers, rows, sevs, sevcol))
        return self

    def blank(self):
        self.blocks.append(("blank",))
        return self

    def pre(self, text):
        self.blocks.append(("pre", text))
        return self

    def render(self, width):
        out = []
        bullet = "• " if UNICODE else "* "
        for b in self.blocks:
            t = b[0]
            if t == "h":
                if out and out[-1]:
                    out.append([])
                out.append([(U(b[1]), "head")])
            elif t == "blank":
                out.append([])
            elif t == "pre":
                w = max(10, width - 2)
                for ln in U(b[1]).expandtabs(4).splitlines():
                    while True:
                        part, n = clip(ln, w)
                        out.append([("  " + part, "code")])
                        ln = ln[len(part):]
                        if not ln:
                            break
                        ln = "    " + ln
            elif t == "kv":
                _, k, v, sev, keyw = b
                keyw = min(keyw, max(10, width // 3))
                role = "sev%d" % sev if sev is not None else "text"
                lines = wrap(v, width - keyw - 3) if v != "" else [""]
                out.append([("  " + fit(k, keyw) + " ", "key"), (lines[0], role)])
                for ln in lines[1:]:
                    out.append([(" " * (keyw + 3), "text"), (ln, role)])
            elif t == "p":
                for ln in wrap(b[1], width - 2):
                    out.append([("  " + ln, b[2])])
            elif t == "item":
                _, text, sev = b
                if sev is None:
                    lines = wrap(text, width - 4)
                    out.append([("  " + bullet + lines[0], "text")])
                    for ln in lines[1:]:
                        out.append([("    " + ln, "text")])
                else:
                    lab = " %s " % sev_label(sev)
                    labw = 13
                    lines = wrap(text, width - labw - 3)
                    out.append([("  ", "text"), (lab, "sev%d" % sev), (" " * (labw - sw(lab)) + " ", "text"),
                                (lines[0], "text")])
                    for ln in lines[1:]:
                        out.append([(" " * (labw + 3), "text"), (ln, "text")])
            elif t == "table":
                _, headers, rows, sevs, sevcol = b
                cols = [Column(str(i), h, maxw=60) for i, h in enumerate(headers)]
                rws = [Row(dict((str(i), v) for i, v in enumerate(r))) for r in rows]
                ws = fit_columns(cols, rws, width - 2, sep=2)
                out.append([("  " + "  ".join(fit(h, ws[i]) for i, h in enumerate(headers)), "thead")])
                for ri, r in enumerate(rws):
                    segs = [("  ", "text")]
                    for i in range(len(cols)):
                        role = "text"
                        if sevs is not None and sevcol == i and sevs[ri] is not None:
                            role = "sev%d" % sevs[ri]
                        segs.append((fit(r.cells.get(str(i), ""), ws[i]), role))
                        if i < len(cols) - 1:
                            segs.append(("  ", "text"))
                    out.append(segs)
        while out and not out[-1]:
            out.pop()
        return out


def visible_columns(cols, rows, avail, sep=1, pad=0):
    """Na waskim ekranie ukrywa kolumny o najnizszym priorytecie (najwyzsza liczba prio)."""
    cols = list(cols)

    def comfort(c):
        w = sw(U(c.title))
        for r in rows:
            if r.selectable:
                w = max(w, sw(U(r.cells.get(c.key, ""))))
        return max(c.minw, min(w, c.maxw, 10)) + 2 * pad
    widths = dict((c.key, comfort(c)) for c in cols)
    while len(cols) > 1:
        need = sum(widths[c.key] for c in cols) + sep * (len(cols) - 1)
        cand = [c for c in cols if c.prio > 0]
        if need <= avail or not cand:
            break
        drop = max(cand, key=lambda c: (c.prio, cols.index(c)))
        cols.remove(drop)
    return cols


def fit_columns(cols, rows, avail, sep=1, pad=0):
    """Szerokosci kolumn: naturalne, a gdy brakuje miejsca – najpierw zwezane sa kolumny
    zwykle (najszersza najpierw), kolumna elastyczna (opisowa) zachowuje szerokosc preferowana."""
    n = len(cols)
    if n == 0:
        return []
    space = avail - sep * (n - 1)
    nat, floor = [], []
    for c in cols:
        w = sw(U(c.title))
        for r in rows:
            if r.selectable:
                v = r.cells.get(c.key, "")
                if v:
                    w = max(w, sw(U(v)))
        nat.append(max(c.minw, min(w, c.maxw)) + 2 * pad)
        floor.append(c.minw + 2 * pad)
    flex = [i for i, c in enumerate(cols) if c.flex] or [n - 1]

    def grow(extra):
        for k, i in enumerate(flex):
            nat[i] += extra // len(flex) + (1 if k < extra % len(flex) else 0)

    if sum(nat) <= space:
        grow(space - sum(nat))
        return nat
    # brakuje miejsca: kazda kolumna oddaje czesc swojego nadmiaru ponad minimum,
    # proporcjonalnie do tego nadmiaru (szerokie kolumny tracą najwiecej)
    need = sum(nat) - space
    excess = [nat[i] - floor[i] for i in range(n)]
    tot = sum(excess)
    if tot > 0:
        cut = [min(excess[i], need * excess[i] / float(tot)) for i in range(n)]
        icut = [int(x) for x in cut]
        rest = min(need, tot) - sum(icut)
        for i in sorted(range(n), key=lambda i: cut[i] - icut[i], reverse=True):
            if rest <= 0:
                break
            if icut[i] < excess[i]:
                icut[i] += 1
                rest -= 1
        for i in range(n):
            nat[i] -= icut[i]
    total = sum(nat)
    while total > space:                             # minima za duze – zwezamy dalej
        i = max(range(n), key=lambda k: nat[k])
        if nat[i] <= 1 + 2 * pad:
            break
        nat[i] -= 1
        total -= 1
    return nat


ERR_NAMES = {"settings": "Ustawienia serwera", "databases": "Lista baz", "db_acl": "Uprawnienia baz",
             "roles": "Role", "members": "Członkostwa ról", "role_db": "Uprawnienia ról do baz",
             "role_settings": "Ustawienia ról", "hba": "Widok pg_hba_file_rules",
             "hba_file": "Reguły pg_hba", "ident": "Mapowania pg_ident", "myssl": "Status SSL",
             "net": "Sieć i firewall"}


# ----------------------------------------------------------------------------- Bazy danych

def build_db_tab(m):
    t = Tab("db", tr("Bazy danych"))
    t.columns = [Column("name", tr("Baza"), minw=8, maxw=30), Column("owner", tr("Właściciel"), minw=6, maxw=20, prio=3),
                 Column("size", tr("Rozmiar"), "r", minw=7, maxw=10, prio=2),
                 Column("sess", tr("Sesje"), "r", minw=5, maxw=6, prio=5),
                 Column("enc", tr("Kodowanie"), minw=6, maxw=10, prio=7), Column("coll", "Collate", minw=6, maxw=14, prio=8),
                 Column("conn", tr("Łączenie"), minw=6, maxw=18, prio=6),
                 Column("acl", tr("Prawo CONNECT mają"), minw=10, maxw=50, flex=True, pref=26),
                 Column("note", tr("Uwagi"), maxw=60, minw=6, prio=4)]
    if m.dbs is None:
        t.error = (m.errors.get("databases", tr("Nie udało się pobrać listy baz.")), None)
        return t
    total = 0
    for d in m.dbs:
        name = d["datname"]
        if d.get("size") is not None:
            total += int(d["size"])
        if d.get("datconnlimit") == -2:
            conn = tr("NIE (uszkodzona)")
        elif not d.get("datallowconn"):
            conn = tr("NIE")
        elif d.get("datconnlimit", -1) >= 0:
            conn = tr("tak, limit %d") % d["datconnlimit"]
        else:
            conn = tr("tak")
        if d.get("datistemplate"):
            conn += tr(", szablon")
        iss = m.db_issues.get(name, [])
        sev = max([x[0] for x in iss] or [OK])
        note = ""
        if iss:
            note = max(iss, key=lambda x: x[0])[1]
        t.rows.append(Row({"name": name, "owner": d.get("owner"), "size": fmt_bytes(d.get("size")),
                           "sess": d.get("sessions"), "enc": d.get("encoding"), "coll": d.get("datcollate"),
                           "conn": conn, "acl": connect_summary(m, name), "note": note},
                          sev=sev if iss else None, sev_col="note",
                          style="dim" if d.get("datistemplate") else None,
                          detail=(lambda d=d: db_doc(m, d))))
    t.count = len(m.dbs)
    t.badge = max([r.sev or OK for r in t.rows] or [OK])
    unknown = sum(1 for d in m.dbs if d.get("size") is None and d.get("datconnlimit") != -2)
    t.info.append([(tr("%d %s, łącznie %s, aktywne sesje: %s") % (
        len(m.dbs), plural(len(m.dbs), tr("baza"), tr("bazy"), tr("baz")), fmt_bytes(total),
        sum(int(d.get("sessions") or 0) for d in m.dbs)), "bold")])
    if unknown:
        t.info.append([(tr("Rozmiar nieznany dla %d %s – brak prawa CONNECT (potrzebne pg_read_all_stats).")
                        % (unknown, plural(unknown, tr("bazy") if LANG == "pl" else tr("baza"), tr("baz"), tr("baz"))), "dim")])
    if m.errors.get("db_acl"):
        t.info.append([(tr("Uprawnienia baz niedostępne: ") + m.errors["db_acl"], "sev2")])
    return t


def connect_summary(m, db):
    acl = [a for a in m.acl.get(db, []) if a["priv"] == "CONNECT"]
    if not acl and db not in m.acl:
        return "?"
    names = sorted(set(a["grantee"] for a in acl))
    if "PUBLIC" in names:
        return tr("wszyscy (PUBLIC)")
    if not names:
        return tr("tylko superużytkownicy")
    return ", ".join(names)


def db_doc(m, d):
    name = d["datname"]
    doc = Doc(tr("Baza danych: %s") % name)
    doc.h(tr("Informacje"))
    doc.kv(tr("Właściciel"), d.get("owner"))
    doc.kv(tr("Rozmiar"), fmt_bytes(d.get("size")) or tr("nieznany (brak prawa CONNECT)"))
    doc.kv(tr("Aktywne sesje"), d.get("sessions"))
    doc.kv(tr("Kodowanie"), d.get("encoding"))
    doc.kv("LC_COLLATE / LC_CTYPE", "%s / %s" % (d.get("datcollate"), d.get("datctype")))
    doc.kv(tr("Przestrzeń tabel"), d.get("tablespace"))
    doc.kv(tr("Szablon"), yn(d.get("datistemplate")))
    doc.kv(tr("Połączenia dozwolone"), yn(d.get("datallowconn")))
    lim = d.get("datconnlimit")
    doc.kv(tr("Limit połączeń"), tr("bez limitu") if lim == -1 else (tr("baza nieprawidłowa") if lim == -2 else lim))
    doc.kv("OID", d.get("oid"))
    if d.get("comment"):
        doc.kv(tr("Komentarz"), d["comment"])
    iss = m.db_issues.get(name, [])
    if iss:
        doc.h(tr("Ocena"))
        for sev, text in iss:
            doc.item(text, sev)

    doc.h(tr("Uprawnienia do bazy (ACL)"))
    acl = m.acl.get(name)
    if acl is None:
        doc.p(tr("Brak danych o uprawnieniach."))
    else:
        if acl and acl[0].get("is_default"):
            doc.p(tr("Uprawnienia domyślne (nie było GRANT/REVOKE): PUBLIC ma CONNECT i TEMPORARY, "
                  "właściciel ma wszystkie prawa."))
        by = {}
        for a in acl:
            by.setdefault(a["grantee"], []).append(a)
        rows = []
        for g in sorted(by, key=lambda x: (x != "PUBLIC", x)):
            privs = ", ".join(a["priv"] + (tr(" (z GRANT OPTION)") if a["grantable"] else "") for a in by[g])
            rows.append([g, privs, ", ".join(sorted(set(a["grantor"] for a in by[g])))])
        doc.table([tr("Komu"), tr("Uprawnienia"), tr("Nadał")], rows)
        doc.p(tr("CONNECT – łączenie się z bazą; CREATE – tworzenie schematów; "
              "TEMPORARY – tworzenie tabel tymczasowych."), "dim")

    doc.h(tr("Role z logowaniem, które mogą łączyć się z bazą (CONNECT)"))
    if not m.role_db:
        doc.p(tr("Brak danych."))
    else:
        names = []
        for r in sorted(m.roles or [], key=lambda x: x["rolname"].lower()):
            if r["rolcanlogin"] and (r["rolname"], name) in m.role_db and m.role_db[(r["rolname"], name)]["c"]:
                names.append(r["rolname"] + (tr(" (superużytkownik)") if r["rolsuper"] else ""))
        doc.p(", ".join(names) if names else tr("żadna"))

    doc.h(tr("Reguły pg_hba dotyczące tej bazy (w kolejności sprawdzania)"))
    if m.hba is None:
        doc.p(tr("Reguły pg_hba są niedostępne."))
    else:
        rows, sevs = [], []
        for h, maybe in m.rules_for(db=name):
            rows.append([h.line_label(), h.type, h.addr_text(), ", ".join(h.users), h.method,
                         sev_label(h.severity) + (tr(" (przesłonięta)") if h.shadowed_by else "")
                         + (tr(" – być może") if maybe else "")])
            sevs.append(h.severity)
        if rows:
            doc.table([tr("Linia"), tr("Typ"), tr("Skąd"), tr("Kto"), tr("Metoda"), tr("Ocena")], rows, sevs, 5)
        else:
            doc.p(tr("Żadna reguła nie obejmuje tej bazy – połączenie nie jest możliwe."), "sev2")
    return doc


# ----------------------------------------------------------------------------- pg_hba

def build_hba_tab(m):
    t = Tab("hba", tr("Dostęp pg_hba"))
    t.columns = [Column("line", tr("Linia"), "r", minw=5, maxw=14), Column("type", tr("Typ"), minw=5, maxw=12, prio=1),
                 Column("addr", tr("Skąd (adres)"), minw=9, maxw=26), Column("db", tr("Dokąd (bazy)"), minw=8, maxw=24),
                 Column("user", tr("Kto (role)"), minw=8, maxw=24), Column("method", tr("Metoda"), minw=6, maxw=13),
                 Column("risk", tr("Ocena"), minw=9, maxw=9),
                 Column("note", tr("Uwagi"), minw=12, maxw=100, flex=True, pref=44, prio=2)]
    rep = m.rep
    if m.hba is None:
        msg = m.errors.get("hba_file") or m.errors.get("hba") or tr("Reguły pg_hba są niedostępne.")
        prog = os.path.basename(sys.argv[0]) or "pgdiag.py"
        t.error = (msg, tr("Najprościej: uruchom „sudo -u postgres python3 %s” i połącz się bez hasła "
                        "przez gniazdo lokalne (puste pole Host). Można też wpisać ścieżkę pliku "
                        "w polu pg_hba.conf.") % prog)
        return t
    for r in m.hba:
        if r.error:
            cells = {"line": r.line_label(), "type": tr("BŁĄD"), "addr": "", "db": "", "user": "",
                     "method": "", "risk": sev_label(CRIT), "note": r.error}
        else:
            cells = {"line": r.line_label(), "type": r.type, "addr": r.addr_text(),
                     "db": ", ".join(r.databases), "user": ", ".join(r.users),
                     "method": r.method, "risk": sev_label(r.severity), "note": r.top_issue()}
        t.rows.append(Row(cells, sev=r.severity, sev_col="risk",
                          style="dim" if r.shadowed_by is not None else None,
                          detail=(lambda r=r: hba_doc(m, r))))
    t.count = len(m.hba)
    t.badge = max([r.severity for r in m.hba] or [OK])
    src = rep.get("hba_source")
    path = rep.get("hba_main_file") or "?"
    if src == "view":
        t.info.append([(tr("Źródło: "), "dim"), (tr("widok pg_hba_file_rules"), "bold"), (tr(" – plik %s") % path, "dim")])
    else:
        t.info.append([(tr("Źródło: "), "dim"), (tr("plik %s") % path, "bold"),
                       (tr(" (odczyt lokalny%s)") % ("; " + rep["hba_note"] if rep.get("hba_note") else ""), "dim")])
    t.info.append([(tr("Reguły są sprawdzane od góry – użyta zostaje pierwsza pasująca (typ, baza, rola, adres). "
                    "Enter – szczegóły reguły."), "dim")])
    errs = sum(1 for r in m.hba if r.error)
    if errs:
        t.info.append([(tr(" KRYTYCZNE "), "sev3"), (tr(" Plik zawiera %d %s – przy przeładowaniu serwer odrzuca "
                       "zmiany i nadal używa poprzedniej wersji reguł.") % (errs, plural(errs, tr("błąd"), tr("błędy"), tr("błędów"))),
                       "sev2")])
    return t


def hba_doc(m, r):
    doc = Doc(tr("Reguła pg_hba – %s") % r.ref())
    if r.error:
        doc.h(tr("Błąd w regule"))
        doc.p(r.error, "sev3")
        doc.kv(tr("Plik"), r.file)
        doc.kv(tr("Linia"), r.line)
        doc.p(tr("PostgreSQL odrzuca cały plik pg_hba.conf, jeśli zawiera błąd: przy przeładowaniu "
              "(pg_ctl reload / SIGHUP) zostaje stara wersja reguł, a przy starcie serwer się nie uruchomi."))
        return doc
    doc.h(tr("Co oznacza ta reguła"))
    doc.kv(tr("Kanał (typ)"), "%s – %s" % (r.type, tr(TYPE_DESC.get(r.type, ""))))
    doc.kv(tr("Skąd (adres)"), "%s – %s" % (r.addr_text(), addr_desc(r)) if r.tcp else addr_desc(r))
    doc.kv(tr("Dokąd (bazy)"), "; ".join("%s: %s" % (x, db_tok_desc(x)) for x in r.databases))
    doc.kv(tr("Kto (role)"), "; ".join("%s: %s" % (x, user_tok_desc(x)) for x in r.users))
    doc.kv(tr("Jak (metoda)"), "%s – %s" % (r.method, tr(METHOD_DESC.get(r.method, ""))))
    if r.options:
        doc.kv(tr("Opcje"), " ".join(r.options))
    doc.kv(tr("Plik"), r.file or "?")
    doc.kv(tr("Linia"), r.line)
    if r.rule_no:
        doc.kv(tr("Numer reguły"), r.rule_no)

    doc.h(tr("Ocena"))
    if r.issues:
        for sev, text in sorted(r.issues, key=lambda x: -x[0]):
            if r.shadowed_by is not None and sev > WARN:
                doc.item(text + tr(" (obecnie nie działa, bo reguła jest przesłonięta – ale zadziała po zmianie "
                                "kolejności lub usunięciu reguły %s)") % r.shadowed_by.ref(), WARN)
            else:
                doc.item(text, sev)
    else:
        doc.item(tr("brak uwag"), OK)
    if r.shadowed_by is not None:
        s = r.shadowed_by
        doc.p(tr("Wcześniejsza reguła (%s: %s; bazy %s; role %s) pasuje do wszystkich połączeń, które "
              "pasowałyby do tej reguły, więc ta nigdy nie jest używana.")
              % (s.ref(), s.short(), ", ".join(s.databases), ", ".join(s.users)))

    doc.h(tr("Role z logowaniem, których dotyczy"))
    if m.roles is None:
        doc.p(tr("Lista ról niedostępna."))
    else:
        yes, maybe = [], []
        for ro in sorted(m.roles, key=lambda x: x["rolname"].lower()):
            if not ro["rolcanlogin"]:
                continue
            res = m.match_user(r, ro["rolname"])
            if res is True:
                yes.append(ro["rolname"])
            elif res is None:
                maybe.append(ro["rolname"])
        doc.p(", ".join(yes) if yes else tr("żadna"))
        if maybe:
            doc.p(tr("Być może (zależy od pliku @ lub wyrażenia): ") + ", ".join(maybe), "dim")

    doc.h(tr("Bazy, których dotyczy"))
    if "replication" in r.databases:
        doc.p(tr("połączenia replikacyjne (np. pg_basebackup, standby)"))
    if m.dbs is not None:
        dbs = [d["datname"] for d in m.dbs if d.get("datallowconn") and m.match_db(r, d["datname"]) is not False]
        if dbs or "replication" not in r.databases:
            doc.p(", ".join(dbs) if dbs else tr("żadna z istniejących baz"))

    mp = [o.split("=", 1)[1] for o in r.options if o.startswith("map=")]
    if mp and m.ident:
        rows = [[x.get("map_name"), x.get("sys_name"), x.get("pg_username"), x.get("error") or ""]
                for x in m.ident if x.get("map_name") in mp]
        doc.h(tr("Mapowanie użytkowników (pg_ident.conf: %s)") % ", ".join(mp))
        if rows:
            doc.table([tr("Mapa"), tr("Użytkownik systemu"), tr("Rola PostgreSQL"), tr("Błąd")], rows)
        else:
            doc.p(tr("Brak wpisów dla tej mapy w pg_ident.conf."), "sev2")

    doc.h(tr("Jak PostgreSQL stosuje reguły"))
    doc.p(tr("Serwer przegląda reguły od góry i bierze pierwszą, która pasuje do typu połączenia, adresu "
          "klienta, bazy i roli. Dalsze reguły nie są sprawdzane – także wtedy, gdy uwierzytelnienie "
          "się nie powiedzie. Po przejściu reguły rola potrzebuje jeszcze prawa CONNECT do bazy."), "dim")
    return doc


# ----------------------------------------------------------------------------- Role

def role_attrs(r):
    a = []
    if r["rolsuper"]:
        a.append("SUPERUSER")
    if r["rolcreatedb"]:
        a.append("CREATEDB")
    if r["rolcreaterole"]:
        a.append("CREATEROLE")
    if r["rolreplication"]:
        a.append("REPLICATION")
    if r.get("rolbypassrls"):
        a.append("BYPASSRLS")
    if not r["rolinherit"]:
        a.append("NOINHERIT")
    return a


def build_roles_tab(m):
    t = Tab("roles", tr("Role"))
    t.columns = [Column("name", tr("Rola"), minw=12, maxw=26), Column("login", "Login", minw=5, maxw=5),
                 Column("attrs", tr("Atrybuty"), minw=8, maxw=30, prio=2), Column("pwd", tr("Hasło"), minw=5, maxw=6, prio=3),
                 Column("valid", tr("Ważne do"), minw=8, maxw=10, prio=5),
                 Column("limit", "Limit", "r", minw=5, maxw=6, prio=6),
                 Column("member", tr("Należy do"), minw=8, maxw=24, prio=4),
                 Column("note", tr("Uwagi"), minw=12, maxw=90, flex=True, pref=40)]
    if m.roles is None:
        t.error = (m.errors.get("roles", tr("Nie udało się pobrać listy ról.")), None)
        return t
    roles = sorted(m.roles, key=lambda r: (r["rolname"].startswith("pg_"), not r["rolcanlogin"], r["rolname"].lower()))
    for r in roles:
        name = r["rolname"]
        vu = r.get("validuntil")
        if not vu:
            valid = ""
        elif vu == "infinity":
            valid = tr("bez limitu")
        else:
            valid = vu[:10]
        iss = m.role_issues.get(name, [])
        sev = max([x[0] for x in iss] or [OK])
        note = max(iss, key=lambda x: x[0])[1] if iss else ""
        system = name.startswith("pg_")
        t.rows.append(Row({"name": name, "login": yn(r["rolcanlogin"]), "attrs": " ".join(role_attrs(r)),
                           "pwd": (("?" if r.get("pwd") is None else tr(r["pwd"])) if r["rolcanlogin"]
                                   else ("" if r.get("pwd") in (None, "brak") else tr(r["pwd"]))),
                           "valid": valid,
                           "limit": "" if r["rolconnlimit"] == -1 else r["rolconnlimit"],
                           "member": ", ".join(sorted(x["role_name"] for x in m.parents.get(name, []))),
                           "note": note},
                          sev=sev if iss else None, sev_col="note",
                          style="system" if system else ("bold" if r["rolsuper"] else None),
                          detail=(lambda r=r: role_doc(m, r))))
    login = sum(1 for r in m.roles if r["rolcanlogin"])
    sup = sum(1 for r in m.roles if r["rolsuper"])
    nsys = sum(1 for r in m.roles if r["rolname"].startswith("pg_"))
    t.count = len(m.roles) - nsys
    t.badge = max([r.sev or OK for r in t.rows] or [OK])
    t.info.append([(tr("%d %s użytkownika (+%d systemowych pg_*): %d z logowaniem, %d %s")
                    % (len(m.roles) - nsys, plural(len(m.roles) - nsys, tr("rola"), tr("role"), tr("ról")), nsys, login, sup,
                       plural(sup, tr("superużytkownik"), tr("superużytkowników"), tr("superużytkowników"))), "bold"),
                   ])
    if not m.p.get("can_authid"):
        t.info.append([(tr("Typ hasła (SCRAM/MD5/brak) widzi tylko superużytkownik – kolumna Hasło pokazuje „?”."), "dim")])
    return t


def role_doc(m, r):
    name = r["rolname"]
    doc = Doc(tr("Rola: %s") % name)
    doc.h(tr("Atrybuty"))
    doc.kv(tr("Logowanie (LOGIN)"), yn(r["rolcanlogin"]))
    doc.kv(tr("Superużytkownik"), yn(r["rolsuper"]), WARN if r["rolsuper"] else None)
    doc.kv(tr("Tworzenie baz (CREATEDB)"), yn(r["rolcreatedb"]))
    doc.kv(tr("Tworzenie ról (CREATEROLE)"), yn(r["rolcreaterole"]))
    doc.kv(tr("Replikacja (REPLICATION)"), yn(r["rolreplication"]))
    doc.kv(tr("Omijanie RLS (BYPASSRLS)"), yn(r.get("rolbypassrls")))
    doc.kv(tr("Dziedziczenie (INHERIT)"), yn(r["rolinherit"]))
    doc.kv(tr("Limit połączeń"), tr("bez limitu") if r["rolconnlimit"] == -1 else r["rolconnlimit"])
    pwd = r.get("pwd")
    pwd_desc = {"SCRAM": tr("SCRAM-SHA-256 (zalecane)"), "MD5": tr("MD5 (przestarzałe)"), "brak": tr("brak hasła"),
                "inne": tr("inny format")}.get(pwd, tr("nieznany (wymaga superużytkownika)"))
    doc.kv(tr("Hasło"), pwd_desc, WARN if pwd == "MD5" else None)
    vu = r.get("validuntil")
    doc.kv(tr("Hasło ważne do"), tr("bez ograniczenia") if not vu or vu == "infinity" else
           fmt_ts(vu) + (tr(" – WYGASŁO") if r.get("expired") else ""), WARN if r.get("expired") else None)
    doc.kv(tr("Aktywne sesje"), r.get("sessions"))
    doc.kv("OID", r.get("oid"))
    if r.get("comment"):
        doc.kv(tr("Komentarz"), r["comment"])
    iss = m.role_issues.get(name, [])
    if iss:
        doc.h(tr("Ocena"))
        for sev, text in sorted(iss, key=lambda x: -x[0]):
            doc.item(text, sev)

    doc.h(tr("Należy do ról"))
    par = m.parents.get(name, [])
    if par:
        rows = []
        for x in sorted(par, key=lambda x: x["role_name"]):
            inh = x.get("inherit_option")
            rows.append([x["role_name"], yn(x.get("admin_option")),
                         "?" if inh is None else yn(inh), x.get("grantor_name") or ""])
        doc.table([tr("Rola"), "ADMIN OPTION", tr("Dziedziczy"), tr("Nadał")], rows)
        indirect = sorted(m.memberships(name) - set(x["role_name"] for x in par))
        if indirect:
            doc.p(tr("Pośrednio także: ") + ", ".join(indirect), "dim")
    else:
        doc.p(tr("— nie należy do żadnej roli"))
    ch = m.children.get(name, [])
    doc.h(tr("Członkowie tej roli"))
    doc.p(", ".join(sorted(x["member_name"] + (" (ADMIN)" if x.get("admin_option") else "") for x in ch))
          if ch else tr("— brak"))

    sets = []
    for c in r.get("rolconfig") or []:
        sets.append([tr("(wszystkie)"), c])
    for s in m.role_settings:
        if s.get("rolname") == name and s.get("datname"):
            for c in s.get("setconfig") or []:
                sets.append([s["datname"], c])
    if sets:
        doc.h(tr("Ustawienia (ALTER ROLE … SET)"))
        doc.table([tr("Baza"), tr("Ustawienie")], sets)

    owned = [d["datname"] for d in (m.dbs or []) if d.get("owner") == name]
    if owned:
        doc.h(tr("Właściciel baz"))
        doc.p(", ".join(owned))

    doc.h(tr("Uprawnienia do baz"))
    rows = []
    for d in m.dbs or []:
        v = m.role_db.get((name, d["datname"]))
        if v:
            rows.append([d["datname"], tr("tak") if v["c"] else "-", tr("tak") if v["cr"] else "-", tr("tak") if v["t"] else "-"])
    if rows:
        doc.table([tr("Baza"), "CONNECT", "CREATE", "TEMPORARY"], rows)
    elif name.startswith("pg_"):
        doc.p(tr("Rola systemowa – uprawnienia wbudowane."), "dim")
    else:
        doc.p(tr("brak uprawnień do baz") if m.role_db else tr("brak danych"))

    doc.h(tr("Skąd i dokąd może się połączyć (reguły pg_hba)"))
    if not r["rolcanlogin"]:
        doc.p(tr("Rola nie ma prawa logowania (NOLOGIN) – nie można się nią połączyć; służy do nadawania "
              "uprawnień swoim członkom."))
    elif m.hba is None:
        doc.p(tr("Reguły pg_hba są niedostępne."))
    else:
        can_repl = r["rolreplication"] or r["rolsuper"]
        rules = [(h, mb) for h, mb in m.rules_for(role=name)
                 if can_repl or any(x != "replication" for x in h.databases)]
        if not rules:
            doc.p(tr("Żadna reguła pg_hba nie dotyczy tej roli – nie może się zalogować."), "sev2")
        else:
            rows, sevs = [], []
            for h, maybe in rules:
                rows.append([h.line_label(), h.type, h.addr_text(), ", ".join(h.databases), h.method,
                             (tr("przesłonięta") if h.shadowed_by else sev_label(h.severity))
                             + (tr(", być może") if maybe else "")])
                sevs.append(h.severity)
            doc.table([tr("Linia"), tr("Typ"), tr("Skąd"), tr("Dokąd"), tr("Metoda"), tr("Ocena")], rows, sevs, 5)
            doc.h(tr("Podsumowanie: do jakich baz i skąd może się połączyć"))
            groups, order = {}, []
            for d in m.dbs or []:
                dn = d["datname"]
                v = m.role_db.get((name, dn))
                if not v or not v["c"] or not d.get("datallowconn"):
                    continue
                rs = tuple(h for h, _ in m.rules_for(role=name, db=dn) if h.shadowed_by is None)
                if rs not in groups:
                    groups[rs] = []
                    order.append(rs)
                groups[rs].append(dn)
            for rs in order:
                doc.p(", ".join(groups[rs]), "bold")
                if not rs:
                    doc.item(tr("brak pasującej reguły pg_hba – połączenie niemożliwe"), WARN)
                for h in rs:
                    doc.item("%s: %s%s" % (h.ref(), h.short(),
                                           tr(" (blokada)") if h.method == "reject" else ""))
            if not order:
                doc.p(tr("Rola nie ma prawa CONNECT do żadnej bazy przyjmującej połączenia."), "sev2")
            doc.p(tr("Dla danego adresu klienta decyduje pierwsza pasująca reguła z listy."), "dim")
    return doc


# ----------------------------------------------------------------------------- Serwer

# ----------------------------------------------------------------------------- sieć: analiza

class NetModel(object):
    """Nasluch, test TCP i firewall – wnioski dla zakladki 'Siec i firewall'."""

    def __init__(self, m, raw):
        self.m, self.raw = m, raw or {}
        self.port = int(self.raw.get("port") or 5432)
        self.local = bool(self.raw.get("local"))
        self.listen = self.raw.get("listen")
        self.unix = self.raw.get("unix")
        self.tests = self.raw.get("tests") or []
        self.fwraw = self.raw.get("fw") or {}
        self.issues = []          # (waga, miejsce, tekst)
        self.mechs = []           # mechanizmy aktywnie filtrujace ruch (z evaluate)
        self.status = []          # (nazwa, stan, uwaga, waga, surowa konfiguracja)
        self.fw_denied = False
        self.ipv6 = os.path.exists("/proc/net/if_inet6") or any(":" in t["addr"] for t in self.tests)
        self._firewalls()
        self.base_issues = list(self.issues)
        self.network_listen = None
        if self.listen is not None:
            self.network_listen = any(not ipaddress.ip_address(s["addr"]).is_loopback for s in self.listen)

    def issue(self, sev, where, text):
        self.issues.append((sev, where, text))

    # -- mechanizmy firewalla
    def _firewalls(self):
        f = self.fwraw
        euid = f.get("euid", os.geteuid())
        if f.get("error"):
            self.status.append(("Firewall", tr("błąd odczytu"), f["error"], INFO, ""))
            return
        exclude = set()
        # firewalld
        d = f.get("firewalld") or {}
        if not d.get("exe"):
            self.status.append(("firewalld", tr("nie zainstalowany"), "", None, "", True))
        elif d.get("state") != "running":
            self.status.append(("firewalld", tr("nie działa (%s)") % d.get("state"), "", None, "", True))
        else:
            fd = FirewalldFw(d)
            if d.get("denied") or not fd.zones:
                self.fw_denied = True
                self.status.append(("firewalld", tr("działa – brak uprawnień do odczytu stref"),
                                    tr("uruchom program jako root"), INFO, ""))
            else:
                self.mechs.append(fd)
                zs = ", ".join(sorted(fd.zones))
                self.status.append(("firewalld", tr("działa – strefy: %s (domyślna: %s)") % (zs, fd.default),
                                    "", OK, fd.raw))
            for fam in ("inet", "ip", "ip6"):
                exclude.add((fam, "firewalld"))
        # ufw
        d = f.get("ufw") or {}
        ufw_active = False
        if not d.get("exe"):
            self.status.append(("ufw", tr("nie zainstalowany"), "", None, "", True))
        elif d.get("text"):
            u = parse_ufw(d["text"], d.get("profiles") or {})
            ufw_active = u.active
            if u.active:
                self.mechs.append(u)
                pol = u.input_chains[0].policy
                self.status.append(("ufw", tr("aktywny – domyślnie dla ruchu przychodzącego: %s, reguł: %d")
                                    % (pol, u.rule_count), "", OK, u.raw))
            else:
                self.status.append(("ufw", tr("nieaktywny"), "", None, d["text"], True))
        else:
            en = d.get("enabled_conf")
            ufw_active = en == "yes"
            self.status.append(("ufw", tr("%s (wg /etc/ufw/ufw.conf)") % (tr("włączony") if en == "yes" else tr("wyłączony")),
                                tr("szczegóły reguł widzi tylko root") if en == "yes" else "",
                                INFO if en == "yes" else None, "", en != "yes"))
            if en == "yes":
                self.fw_denied = True
        # nftables
        d = f.get("nft") or {}
        nft = None
        if not d.get("exe"):
            self.status.append(("nftables", tr("nie zainstalowany (polecenie nft)"), "", None, "", True))
        elif d.get("state") == "inactive":
            self.status.append(("nftables", tr("nieaktywny – moduł jądra nf_tables nie jest załadowany"), "", None, "", True))
        elif d.get("state") == "denied":
            self.fw_denied = True
            self.status.append(("nftables", tr("brak uprawnień do odczytu reguł"),
                                tr("uruchom program jako root (sudo)"), INFO, ""))
        elif d.get("state") == "ok":
            try:
                if ufw_active:
                    data = json.loads(d["json"]).get("nftables", [])
                    for it in data:
                        c = it.get("chain")
                        if c and c["name"].startswith("ufw"):
                            exclude.add((c["family"], c["table"]))
                nft = parse_nft(d["json"], d.get("text", ""), exclude)
            except Exception as e:
                self.status.append(("nftables", tr("nie udało się przeanalizować reguł"), str(e), INFO, d.get("text", "")))
                nft = None
            if nft is not None:
                if not nft.tables:
                    self.status.append(("nftables", tr("brak reguł (pusty zestaw)"), "", None, d.get("text", ""), True))
                else:
                    ins = ", ".join(tr("%s (polityka %s)") % (c.label(), c.policy or "accept") for c in nft.input_chains)
                    self.status.append(("nftables", tr("tabele: %s; reguł: %d") % (", ".join(nft.tables), nft.rule_count),
                                        tr("łańcuchy wejściowe: %s") % ins if ins else tr("brak łańcuchów dla ruchu przychodzącego"),
                                        None, d.get("text", "")))
                    if nft.input_chains and nft.filters():
                        self.mechs.append(nft)
        else:
            self.status.append(("nftables", tr("błąd odczytu"), d.get("error", ""), INFO, ""))
        # iptables
        for base, fam in (("iptables", 4), ("ip6tables", 6)):
            d = f.get(base) or {}
            name = "%s (IPv%d)" % (base, fam)
            if not d.get("exe"):
                continue
            if d.get("legacy_text"):
                lf = parse_iptables_save(d["legacy_text"], fam, "%s-legacy" % base)
                if ufw_active and any(c.name.startswith("ufw") for c in lf.chains.values()):
                    self.status.append((name, tr("legacy – zarządzany przez ufw"), "", None, d["legacy_text"]))
                else:
                    pol = lf.input_chains[0].policy if lf.input_chains else "accept"
                    self.status.append((name, tr("legacy: reguł %d, polityka INPUT: %s") % (lf.rule_count, pol), "",
                                        None, d["legacy_text"]))
                    if lf.input_chains and lf.filters():
                        self.mechs.append(lf)
                        if nft is not None and nft.input_chains and self.local:
                            self.issue(WARN, "firewall", tr("aktywne są jednocześnie reguły iptables-legacy i nftables "
                                                         "– oba zestawy filtrują ruch, łatwo przeoczyć jeden z nich"))
            elif d.get("legacy_denied"):
                self.fw_denied = True
                self.status.append((name, tr("legacy – brak uprawnień do odczytu"), tr("uruchom jako root"), INFO, ""))
            if d.get("backend") == "nf_tables":
                txt = d.get("text") or ""
                body = [ln for ln in txt.splitlines() if ln.startswith("-A ")]
                if d.get("denied"):
                    self.status.append((name, tr("nf_tables – brak uprawnień"), "", None, ""))
                elif body:
                    self.status.append((name, tr("nf_tables: %d reguł (widoczne też w nftables)") % len(body), "", None, txt))
                elif not d.get("legacy_text"):
                    self.status.append((name, tr("brak reguł"), "", None, txt, True))
        if self.fw_denied and euid != 0 and self.local:
            self.issue(INFO, "firewall", tr("nie wszystkie reguły firewalla są czytelne – uruchom program jako root"))

    def filtering(self):
        return any(f.filters() for f in self.mechs)

    def evaluate(self, net):
        res = []
        for f in self.mechs:
            v = f.evaluate(net, self.port)
            if v is not None:
                if not v.mech:
                    v.mech = f.label
                res.append(v)
        if not res:
            return None
        deny = [v for v in res if v.decision in ("drop", "reject")]
        final = deny[0] if deny else res[0]
        final.all = res
        if not deny:
            final.partial = [p for v in res for p in v.partial]
        return final

    def port_rules(self):
        out = []
        for f in self.mechs:
            for r in f.rules():
                if r.mentions_port(self.port):
                    out.append((f, r))
        return out

    def hba_targets(self):
        """Reguly pg_hba dla sieci (TCP), ktore realnie dzialaja: (regula, lista sieci)."""
        out = []
        for h in self.m.hba or []:
            if h.error or not h.tcp or h.method == "reject" or h.shadowed_by is not None:
                continue
            if h.kind == "net" and not h.net.is_loopback:
                out.append((h, [h.net]))
            elif h.kind == "all":
                out.append((h, [WORLD4, WORLD6] if self.ipv6 else [WORLD4]))
            elif h.kind in ("samenet", "samehost", "hostname"):
                out.append((h, []))
        return out


def verdict_text(v):
    if v is None:
        return tr("brak filtrowania – dozwolone"), None
    txt = tr(DEC_RES.get(v.decision, v.decision))
    if v.partial:
        txt += tr(" (z zastrzeżeniami)")
    return txt, v.decision


def verdict_doc(doc, v, port):
    if v is None:
        doc.p(tr("Żaden aktywny mechanizm firewalla nie filtruje ruchu przychodzącego – pakiety na port %d "
              "docierają do serwera.") % port)
        return
    doc.kv(tr("Wynik"), tr(DEC_RES.get(v.decision, v.decision)), OK if v.decision == "accept" else WARN)
    doc.kv(tr("Rozstrzyga"), v.mech)
    doc.kv(tr("Powód"), v.reason())
    if len(v.all) > 1:
        doc.h(tr("Wyniki poszczególnych mechanizmów"))
        for x in v.all:
            doc.item("%s: %s – %s" % (x.mech, tr(DEC_RES.get(x.decision, x.decision)), x.reason()))
    if v.partial:
        doc.h(tr("Reguły, które mogą zmienić wynik (dotyczą tylko części ruchu)"))
        for r, why in v.partial:
            doc.item("%s – %s" % (r.text, "; ".join(why or [])), INFO)


def build_net_tab(m):
    t = Tab("net", tr("Sieć i firewall"))
    t.columns = [Column("k", tr("Element"), minw=22, maxw=36),
                 Column("v", tr("Stan"), minw=10, maxw=80, flex=True, pref=40),
                 Column("n", tr("Ocena / uwagi"), minw=10, maxw=70, prio=1)]
    nm = m.net
    if nm is None:
        if m.rep.get("net_skipped"):
            t.error = (tr("Sprawdzanie sieci i firewalla zostało pominięte (opcja --no-net)."), None)
        else:
            t.error = (m.errors.get("net", tr("Nie udało się sprawdzić sieci.")), None)
        return t
    nm.issues = list(nm.base_issues)
    rows = []
    port = nm.port

    def sec(title):
        rows.append(Row({"k": title, "v": "", "n": ""}, style="section", selectable=False))

    def add(k, v, note="", sev=None, doc=None, style=None):
        def detail(k=k, v=v, note=note, sev=sev, doc=doc):
            if doc is not None:
                return doc() if callable(doc) else doc
            d = Doc(k)
            d.h(tr("Stan"))
            d.p(v or "—")
            if note:
                d.h(tr("Ocena"))
                d.item(note, sev if sev is not None else INFO)
            return d
        rows.append(Row({"k": k, "v": v, "n": note}, sev=sev, sev_col="n" if sev is not None else None,
                        detail=detail, style=style))
        if sev is not None and sev >= WARN:
            nm.issue(sev, tr("sieć: %s") % k, note)

    hba_net = [h for h, nets in nm.hba_targets()]
    la = m.setting("listen_addresses")
    pend = [n for n in ("listen_addresses", "port")
            if (m.settings.get(n) or {}).get("pending_restart")]

    # ---------------------------------------------------------------- nasłuch
    sec(tr("Nasłuch serwera"))
    if not nm.local:
        add(tr("Serwer"), tr("%s:%d (zdalny)") % (nm.raw.get("host"), port),
            tr("nasłuch zdalnego serwera oceniany testem połączenia poniżej"))
    else:
        add("listen_addresses", la if la is not None else (tr("(brak połączenia z bazą)") if not m.settings
                                                            else tr("(niedostępne bez uprawnień)")),
            tr("zmiana czeka na restart serwera – obecny nasłuch może być inny") if "listen_addresses" in pend else "",
            WARN if "listen_addresses" in pend else None)
        if "port" in pend:
            add("Port", str(port), tr("zmiana portu czeka na restart serwera"), WARN)
        if nm.listen is None:
            add(tr("Gniazda TCP"), tr("nie można odczytać /proc/net/tcp"), "", INFO)
        elif not nm.listen and not nm.unix:
            others = [p for p in nm.raw.get("pg_ports") or [] if p != port]
            add(tr("Gniazda TCP i Unix"), tr("brak – na porcie %d nic nie nasłuchuje") % port,
                tr("serwer nie działa albo używa innego portu") + (
                    tr(" – lokalne serwery PostgreSQL działają na portach: %s") % ", ".join(map(str, others))
                    if others else ""), WARN)
        elif not nm.listen:
            add(tr("Gniazda TCP"), tr("brak – serwer nie nasłuchuje na porcie %d w sieci") % port,
                (tr("pg_hba ma reguły dla sieci, ale klienci z sieci nie połączą się (listen_addresses)")
                 if hba_net else tr("dostęp tylko przez gniazdo Unix")), INFO)
        else:
            for s in sorted(nm.listen, key=lambda x: (x["family"], x["addr"])):
                ip = ipaddress.ip_address(s["addr"])
                if ip.is_unspecified:
                    what, sev = tr("wszystkie interfejsy IPv%d") % s["family"], None
                elif ip.is_loopback:
                    what, sev = tr("tylko lokalnie (loopback)"), None
                else:
                    ifn = [n for n, a in nm.raw.get("ifaces", []) if a == s["addr"]]
                    what, sev = tr("interfejs %s") % (ifn[0] if ifn else "?"), None
                proc = s.get("proc")
                ptxt = tr("proces %s (pid %d)") % (proc[1], proc[0]) if proc else tr("proces niewidoczny (inne konto)")
                addr = "[%s]" % s["addr"] if ":" in s["addr"] else s["addr"]

                def sdoc(s=s, what=what, ptxt=ptxt, addr=addr):
                    d = Doc(tr("Gniazdo TCP %s:%d") % (addr, port))
                    d.kv(tr("Adres"), "%s – %s" % (s["addr"], what))
                    d.kv(tr("Rodzina"), "IPv%d" % s["family"])
                    d.kv(tr("Proces"), ptxt)
                    d.kv(tr("UID właściciela"), s["uid"])
                    d.kv(tr("Źródło"), "/proc/net/tcp%s" % ("6" if s["family"] == 6 else ""))
                    d.p(tr("Adres 0.0.0.0 lub :: oznacza nasłuch na wszystkich interfejsach; o tym, kto faktycznie się "
                        "połączy, decydują dalej firewall i reguły pg_hba."), "dim")
                    return d
                add("TCP %s:%d" % (addr, port), what, ptxt, sev, doc=sdoc)
        for p in nm.unix or []:
            add(tr("Gniazdo Unix"), p, tr("połączenia lokalne (typ local w pg_hba)"))
        if nm.network_listen and la is not None and la.strip() in ("", "localhost"):
            add(tr("Niezgodność"), tr("serwer nasłuchuje w sieci, choć listen_addresses = %s") % la,
                tr("prawdopodobnie zmiana czeka na restart"), WARN)

    # ---------------------------------------------------------------- test TCP
    sec(tr("Test połączenia TCP (z tego komputera)"))
    if nm.raw.get("resolve_error"):
        add(tr("Nazwa hosta"), nm.raw.get("host"), tr("nie można ustalić adresu: %s") % nm.raw["resolve_error"], WARN)
    listened = set(s["addr"] for s in (nm.listen or []))
    wild4 = "0.0.0.0" in listened
    wild6 = "::" in listened
    for tst in nm.tests:
        a = tst["addr"]
        lab = "%s:%d" % ("[%s]" % a if ":" in a else a, port)
        if tst.get("label") and tst["label"] != nm.raw.get("host"):
            lab += " (%s)" % tst["label"]
        res = tst.get("result")
        is_lo = ipaddress.ip_address(a).is_loopback
        covered = a in listened or (wild4 and ":" not in a) or (wild6 and ":" in a)
        if res == "open":
            ms = tst.get("ms", 0)
            mtxt = ldec("< 0.1") if ms < 0.1 else ldec("%.1f" % ms)
            v, note, sev = tr("otwarty – odpowiedź w %s ms") % mtxt, tr("port dostępny"), OK
        elif res == "refused":
            v = tr("odrzucone (connection refused)")
            if nm.local and nm.listen is not None and not covered:
                note, sev = tr("serwer nie nasłuchuje na tym adresie (listen_addresses)"), INFO
            elif nm.local:
                note, sev = tr("odrzucone mimo nasłuchu – prawdopodobnie firewall (REJECT)"), WARN
            else:
                note, sev = tr("port zamknięty na serwerze albo odrzucony przez firewall"), WARN
        elif res == "timeout":
            v = tr("brak odpowiedzi w %s s") % ldec("%g" % tst.get("timeout", 2))
            note, sev = (tr("pakiety prawdopodobnie odrzucane po cichu przez firewall (DROP)") if nm.local else
                         tr("brak odpowiedzi – firewall po drodze (DROP) albo host niedostępny")), WARN
        else:
            v = tr("błąd: %s") % tst.get("error", "?")
            note = (tr("odrzucone przez firewall (ICMP) lub brak trasy") if "route" in tst.get("error", "").lower()
                    or "unreachable" in tst.get("error", "").lower() else "")
            sev = WARN

        def tdoc(tst=tst, lab=lab, v=v, note=note, sev=sev, is_lo=is_lo):
            d = Doc("Test TCP %s" % lab)
            d.kv(tr("Wynik"), v, sev)
            if note:
                d.kv(tr("Interpretacja"), note)
            d.h(tr("Jak działa test"))
            d.p(tr("Program otwiera połączenie TCP na port %d i od razu je zamyka – nic nie jest wysyłane, serwer nie "
                "widzi próby logowania.") % port)
            if nm.local:
                d.p(tr("Uwaga: połączenie z tego samego komputera – nawet na adres interfejsu sieciowego – przechodzi "
                    "przez interfejs lo i zwykle nie podlega regułom firewalla dla ruchu z zewnątrz. O dostępności "
                    "z innych komputerów mówi sekcja „Port w firewallu” poniżej."), "dim")
            return d
        add(lab, v, note, sev, doc=tdoc)
    if not nm.tests and not nm.raw.get("resolve_error"):
        add("Test", tr("brak adresów do sprawdzenia"), "", None)

    # ---------------------------------------------------------------- firewall: stan
    sec(tr("Firewall – stan"))
    for entry in nm.status:
        name, state, note, sev, raw = entry[:5]
        inactive = len(entry) > 5 and entry[5]
        def fdoc(name=name, state=state, note=note, raw=raw):
            d = Doc("Firewall: %s" % name)
            d.kv(tr("Stan"), state)
            if note:
                d.kv(tr("Uwagi"), note)
            if raw and raw.strip():
                d.h(tr("Konfiguracja (wynik polecenia tylko do odczytu)"))
                d.pre(raw.rstrip())
            return d
        add(name, state, note, sev, doc=fdoc, style="dim" if inactive else None)
    if not nm.local:
        add(tr("Znaczenie"), tr("serwer jest zdalny"),
            tr("firewall tego komputera nie wpływa na ruch przychodzący do bazy – sprawdź firewall na serwerze"), INFO)
    else:
        if nm.mechs:
            names = ", ".join(f.label for f in nm.mechs)
            add(tr("Ruch przychodzący"), tr("filtrowany – %s") % names, "", OK)
        elif nm.fw_denied:
            add(tr("Ruch przychodzący"), tr("nieznane – brak uprawnień"), tr("uruchom jako root"), INFO)
        else:
            world_hba = [h for h, nets in nm.hba_targets() if h.is_world()]
            sev = WARN if (nm.network_listen and world_hba) else INFO
            add(tr("Ruch przychodzący"), tr("niefiltrowany – brak aktywnych reguł"),
                (tr("port %d dostępny z każdej sieci; chroni go tylko pg_hba%s") % (
                    port, tr(" (są reguły dla dowolnego adresu)") if world_hba else "")
                 if nm.network_listen else tr("serwer i tak nie nasłuchuje w sieci")), sev)
        for f in nm.mechs:
            for ch in f.input_chains:
                def cdoc(f=f, ch=ch):
                    d = Doc("%s – %s" % (f.label, ch.label()))
                    d.kv(tr("Polityka domyślna"), ch.policy or "accept")
                    d.kv(tr("Reguł"), len(ch.rules))
                    if ch.rules:
                        d.h(tr("Reguły (w kolejności sprawdzania)"))
                        rows_, sevs = [], []
                        for i, r in enumerate(ch.rules, 1):
                            mark = "← port %d" % port if r.mentions_port(port) else ""
                            rows_.append([str(i), r.text, verdict_verb(r), mark])
                            sevs.append(OK if r.verdict == "accept" else (WARN if r.verdict in ("drop", "reject") else None))
                        d.table(["#", tr("Reguła"), tr("Działanie"), ""], rows_, sevs, 2)
                    return d
                add("↳ %s %s" % (SHORT_MECH.get(f.label, f.label), ch.name if f.backend != "nft" else ch.label()),
                    tr("polityka %s, reguł: %d") % (ch.policy or "accept", len(ch.rules)),
                    tr("Enter – lista reguł"), None, doc=cdoc)

    # ---------------------------------------------------------------- port w firewallu
    if nm.local and nm.mechs:
        sec(tr("Port %d/tcp w firewallu (ruch z sieci)") % port)
        worlds = [WORLD4, WORLD6] if nm.ipv6 else [WORLD4]
        for w in worlds:
            v = nm.evaluate(w)
            txt, dec = verdict_text(v)
            if dec == "accept" and not (v and v.partial):
                note, sev = tr("port otwarty dla wszystkich adresów IPv%d") % w.version, INFO
            elif dec == "accept":
                note, sev = tr("otwarty, ale część reguł zależy od dodatkowych warunków"), INFO
            elif v and v.partial:
                note, sev = tr("zablokowany poza wybranymi sieciami – szczegóły pod Enter"), OK
            else:
                note, sev = (tr("port zablokowany dla całego ruchu z sieci") if nm.network_listen else ""), (
                    INFO if nm.network_listen else None)

            def wdoc(v=v, w=w):
                d = Doc(tr("Port %d z dowolnego adresu IPv%d") % (port, w.version))
                verdict_doc(d, v, port)
                return d
            add(tr("Z dowolnego adresu IPv%d") % w.version, txt + (" – " + v.reason() if v else ""), note, sev, doc=wdoc)
        for f, r in nm.port_rules():
            who = _short_nets(r.saddr) if r.saddr else tr("wszyscy")
            if r.saddr_neg:
                who = tr("wszyscy oprócz ") + who
            sev = OK if r.verdict == "accept" else (WARN if r.verdict in ("drop", "reject") and not r.saddr else None)

            def rdoc(f=f, r=r, who=who):
                d = Doc(tr("Reguła %s") % f.label)
                d.kv(tr("Reguła"), r.text)
                d.kv(tr("Łańcuch"), r.where())
                d.kv(tr("Działanie"), verdict_verb(r) if r.verdict else tr("brak (np. log/licznik)"))
                d.kv(tr("Źródło"), who)
                if r.iif:
                    d.kv(tr("Interfejs"), "%s%s" % (tr("oprócz ") if r.iif_neg else "", ", ".join(sorted(r.iif))))
                if r.ct:
                    d.kv(tr("Stan połączenia"), "%s%s" % (tr("nie ") if r.ct_neg else "", ", ".join(sorted(r.ct))))
                if r.unknown:
                    d.kv(tr("Inne warunki"), "; ".join(r.unknown))
                return d
            idx = next((i for i, x in enumerate(f.chains.get((r.table, r.chain)).rules, 1) if x is r), 0) \
                if (r.table, r.chain) in f.chains else 0
            add("↳ %s %s #%d" % (SHORT_MECH.get(f.label, f.label), r.chain, idx), r.text,
                tr("%s – źródło: %s") % (verdict_verb(r), who), sev, doc=rdoc)

    # ---------------------------------------------------------------- pg_hba a firewall
    targets = nm.hba_targets()
    if nm.local and targets:
        sec(tr("Reguły pg_hba a nasłuch i firewall"))
        for h, nets in targets:
            lab = "pg_hba %s" % h.ref()
            val = "%s %s → %s" % (h.type, h.addr_text(), h.method)
            if nm.listen is not None and not nm.network_listen:
                add(lab, val, tr("serwer nie nasłuchuje w sieci – reguła nie jest używana"), INFO)
                continue
            if not nets:
                add(lab, val, tr("adres typu %s – zgodności z firewallem nie da się ocenić automatycznie") % h.kind, None)
                continue
            if not nm.mechs:
                add(lab, val, tr("brak filtrowania (firewall nie ogranicza)") if not nm.fw_denied
                    else tr("firewall nieczytelny – brak uprawnień"), None)
                continue
            vs = [(n, nm.evaluate(n)) for n in nets]
            decs = set(v.decision if v else "accept" for _, v in vs)
            partial = any(v and v.partial for _, v in vs)
            if decs == {"accept"}:
                note, sev = tr("firewall przepuszcza") + (tr(" (z zastrzeżeniami)") if partial else ""), OK
            elif "accept" in decs:
                note, sev = tr("firewall przepuszcza tylko część (np. jedną rodzinę adresów)"), INFO
            elif partial:
                note, sev = tr("firewall blokuje większość adresów tej sieci – przepuszcza tylko część"), INFO
            else:
                note, sev = (tr("firewall BLOKUJE – pg_hba dopuszcza tę sieć, ale połączenia nie dotrą do serwera"), WARN)

            def hdoc(h=h, vs=vs, val=val):
                d = Doc(tr("pg_hba %s a firewall") % h.ref())
                d.kv(tr("Reguła pg_hba"), tr("%s; bazy %s; role %s") % (val, ", ".join(h.databases), ", ".join(h.users)))
                for n, v in vs:
                    d.h(tr("Ruch z %s") % n)
                    verdict_doc(d, v, port)
                d.p(tr("Żeby klient się połączył, muszą zgodzić się wszystkie warstwy: nasłuch serwera "
                    "(listen_addresses), firewall i reguła pg_hba, a na końcu uprawnienie CONNECT do bazy."), "dim")
                return d
            add(lab, val, note, sev, doc=hdoc)

    t.rows = rows
    t.badge = max([r.sev or OK for r in rows if r.selectable] or [OK])
    if any(x[0] >= WARN and x[1] == "firewall" for x in nm.issues) and t.badge < WARN:
        t.badge = WARN
    t.info.append([(tr("Port %d · serwer %s · sprawdzono w %.1f s") % (
        port, tr("lokalny") if nm.local else tr("zdalny (%s)") % nm.raw.get("host"), nm.raw.get("elapsed", 0)), "bold"),
        (tr("   konto: %s") % ("root" if nm.fwraw.get("euid") == 0 else (getpass.getuser() + tr(" – reguły firewalla widzi tylko root"))), "dim")])
    t.info.append([(tr("Tylko odczyt: /proc/net, nft list ruleset, iptables-save, firewall-cmd --list-all, ufw status; "
                    "test TCP jedynie otwiera i zamyka połączenie."), "dim")])
    for sev, where, text in nm.issues:
        if where == "firewall":
            t.info.append([(" %s " % sev_label(sev), "sev%d" % sev), (" " + text, "sev2" if sev >= WARN else "dim")])
    return t


def build_server_tab(m, other_tabs):
    t = Tab("server", tr("Serwer"))
    t.columns = [Column("k", tr("Parametr"), maxw=30, minw=12),
                 Column("v", tr("Wartość"), maxw=80, minw=10, flex=True, pref=46),
                 Column("n", tr("Uwagi"), maxw=48, minw=6)]
    p, rep = m.p, m.rep
    rows = []

    def sec(title):
        rows.append(Row({"k": title, "v": "", "n": ""}, style="section", selectable=False))

    def add(k, v, note="", sev=None, setting=None, extra=None):
        def detail(k=k, v=v, note=note, sev=sev, setting=setting, extra=extra):
            d = Doc(k)
            d.h(tr("Wartość"))
            d.p(cell(v) if v not in (None, "") else "—")
            if note:
                d.h(tr("Ocena"))
                d.item(note, sev if sev is not None else INFO)
            if setting:
                s = m.settings.get(setting)
                d.h(tr("Parametr konfiguracji"))
                d.kv(tr("Nazwa"), setting)
                if s:
                    d.kv(tr("Wartość surowa"), "%s%s" % (s.get("setting"), " " + s["unit"] if s.get("unit") else ""))
                    d.kv(tr("Źródło"), s.get("source") or "")
                    if s.get("sourcefile"):
                        d.kv(tr("Plik"), "%s:%s" % (s["sourcefile"], s.get("sourceline")))
                else:
                    d.kv(tr("Wartość"), tr("niedostępna – wymaga superużytkownika lub roli pg_read_all_settings"))
            for ek, ev in extra or []:
                d.kv(ek, ev)
            return d
        rows.append(Row({"k": k, "v": v, "n": note}, sev=sev, sev_col="n" if sev is not None else None,
                        detail=detail))

    st = m.setting
    host = rep["params"].get("host") or ""
    nodata = tr("(niedostępne – wymaga superużytkownika lub pg_read_all_settings)")

    # --- ustawienia i ich ocena (liczone wczesniej – potrzebne w podsumowaniu)
    srv = []  # (k, v, note, sev, setting)
    la = st("listen_addresses")
    if la is None:
        srv.append((tr("Nasłuch (listen_addresses)"), nodata, "", None, "listen_addresses"))
    else:
        parts = [x.strip() for x in la.split(",") if x.strip()]
        if not parts:
            srv.append((tr("Nasłuch (listen_addresses)"), tr("(puste)"), tr("tylko gniazdo Unix – brak dostępu sieciowego"), OK, "listen_addresses"))
        elif any(x in ("*", "0.0.0.0", "::") for x in parts):
            srv.append((tr("Nasłuch (listen_addresses)"), la, tr("nasłuchuje na wszystkich interfejsach sieciowych"), INFO, "listen_addresses"))
        elif all(x in ("localhost", "127.0.0.1", "::1") for x in parts):
            srv.append((tr("Nasłuch (listen_addresses)"), la, tr("tylko lokalnie"), OK, "listen_addresses"))
        else:
            srv.append((tr("Nasłuch (listen_addresses)"), la, tr("wybrane interfejsy"), INFO, "listen_addresses"))
    network = la is None or any(x.strip() not in ("localhost", "127.0.0.1", "::1", "")
                                for x in (la or "").split(","))
    srv.append(("Port", st("port") or p.get("server_port") or "", "", None, "port"))
    srv.append((tr("Katalog gniazd Unix"), st("unix_socket_directories") if st("unix_socket_directories") is not None
                else nodata, "", None, "unix_socket_directories"))
    ssl = st("ssl")
    if ssl == "off":
        srv.append((tr("SSL na serwerze"), tr("wyłączony"), tr("SSL wyłączony – hasła i dane w sieci bez szyfrowania")
                    if network else tr("SSL wyłączony"), WARN if network else INFO, "ssl"))
    elif ssl == "on":
        srv.append((tr("SSL na serwerze"), tr("włączony"), "", OK, "ssl"))
    mp = st("ssl_min_protocol_version")
    if mp:
        srv.append((tr("Min. wersja TLS"), mp, tr("przestarzała wersja TLS") if mp in ("TLSv1", "TLSv1.1") else "",
                    WARN if mp in ("TLSv1", "TLSv1.1") else None, "ssl_min_protocol_version"))
    pe = st("password_encryption")
    if pe:
        if pe in ("md5", "on"):
            srv.append((tr("Szyfrowanie nowych haseł"), pe, tr("nowe hasła zapisywane jako MD5 – ustaw scram-sha-256"),
                        WARN, "password_encryption"))
        else:
            srv.append((tr("Szyfrowanie nowych haseł"), pe, "", OK, "password_encryption"))
    lc = st("log_connections")
    if lc is not None:
        off = lc.strip().lower() in ("off", "", "false", "0")
        srv.append((tr("Logowanie połączeń"), tr("wyłączone") if off else tr("włączone (%s)") % lc,
                    tr("połączenia nie są zapisywane w logu – trudniej audytować dostęp") if off else "",
                    INFO if off else None, "log_connections"))
    at = st("authentication_timeout")
    if at:
        srv.append((tr("Czas na uwierzytelnienie"), "%s s" % at, "", None, "authentication_timeout"))

    # --- podsumowanie
    all_iss = []  # (sev, miejsce, tekst)
    for r in m.hba or []:
        for sev, text in r.issues:
            if sev >= WARN:
                all_iss.append((sev if r.shadowed_by is None or sev < CRIT else WARN,
                                "pg_hba %s" % r.ref(), text))
    for name, iss in m.role_issues.items():
        for sev, text in iss:
            if sev >= WARN:
                all_iss.append((sev, tr("rola %s") % name, text))
    for name, iss in m.db_issues.items():
        for sev, text in iss:
            if sev >= WARN:
                all_iss.append((sev, tr("baza %s") % name, text))
    for k, v, note, sev, _ in srv:
        if sev is not None and sev >= WARN:
            all_iss.append((sev, tr("serwer: %s") % k, note))
    if m.net is not None:
        for sev, where, text in m.net.issues:
            if sev >= WARN:
                all_iss.append((sev, where, text))
    ncrit = sum(1 for x in all_iss if x[0] == CRIT)
    nwarn = sum(1 for x in all_iss if x[0] == WARN)

    sec(tr("Podsumowanie"))
    if all_iss:
        txt = "%d %s, %d %s" % (ncrit, plural(ncrit, tr("krytyczny"), tr("krytyczne"), tr("krytycznych")),
                                 nwarn, plural(nwarn, tr("ostrzeżenie"), tr("ostrzeżenia"), tr("ostrzeżeń")))
        sev = CRIT if ncrit else WARN

        def issues_doc():
            d = Doc(tr("Znalezione problemy"))
            for s in (CRIT, WARN):
                items = [x for x in all_iss if x[0] == s]
                if items:
                    d.h(tr("Krytyczne") if s == CRIT else tr("Ostrzeżenia"))
                    for _, where, text in items:
                        d.item("%s – %s" % (where, text), s)
            d.blank()
            d.p(tr("Informacje o niższej wadze (info) są widoczne w kolumnach Uwagi na poszczególnych zakładkach."), "dim")
            return d
        rows.append(Row({"k": tr("Znalezione problemy"), "v": txt, "n": tr("Enter – pełna lista")},
                        sev=sev, sev_col="n", detail=issues_doc))
    else:
        add(tr("Znalezione problemy"), tr("brak problemów krytycznych i ostrzeżeń"), "", OK)
    if m.dbs is not None:
        nt = sum(1 for d in m.dbs if d.get("datistemplate"))
        add(tr("Bazy danych"), tr("%d (w tym %d %s)") % (len(m.dbs), nt, plural(nt, tr("szablon"), tr("szablony"), tr("szablonów"))))
    if m.roles is not None:
        nsys = sum(1 for r in m.roles if r["rolname"].startswith("pg_"))
        add(tr("Role"), tr("%d (z logowaniem: %d, superużytkownicy: %d, systemowe pg_*: %d)") % (
            len(m.roles) - nsys, sum(1 for r in m.roles if r["rolcanlogin"]),
            sum(1 for r in m.roles if r["rolsuper"]), nsys))
    if m.hba is not None:
        ne = sum(1 for r in m.hba if r.error)
        nsh = sum(1 for r in m.hba if r.shadowed_by is not None)
        add(tr("Reguły pg_hba"), tr("%d (błędne: %d, przesłonięte: %d)") % (len(m.hba), ne, nsh),
            tr("plik zawiera błędy") if ne else "", CRIT if ne else None)
    else:
        add(tr("Reguły pg_hba"), tr("niedostępne"), (m.errors.get("hba_file") or m.errors.get("hba") or "")[:200], INFO)
    if m.net is not None:
        nmo = m.net
        if not nmo.local:
            ftxt = tr("serwer zdalny – firewall oceniany tylko testem połączenia")
        elif nmo.mechs:
            ftxt = tr("aktywny: ") + ", ".join(f.label for f in nmo.mechs)
        elif nmo.fw_denied:
            ftxt = tr("nieznany (brak uprawnień – uruchom jako root)")
        else:
            ftxt = tr("brak aktywnych reguł filtrujących")
        add("Firewall", ftxt, tr("szczegóły: zakładka 5"))

    sec(tr("Połączenie"))
    if p.get("server_addr"):
        where = "%s:%s" % (p["server_addr"], p.get("server_port"))
    else:
        where = tr("gniazdo Unix %s, port %s") % (host or (st("unix_socket_directories") or "").split(",")[0],
                                               st("port") or rep["params"].get("port") or "5432")
    add(tr("Serwer"), where)
    add(tr("Zalogowano jako"), "%s%s" % (p.get("cur_user"), tr(" (superużytkownik)") if p.get("is_super") else ""),
        "" if p.get("is_super") else tr("część danych może być niedostępna – pełny obraz daje superużytkownik"),
        None if p.get("is_super") else INFO)
    add(tr("Baza połączenia"), p.get("cur_db"))
    myssl = (rep.get("myssl") or [None])[0]
    if not p.get("server_addr"):
        add(tr("Szyfrowanie połączenia"), tr("nie dotyczy (gniazdo lokalne)"))
    elif myssl and myssl.get("ssl"):
        add(tr("Szyfrowanie połączenia"), "SSL %s, %s" % (myssl.get("version"), myssl.get("cipher")), "", OK)
    elif myssl is not None:
        loop = p.get("server_addr") in ("127.0.0.1", "::1")
        add(tr("Szyfrowanie połączenia"), tr("brak – połączenie nieszyfrowane"), "", INFO if loop else WARN)
    add(tr("Wersja"), (p.get("version") or "").split(" on ")[0].split(",")[0], "", None,
        extra=[(tr("Pełny opis"), p.get("version"))])

    sec(tr("Instancja"))
    add(tr("Rola serwera"), tr("standby (tryb odtwarzania)") if p.get("in_recovery") else tr("główny (primary)"))
    add(tr("Uruchomiony"), tr("%s (od %s)") % (fmt_ts(p.get("started")), fmt_interval(p.get("uptime"))))
    mc = st("max_connections")
    add(tr("Sesje"), "%s / %s%s" % (p.get("sessions"), mc or "?",
                                 (tr(" (zarezerwowane dla superużytkowników: %s)") % st("superuser_reserved_connections"))
                                 if st("superuser_reserved_connections") else ""), "", None, "max_connections")
    sb = m.settings.get("shared_buffers")
    if sb:
        try:
            unit = sb.get("unit") or ""
            mult = {"8kB": 8192, "kB": 1024, "MB": 1024 ** 2, "B": 1}.get(unit, 1)
            add("shared_buffers", fmt_bytes(int(sb["setting"]) * mult), "", None, "shared_buffers")
        except (ValueError, TypeError):
            pass
    add(tr("Kodowanie serwera"), st("server_encoding") or "", "", None, "server_encoding")
    add(tr("Strefa czasowa"), st("TimeZone") or "", "", None, "TimeZone")

    sec(tr("Pliki konfiguracyjne"))
    for k, name in ((tr("Katalog danych"), "data_directory"), ("postgresql.conf", "config_file"),
                    ("pg_hba.conf", "hba_file"), ("pg_ident.conf", "ident_file")):
        add(k, st(name) or nodata, "", None, name)

    sec(tr("Sieć i bezpieczeństwo"))
    for k, v, note, sev, setting in srv:
        add(k, v, note, sev, setting)

    if rep.get("errors"):
        sec(tr("Problemy z pobraniem danych"))
        for name, msg in sorted(rep["errors"].items()):
            if name == "hba" and m.hba is not None:
                continue
            add(tr(ERR_NAMES.get(name, name)), msg, "", INFO)

    cl = rep.get("clusters")
    if cl:
        sec(tr("Klastry na tym komputerze (pg_lsclusters)"))
        for c in cl:
            add("%s/%s" % (c["ver"], c["cluster"]), tr("port %s, %s, właściciel %s") % (c["port"], c["status"], c["owner"]),
                c["datadir"], OK if c["status"].startswith("online") else INFO,
                extra=[(tr("Katalog danych"), c["datadir"]), (tr("Plik logu"), c["log"])])

    t.rows = rows
    t.badge = CRIT if ncrit else (WARN if nwarn else OK)
    t.info.append([("PostgreSQL %s" % (p.get("server_version") or ""), "bold"),
                   (tr(" · %s · pobrano o %s w %.1f s") % (tr("superużytkownik") if p.get("is_super") else tr("zwykły użytkownik"),
                                                       rep.get("when", ""), rep.get("elapsed", 0)), "dim")])
    t.stats = (ncrit, nwarn)
    return t


def offline_report(params, net):
    """Raport bez polaczenia z baza – tylko siec i firewall."""
    rep = {"params": dict((k, v) for k, v in params.items() if k != "password"), "errors": {}, "probe": {},
           "net": net, "when": time.strftime("%H:%M:%S"), "elapsed": (net or {}).get("elapsed", 0),
           "offline": True}
    m = Model(rep)
    tabs = empty_tabs()
    for t in tabs[:4]:
        t.error = (tr("Nie udało się połączyć z bazą – brak danych w tej zakładce."),
                   tr("Sprawdź zakładkę 5 (Sieć i firewall): czy serwer nasłuchuje, czy port odpowiada "
                   "i czy firewall go nie blokuje."))
    tabs[4] = build_net_tab(m)
    return rep, m, tabs


def build_tabs(m):
    db = build_db_tab(m)
    hba = build_hba_tab(m)
    roles = build_roles_tab(m)
    net = build_net_tab(m)
    server = build_server_tab(m, [db, hba, roles, net])
    return [server, db, hba, roles, net]


def empty_tabs():
    return [Tab("server", tr("Serwer")), Tab("db", tr("Bazy danych")), Tab("hba", tr("Dostęp pg_hba")), Tab("roles", tr("Role")),
            Tab("net", tr("Sieć i firewall"))]


def about_doc(psql=None, colors=None):
    d = Doc(tr("O programie – PgDiag %s") % VERSION)
    d.h("PgDiag %s" % VERSION)
    d.p(tr("Konsolowe narzędzie diagnostyczne PostgreSQL działające wyłącznie w trybie odczytu: bazy danych, "
           "reguły dostępu pg_hba, role, nasłuch sieciowy i firewall."))
    d.h(tr("Autor"))
    d.kv(tr("Imię i nazwisko"), AUTHOR)
    d.kv("E-mail", AUTHOR_EMAIL)
    d.kv(tr("Prawa autorskie"), "© %s %s" % (COPYRIGHT_YEAR, AUTHOR))
    d.h(tr("Licencja"))
    d.kv(tr("Rodzaj"), tr("MIT – licencja otwarta, permisywna"))
    d.item(tr("program można bezpłatnie używać, kopiować, modyfikować, łączyć z innym oprogramowaniem, publikować, "
              "rozpowszechniać, udzielać sublicencji i sprzedawać – także w zastosowaniach komercyjnych"))
    d.item(tr("warunek: do wszystkich kopii lub istotnych części programu trzeba dołączyć informację o prawach "
              "autorskich i treść licencji"))
    d.item(tr("program jest dostarczany „tak jak jest”, bez jakiejkolwiek gwarancji; autor nie odpowiada za "
              "szkody wynikłe z jego użycia"))
    d.h(tr("Tekst licencji"))
    if LANG != "en":
        d.p(tr("Wiążący jest oryginalny tekst w języku angielskim:"), "dim")
    d.pre(LICENSE_TEXT.rstrip())
    d.h(tr("Środowisko"))
    d.kv("Python", "%s (%s)" % (platform.python_version(), sys.executable))
    d.kv(tr("System"), "%s %s (%s)" % (platform.system(), platform.release(), platform.machine()))
    d.kv("psql", psql or tr("nie znaleziono"))
    if colors is not None:
        d.kv(tr("Terminal"), tr("TERM=%s, kolorów: %d") % (os.environ.get("TERM", "?"), colors))
    cp = config_path()
    d.kv(tr("Plik ustawień"), cp if os.path.exists(cp) else "%s %s" % (cp, tr("(jeszcze nie utworzony)")))
    return d


def help_doc():
    prog = os.path.basename(sys.argv[0]) or "pgdiag.py"
    d = Doc(tr("Pomoc – PgDiag %s") % VERSION)
    d.h(tr("Klawisze – ogólne"))
    for k, v in (("F1 / ?", tr("ta pomoc")),
                 ("F2 / Ctrl+R", tr("uruchom diagnostykę (to samo co przycisk [ Uruchom ])")),
                 ("Tab / Shift+Tab", tr("przejście między polami formularza i tabelą wyników")),
                 ("F10 / q", tr("wyjście (q – gdy kursor nie stoi w polu tekstowym)")),
                 ("Ctrl+L", tr("przerysuj ekran")),
                 (tr("Esc, cyfra"), tr("zamiennik klawiszy F (Esc 1 = F1 … Esc 0 = F10), jak w Midnight Commanderze"))):
        d.kv(k, v, keyw=20)
    d.h(tr("Formularz (górna część ekranu)"))
    for k, v in (("↑ ↓", tr("poprzedni / następny wiersz pól; ↓ z ostatniego wiersza przechodzi do tabeli")),
                 ("← →", tr("kursor w polu; na początku/końcu pola – przejście do poprzedniego/następnego pola")),
                 ("Enter", tr("uruchom diagnostykę; w polu SSL – lista wyboru (także Spacja)")),
                 ("Home / End", tr("początek / koniec pola")),
                 ("Ctrl+U", tr("wyczyść pole"))):
        d.kv(k, v, keyw=20)
    d.h(tr("Tabela wyników"))
    for k, v in (("↑ ↓ PgUp PgDn", tr("wybór wiersza (↑ w pierwszym wierszu wraca do formularza)")),
                 ("Home / End", tr("pierwszy / ostatni wiersz")),
                 (tr("← → lub 1–5"), tr("zmiana zakładki")),
                 ("Enter / F3", tr("szczegóły wybranego wiersza")),
                 (tr("/ lub F4"), tr("filtr – tylko wiersze zawierające wpisany tekst (Esc czyści filtr)")),
                 ("s / F6", tr("pokaż lub ukryj role systemowe pg_* (zakładka Role)")),
                 ("t / F9", tr("wybór motywu kolorów (także z formularza: F9)")),
                 ("l / F8", tr("wybór języka: English / Polski (także z formularza: F8)")),
                 ("F7", tr("o programie: wersja, autor, licencja MIT"))):
        d.kv(k, v, keyw=20)
    d.h(tr("Okno szczegółów"))
    for k, v in (("↑ ↓ PgUp PgDn", tr("przewijanie")), ("← →", tr("poprzedni / następny wiersz tabeli")),
                 ("Esc / Enter / q", tr("zamknięcie"))):
        d.kv(k, v, keyw=20)
    d.h(tr("Motywy (F9)"))
    for key, label, desc, _ in THEMES:
        d.kv(tr(label), "%s  [%s]" % (tr(desc), key), keyw=20)
    d.p(tr("Wybrany motyw i język są zapamiętywane w pliku %s – to jedyny plik, który program zapisuje, i tylko "
           "wtedy, gdy zmienisz motyw (F9) lub język (F8). Na jedno uruchomienie można je wskazać opcjami "
           "--theme i --lang.") % config_path(), "dim")
    d.h(tr("Mysz"))
    d.p(tr("Kliknięcie pola, przycisku, zakładki, wiersza lub klawisza na dolnym pasku. Dwuklik wiersza – "
        "szczegóły. Kółko – przewijanie. Kliknięcie poza oknem – zamknięcie okna. Zaznaczanie tekstu "
        "w terminalu: Shift + przeciągnięcie myszą."))
    d.h(tr("Pola połączenia"))
    for k, v in (("Host", tr("puste = lokalne gniazdo Unix; nazwa, adres IP albo katalog gniazda (np. /var/run/postgresql)")),
                 ("Port", tr("domyślnie 5432")),
                 (tr("Baza"), tr("baza, do której program się łączy (domyślnie postgres); dane o wszystkich bazach "
                          "pochodzą z katalogu systemowego")),
                 (tr("Użytkownik"), tr("puste = nazwa bieżącego użytkownika systemu")),
                 (tr("Hasło"), tr("puste = psql użyje ~/.pgpass lub PGPASSWORD; hasło trafia do psql przez zmienną "
                           "środowiskową, nie przez linię poleceń")),
                 ("SSL", tr("tryb sslmode: prefer, disable, allow, require, verify-ca, verify-full")),
                 (tr("Plik pg_hba.conf"), tr("opcjonalnie: ścieżka do pliku czytanego lokalnie. Puste = widok "
                                      "pg_hba_file_rules z serwera; gdy brak uprawnień – próba odczytu "
                                      "pliku na tym komputerze")),
                 (tr("psql jako"), tr("tylko gdy program działa jako root: konto systemowe, z którego uruchamiany jest "
                               "psql. Wybierz postgres, aby połączyć się metodą peer jako superużytkownik, a "
                               "jednocześnie (jako root) odczytać reguły firewalla"))):
        d.kv(k, v, keyw=20)
    d.h(tr("Zakładki"))
    for k, v in ((tr("Serwer"), tr("podsumowanie problemów, połączenie, wersja, pliki konfiguracyjne, nasłuch, "
                            "SSL, szyfrowanie haseł, klastry na tym komputerze")),
                 (tr("Bazy danych"), tr("bazy w instancji: rozmiar, właściciel, kodowanie, kto ma prawo CONNECT")),
                 (tr("Dostęp (pg_hba)"), tr("reguły: skąd (adres), dokąd (bazy), kto (role), jak (metoda) – z oceną "
                                     "ryzyka i wykrywaniem reguł przesłoniętych")),
                 (tr("Role"), tr("atrybuty, typ hasła, członkostwa, uprawnienia do baz i pasujące reguły pg_hba")),
                 (tr("Sieć i firewall"), tr("na jakich adresach serwer nasłuchuje, test połączenia TCP, stan firewalla "
                                     "(nftables, iptables, firewalld, ufw), czy port bazy jest otwarty z sieci "
                                     "i czy firewall nie blokuje sieci dopuszczonych w pg_hba"))):
        d.kv(k, v, keyw=20)
    d.h(tr("Ocena"))
    d.item(tr("poważne ryzyko, np. trust z sieci albo błąd w pliku pg_hba.conf"), CRIT)
    d.item(tr("warto poprawić, np. dostęp z dowolnego adresu, hasło jawnym tekstem, hasło MD5, "
           "reguła przesłonięta"), WARN)
    d.item(tr("informacja lub dobra praktyka"), INFO)
    d.item(tr("brak uwag"), OK)
    d.h(tr("Bezpieczeństwo – program niczego nie zmienia"))
    d.item(tr("wykonuje wyłącznie stałe zapytania SELECT do katalogów systemowych"))
    d.item(tr("każde zapytanie działa w transakcji BEGIN READ ONLY zakończonej ROLLBACK"))
    d.item(tr("psql jest uruchamiany z -X (bez ~/.psqlrc) i -w (bez pytań o hasło)"))
    d.item(tr("program nie zmienia niczego w systemie; plik pg_hba.conf jest tylko czytany; jedyny zapisywany plik "
           "to własne ustawienia interfejsu (motyw i język) w katalogu domowym – tylko po ich zmianie"))
    d.item(tr("stan sieci i firewalla: odczyt /proc/net oraz wyłącznie polecenia listujące – nft list ruleset, "
           "iptables-save, firewall-cmd --state/--list-all, ufw status; moduły jądra firewalla nie są "
           "ładowane, jeśli nie są aktywne"))
    d.item(tr("test połączenia TCP tylko otwiera i od razu zamyka połączenie – nic nie jest wysyłane"))
    d.h(tr("Wskazówki"))
    d.p(tr("Najpełniejsze dane (typy haseł, reguły pg_hba, ścieżki plików) widzi superużytkownik bazy, "
        "a reguły firewalla – root. Najprościej uruchomić program jako root; psql zostanie wtedy "
        "uruchomiony z konta postgres (pole „psql jako”):"))
    d.p("    sudo python3 %s" % prog, "key")
    d.p(tr("Bez uprawnień roota (bez sprawdzenia reguł firewalla):"))
    d.p("    sudo -u postgres python3 %s" % prog, "key")
    d.p(tr("Raport tekstowy bez interfejsu:"))
    d.p("    python3 %s --report" % prog, "key")
    d.h(tr("Autor i licencja"))
    d.kv(tr("Autor"), "%s <%s>" % (AUTHOR, AUTHOR_EMAIL), keyw=20)
    d.kv(tr("Licencja"), tr("MIT – pełny tekst: F7 (O programie) lub opcja --license"), keyw=20)
    return d


# =============================================================================
#  Interfejs pelnoekranowy (curses)
# =============================================================================

# Role kolorow: (kolor tekstu, kolor tla, pogrubienie). "white" bez pogrubienia to jasnoszary,
# z pogrubieniem – bialy (jak lightgray / white w skorkach Midnight Commandera).
THEME_SPEC = {
    "normal": ("white", "blue", 0), "bold": ("white", "blue", 1), "dim": ("cyan", "blue", 0),
    "frame": ("white", "blue", 0), "ptitle": ("black", "cyan", 0), "ptitle_in": ("white", "blue", 1),
    "header": ("yellow", "blue", 1), "section": ("yellow", "blue", 1),
    "sel": ("black", "cyan", 0), "sel_in": ("black", "white", 0),
    "label": ("white", "blue", 0), "label_f": ("yellow", "blue", 1),
    "field": ("black", "cyan", 0), "field_ph": ("blue", "cyan", 0), "field_f": ("yellow", "black", 1),
    "button": ("black", "white", 0), "button_f": ("yellow", "black", 1),
    "tab": ("white", "blue", 0), "tab_a": ("black", "cyan", 0), "tab_ai": ("black", "white", 0),
    "title": ("black", "cyan", 0), "title_ro": ("white", "green", 1),
    "status": ("white", "blue", 0), "status_err": ("white", "red", 1), "status_ok": ("green", "blue", 1),
    "status_warn": ("yellow", "blue", 1), "status_info": ("white", "blue", 0),
    "fnum": ("white", "black", 0), "flabel": ("black", "cyan", 0),
    "sev0": ("green", "blue", 1), "sev1": ("cyan", "blue", 1), "sev2": ("yellow", "blue", 1),
    "sev3": ("white", "red", 1),
    "p_text": ("black", "white", 0), "p_frame": ("black", "white", 0), "p_title": ("blue", "white", 1),
    "p_head": ("blue", "white", 1), "p_key": ("blue", "white", 0), "p_thead": ("blue", "white", 1),
    "p_dim": ("blue", "white", 0), "p_bold": ("black", "white", 1), "p_sel": ("black", "cyan", 0),
    "p_sev0": ("green", "white", 1), "p_sev1": ("white", "blue", 1), "p_sev2": ("black", "yellow", 0),
    "p_sev3": ("white", "red", 1),
    "e_text": ("white", "red", 1), "e_frame": ("white", "red", 1), "e_title": ("yellow", "red", 1),
    "e_head": ("yellow", "red", 1), "e_key": ("white", "red", 0), "e_dim": ("white", "red", 0),
}

# GoTaR – odwzorowanie skorki gotar.ini z Midnight Commandera: czarne tlo, jasnoszary tekst,
# zaznaczenie bialym na niebieskim, naglowki jaskrawoczerwone, pola zielone, okna turkusowe na niebieskim.
THEME_GOTAR = {
    "normal": ("white", "black", 0), "bold": ("white", "black", 1), "dim": ("cyan", "black", 0),
    "frame": ("white", "black", 0), "ptitle": ("white", "blue", 1), "ptitle_in": ("white", "black", 0),
    "header": ("red", "black", 1), "section": ("cyan", "black", 1),
    "sel": ("white", "blue", 1), "sel_in": ("green", "blue", 1),
    "label": ("white", "black", 0), "label_f": ("yellow", "black", 1),
    "field": ("green", "blue", 1), "field_ph": ("cyan", "blue", 0), "field_f": ("yellow", "black", 1),
    "button": ("cyan", "blue", 1), "button_f": ("red", "black", 1),
    "tab": ("white", "black", 0), "tab_a": ("white", "blue", 1), "tab_ai": ("green", "black", 1),
    "title": ("green", "black", 1), "title_ro": ("black", "green", 0),
    "status": ("white", "black", 0), "status_err": ("white", "red", 1), "status_ok": ("green", "black", 1),
    "status_warn": ("yellow", "black", 1), "status_info": ("white", "black", 0),
    "fnum": ("white", "black", 0), "flabel": ("white", "blue", 1),
    "sev0": ("green", "black", 1), "sev1": ("cyan", "black", 1), "sev2": ("yellow", "black", 1),
    "sev3": ("white", "red", 1),
    "p_text": ("cyan", "blue", 1), "p_frame": ("cyan", "blue", 1), "p_title": ("red", "blue", 1),
    "p_head": ("red", "blue", 1), "p_key": ("white", "blue", 0), "p_thead": ("yellow", "blue", 1),
    "p_dim": ("white", "blue", 0), "p_bold": ("white", "blue", 1), "p_sel": ("yellow", "black", 1),
    "p_sev0": ("green", "blue", 1), "p_sev1": ("black", "cyan", 0), "p_sev2": ("black", "yellow", 0),
    "p_sev3": ("white", "red", 1),
}

# Dark – odwzorowanie skorki dark.ini z Midnight Commandera.
THEME_DARK = {
    "normal": ("white", "black", 0), "bold": ("white", "black", 1), "dim": ("cyan", "black", 0),
    "frame": ("white", "black", 0), "ptitle": ("black", "cyan", 0), "ptitle_in": ("white", "black", 1),
    "header": ("yellow", "black", 1), "section": ("yellow", "black", 1),
    "sel": ("black", "cyan", 0), "sel_in": ("black", "white", 0),
    "label": ("white", "black", 0), "label_f": ("yellow", "black", 1),
    "field": ("black", "cyan", 0), "field_ph": ("blue", "cyan", 0), "field_f": ("white", "blue", 1),
    "button": ("black", "white", 0), "button_f": ("black", "cyan", 0),
    "tab": ("white", "black", 0), "tab_a": ("black", "cyan", 0), "tab_ai": ("black", "white", 0),
    "title": ("black", "cyan", 0), "title_ro": ("white", "green", 1),
    "status": ("white", "black", 0), "status_err": ("white", "red", 1), "status_ok": ("green", "black", 1),
    "status_warn": ("yellow", "black", 1), "status_info": ("white", "black", 0),
    "fnum": ("white", "black", 0), "flabel": ("black", "cyan", 0),
    "sev0": ("green", "black", 1), "sev1": ("cyan", "black", 1), "sev2": ("yellow", "black", 1),
    "sev3": ("white", "red", 1),
    "p_text": ("cyan", "blue", 1), "p_frame": ("cyan", "blue", 1), "p_title": ("white", "blue", 1),
    "p_head": ("white", "blue", 1), "p_key": ("white", "blue", 0), "p_thead": ("yellow", "blue", 1),
    "p_dim": ("white", "blue", 0), "p_bold": ("white", "blue", 1), "p_sel": ("blue", "cyan", 0),
    "p_sev0": ("green", "blue", 1), "p_sev1": ("black", "cyan", 0), "p_sev2": ("black", "yellow", 0),
    "p_sev3": ("white", "red", 1),
}

# Jasny – czarny tekst na jasnym tle, dla terminali z jasnym schematem.
THEME_LIGHT = {
    # na jasnym tle unikamy pogrubien – w wielu terminalach rozjasniaja kolor i psuja kontrast
    "normal": ("black", "white", 0), "bold": ("black", "white", 1), "dim": ("blue", "white", 0),
    "frame": ("black", "white", 0), "ptitle": ("white", "blue", 1), "ptitle_in": ("black", "white", 0),
    "header": ("red", "white", 0), "section": ("magenta", "white", 0),
    "sel": ("white", "blue", 1), "sel_in": ("black", "cyan", 0),
    "label": ("black", "white", 0), "label_f": ("red", "white", 0),
    "field": ("black", "cyan", 0), "field_ph": ("blue", "cyan", 0), "field_f": ("white", "blue", 1),
    "button": ("black", "cyan", 0), "button_f": ("white", "blue", 1),
    "tab": ("black", "white", 0), "tab_a": ("white", "blue", 1), "tab_ai": ("black", "cyan", 0),
    "title": ("white", "blue", 1), "title_ro": ("white", "green", 1),
    "status": ("black", "white", 0), "status_err": ("white", "red", 1), "status_ok": ("green", "white", 0),
    "status_warn": ("red", "white", 0), "status_info": ("black", "white", 0),
    "fnum": ("white", "black", 0), "flabel": ("black", "cyan", 0),
    "sev0": ("green", "white", 0), "sev1": ("blue", "white", 0), "sev2": ("black", "yellow", 0),
    "sev3": ("white", "red", 1),
    "p_text": ("black", "cyan", 0), "p_frame": ("black", "cyan", 0), "p_title": ("blue", "cyan", 0),
    "p_head": ("blue", "cyan", 0), "p_key": ("blue", "cyan", 0), "p_thead": ("red", "cyan", 0),
    "p_dim": ("blue", "cyan", 0), "p_bold": ("black", "cyan", 1), "p_sel": ("white", "blue", 1),
    "p_sev0": ("black", "green", 0), "p_sev1": ("white", "blue", 1), "p_sev2": ("black", "yellow", 0),
    "p_sev3": ("white", "red", 1),
}

THEMES = [
    ("mc", "Midnight Commander", "klasyczny niebieski (domyślny)", THEME_SPEC),
    ("gotar", "GoTaR", "skórka gotar z MC – czarne tło, zielone pola, turkusowe okna", THEME_GOTAR),
    ("dark", "Dark", "skórka dark z MC – czarne tło, turkusowe zaznaczenie", THEME_DARK),
    ("light", "Jasny", "ciemny tekst na jasnym tle", THEME_LIGHT),
    ("mono", "Monochromatyczny", "bez kolorów – inwersja i pogrubienie", None),
]
THEME_NAMES = [t[0] for t in THEMES]
THEME_ALIASES = {"jasny": "light"}          # klucz z wersji 1.2

# W terminalach 256-kolorowych "niebieski" z palety ANSI bywa bardzo jasny (np. MobaXterm, PuTTY),
# przez co tekst na niebieskim tle ma slaby kontrast. Tam uzywamy stalych kolorow z palety 256:
# 18 = #000087 (ciemny granat) – niezaleznie od ustawien palety terminala.
DEEP_256 = {"gotar": {"blue": 18}, "dark": {"blue": 18}}

MONO = {"sel": "R", "field": "U", "field_f": "R", "button_f": "R", "tab_a": "R", "tab_ai": "U",
        "title": "R", "title_ro": "R", "flabel": "R", "header": "B", "section": "B", "bold": "B",
        "sev2": "B", "sev3": "R", "status_err": "R", "p_head": "B", "p_title": "B", "p_thead": "B",
        "p_sel": "R", "p_sev3": "R", "p_sev2": "B", "e_title": "B", "ptitle": "R", "label_f": "B",
        "p_sev0": "B", "sev0": "B", "button": "U", "fnum": "B", "status_warn": "B", "e_text": "R",
        "e_frame": "R", "e_head": "R", "e_key": "R", "e_dim": "R"}


class Theme(object):
    def __init__(self):
        self.attr = {}
        self.name = "mc"
        self._started = False

    def setup(self, name="mc"):
        if name not in THEME_NAMES:
            name = "mc"
        self.name = name
        spec = dict(THEME_SPEC)
        overrides = dict((t[0], t[3]) for t in THEMES)[name]
        self.attr = {}
        if curses.has_colors() and overrides is not None:
            if not self._started:
                curses.start_color()
                self._started = True
            spec.update(overrides)
            cmap = {"black": curses.COLOR_BLACK, "red": curses.COLOR_RED, "green": curses.COLOR_GREEN,
                    "yellow": curses.COLOR_YELLOW, "blue": curses.COLOR_BLUE, "magenta": curses.COLOR_MAGENTA,
                    "cyan": curses.COLOR_CYAN, "white": curses.COLOR_WHITE}
            if curses.COLORS >= 256:
                cmap.update(DEEP_256.get(name, {}))
            pairs = {}
            for role, (fg, bg, bold) in spec.items():
                key = (fg, bg)
                if key not in pairs:
                    n = len(pairs) + 1
                    if n >= curses.COLOR_PAIRS:
                        n = 0
                    else:
                        curses.init_pair(n, cmap[fg], cmap[bg])
                    pairs[key] = n
                self.attr[role] = curses.color_pair(pairs[key]) | (curses.A_BOLD if bold else 0)
        else:
            if curses.has_colors() and not self._started:
                curses.start_color()
                self._started = True
            m = {"R": curses.A_REVERSE, "U": curses.A_UNDERLINE, "B": curses.A_BOLD}
            for role in spec:
                self.attr[role] = m.get(MONO.get(role, ""), curses.A_NORMAL)

    def get(self, name):
        return self.attr.get(name, self.attr.get("normal", 0))


# ----------------------------------------------------------------------------- ustawienia interfejsu
# Jedyny plik, jaki program zapisuje: wybrany motyw (tylko gdy uzytkownik go zmieni).

def config_path():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "pgdiag", "pgdiag.conf")


def load_config():
    import configparser
    cp = configparser.RawConfigParser()
    try:
        cp.read(config_path(), encoding="utf-8")
    except Exception:
        return {}
    theme = cp.get("ui", "theme", fallback=None) if cp.has_section("ui") else None
    theme = THEME_ALIASES.get(theme, theme)
    lang = cp.get("ui", "lang", fallback=None) if cp.has_section("ui") else None
    return {"theme": theme if theme in THEME_NAMES else None,
            "lang": lang if lang in ("en", "pl") else None}


def save_config(theme=None, lang=None):
    """Zapisuje motyw/jezyk w ~/.config/pgdiag/pgdiag.conf (atomowo, prawa 0600). Zwraca sciezke."""
    import configparser
    path = config_path()
    cfg_dir = os.path.dirname(path)
    base_dir = os.path.dirname(cfg_dir)
    created = [d for d in (base_dir, cfg_dir) if not os.path.isdir(d)]
    os.makedirs(cfg_dir, mode=0o700, exist_ok=True)
    cp = configparser.RawConfigParser()
    try:
        cp.read(path, encoding="utf-8")
    except Exception:
        cp = configparser.RawConfigParser()
    if not cp.has_section("ui"):
        cp.add_section("ui")
    if theme:
        cp.set("ui", "theme", theme)
    if lang:
        cp.set("ui", "lang", lang)
    tmp = "%s.tmp-%d" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("# PgDiag – UI settings / ustawienia interfejsu (F8: language/język, F9: theme/motyw)\n")
        cp.write(f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    # uruchomienie przez sudo z zachowanym HOME: plik ma nalezec do wlasciciela katalogu domowego
    if os.geteuid() == 0:
        try:
            st = os.stat(os.path.expanduser("~"))
            if st.st_uid != 0:
                for x in created + [path]:
                    os.chown(x, st.st_uid, st.st_gid)
        except OSError:
            pass
    return path


class Field(object):
    def __init__(self, key, label, value="", width=14, kind="text", choices=None, placeholder="", grow=False):
        self.key, self.label, self.value, self.width = key, label, value or "", width
        self.kind, self.choices, self.placeholder, self.grow = kind, choices or [], placeholder, grow
        self.cur, self.off = len(self.value), 0
        self.y = self.lx = self.fx = self.fw = 0

    def total(self):
        if self.kind == "button":
            return sw(U("[ %s ]" % tr(self.label)))
        return sw(U(tr(self.label))) + 2 + self.width


KEYMAP = {}
CTRL_KEYS = {"\x12": "C-R", "\x15": "C-U", "\x01": "HOME", "\x05": "END", "\x0b": "C-K",
             "\x0c": "C-L", "\x03": "C-C", "\x06": "F4"}


def init_keymap():
    k = KEYMAP
    pairs = [("KEY_UP", "UP"), ("KEY_DOWN", "DOWN"), ("KEY_LEFT", "LEFT"), ("KEY_RIGHT", "RIGHT"),
             ("KEY_PPAGE", "PGUP"), ("KEY_NPAGE", "PGDN"), ("KEY_HOME", "HOME"), ("KEY_END", "END"),
             ("KEY_BACKSPACE", "BS"), ("KEY_DC", "DEL"), ("KEY_BTAB", "BTAB"), ("KEY_ENTER", "ENTER"),
             ("KEY_RESIZE", "RESIZE"), ("KEY_MOUSE", "MOUSE"), ("KEY_A1", "HOME"), ("KEY_C1", "END"),
             ("KEY_A3", "PGUP"), ("KEY_C3", "PGDN"), ("KEY_FIND", "HOME"), ("KEY_SELECT", "END")]
    for attr, name in pairs:
        if hasattr(curses, attr):
            k[getattr(curses, attr)] = name
    for n in range(1, 13):
        k[curses.KEY_F0 + n] = "F%d" % n


def norm_key(k):
    if isinstance(k, int):
        return KEYMAP.get(k, k)
    if k in ("\n", "\r"):
        return "ENTER"
    if k == "\t":
        return "TAB"
    if k == "\x1b":
        return "ESC"
    if k in ("\x7f", "\x08"):
        return "BS"
    return CTRL_KEYS.get(k, k)


def printable(k):
    return isinstance(k, str) and len(k) == 1 and k.isprintable()


BUTTON5 = getattr(curses, "BUTTON5_PRESSED", 0x200000)
BUTTON4 = getattr(curses, "BUTTON4_PRESSED", 0x80000)
CLICK = (getattr(curses, "BUTTON1_PRESSED", 2) | getattr(curses, "BUTTON1_CLICKED", 4)
         | getattr(curses, "BUTTON1_DOUBLE_CLICKED", 8))
DOUBLE = getattr(curses, "BUTTON1_DOUBLE_CLICKED", 8)

FKEYS = [(1, "Pomoc"), (2, "Uruchom"), (3, "Szczeg."), (4, "Filtr"), (5, ""), (6, "Systemowe"),
         (7, "O progr."), (8, "Język"), (9, "Motyw"), (10, "Wyjście")]


class App(object):
    MIN_W, MIN_H = 64, 18

    def __init__(self, scr, opts):
        self.scr, self.opts = scr, opts
        self.theme = Theme()
        self.theme.setup(opts.theme or load_config().get("theme") or "mc")
        scr.bkgd(" ", self.A("normal"))
        scr.keypad(True)
        self.set_cursor(False)
        if not opts.no_mouse:
            try:
                curses.mousemask(curses.ALL_MOUSE_EVENTS)
                curses.mouseinterval(0)
            except curses.error:
                pass
        try:
            osuser = getpass.getuser()
        except Exception:
            osuser = tr("bieżący")
        ssl_choices = list(SSL_MODES)
        if opts.sslmode and opts.sslmode not in ssl_choices:
            ssl_choices.append(opts.sslmode)
        self.fields = [
            Field("host", "Host", opts.host, 18, placeholder="(gniazdo lokalne)", grow=True),
            Field("port", "Port", opts.port, 6),
            Field("dbname", "Baza", opts.dbname, 14, grow=True),
            Field("user", "Użytkownik", opts.user, 14, placeholder="(%s)" % osuser, grow=True),
            Field("password", "Hasło", opts.password, 14, kind="password", placeholder="(brak/.pgpass)"),
            Field("sslmode", "SSL", opts.sslmode or "prefer", 13, kind="choice", choices=ssl_choices),
            Field("hba", "pg_hba.conf", opts.hba_file, 22, placeholder="(z serwera)", grow=True),
        ]
        if os.geteuid() == 0:
            ch = ["root"] + [u for u in ("postgres",) if user_exists(u)]
            if opts.os_user and opts.os_user not in ch:
                ch.append(opts.os_user)
            self.fields.append(Field("os_user", "psql jako", opts.os_user or "root", 10, kind="choice", choices=ch))
        self.button = Field("run", "Uruchom", kind="button")
        self.widgets = self.fields + [self.button]
        self.focus, self.fidx = "form", 0
        self.tabs, self.tab = empty_tabs(), 0
        self.show_system = False
        self.model = self.report = None
        self.running, self.q, self.t_start = False, queue.Queue(), 0.0
        self.status = (tr("Wpisz parametry połączenia i naciśnij Enter lub F2. Program niczego nie zmienia na serwerze."), "info")
        self.pending_error = None
        self.hits, self.cursor, self.page = [], None, 10
        self.last_click = (0.0, -1)
        self.last_info = ""
        self.layout()

    # ------------------------------------------------------------- narzedzia rysowania
    def A(self, name):
        return self.theme.get(name)

    def set_cursor(self, on):
        try:
            curses.curs_set(1 if on else 0)
        except curses.error:
            pass

    def put(self, y, x, text, role="normal", w=None):
        if y < 0 or y >= self.H or x < 0 or x >= self.W:
            return
        maxw = self.W - x if w is None else min(w, self.W - x)
        if maxw <= 0:
            return
        t, _ = clip(U(text), maxw)
        try:
            self.scr.addstr(y, x, t, self.A(role))
        except curses.error:
            pass

    def put_ch(self, y, x, ch, role="frame"):
        if 0 <= y < self.H and 0 <= x < self.W:
            try:
                self.scr.addch(y, x, ch, self.A(role))
            except curses.error:
                pass

    def hline(self, y, x, n, role="frame"):
        if n > 0 and 0 <= y < self.H:
            try:
                self.scr.hline(y, x, curses.ACS_HLINE | self.A(role), n)
            except curses.error:
                pass

    def box(self, y, x, h, w, role="frame", title=None, title_role=None):
        a = self.A(role)
        s = self.scr
        try:
            s.addch(y, x, curses.ACS_ULCORNER, a)
            s.hline(y, x + 1, curses.ACS_HLINE | a, w - 2)
            s.addch(y, x + w - 1, curses.ACS_URCORNER, a)
            s.vline(y + 1, x, curses.ACS_VLINE | a, h - 2)
            s.vline(y + 1, x + w - 1, curses.ACS_VLINE | a, h - 2)
            s.addch(y + h - 1, x, curses.ACS_LLCORNER, a)
            s.hline(y + h - 1, x + 1, curses.ACS_HLINE | a, w - 2)
            s.addch(y + h - 1, x + w - 1, curses.ACS_LRCORNER, a)
        except curses.error:
            pass
        if title:
            self.put(y, x + 2, title, title_role or role, w - 4)

    # ------------------------------------------------------------- uklad ekranu
    def layout(self):
        self.H, self.W = self.scr.getmaxyx()
        W = self.W
        inner = W - 4
        rows, cur, used = [], [], 0
        for wd in self.widgets:
            need = wd.total()
            add = need if not cur else need + 3
            if cur and used + add > inner:
                rows.append(cur)
                cur, used, add = [], 0, need
            cur.append(wd)
            used += add
        if cur:
            rows.append(cur)
        y = 2
        for row in rows:
            used = sum(wd.total() for wd in row) + 3 * (len(row) - 1)
            extra = inner - used
            growers = [wd for wd in row if wd.grow]
            per = min(extra // len(growers), 30) if growers and extra > 0 else 0
            x = 2
            for wd in row:
                wd.y = y
                if wd.kind == "button":
                    bw = wd.total()
                    if wd is row[-1]:
                        x = max(x, W - 2 - bw)
                    wd.lx = wd.fx = x
                    wd.fw = bw
                    x += bw + 3
                else:
                    wd.lx = x
                    wd.fx = x + sw(U(tr(wd.label))) + 2
                    wd.fw = wd.width + (per if wd.grow else 0)
                    x = wd.fx + wd.fw + 3
            y += 1
        self.form_rows = rows
        self.form_h = len(rows) + 2
        self.tabs_y = 1 + self.form_h
        self.panel_top = self.tabs_y + 1
        self.panel_bot = self.H - 3
        self.status_y = self.H - 2
        self.fbar_y = self.H - 1

    def cur_tab(self):
        return self.tabs[self.tab]

    def rows_now(self):
        return self.cur_tab().visible(self.show_system)

    # ------------------------------------------------------------- rysowanie
    def draw(self, refresh=True):
        s = self.scr
        s.erase()
        self.hits = []
        self.cursor = None
        H, W = self.H, self.W
        if H < self.MIN_H or W < self.MIN_W:
            self.put(0, 0, tr("Za mały terminal: %dx%d") % (W, H), "bold")
            self.put(1, 0, "Minimum: %dx%d" % (self.MIN_W, self.MIN_H), "normal")
            self.put(2, 0, tr("Powiększ okno lub F10/q"), "normal")
            if refresh:
                s.noutrefresh()
                curses.doupdate()
            return
        # pasek tytulu
        self.put(0, 0, " " * W, "title")
        self.put(0, 1, tr("PgDiag %s – diagnostyka PostgreSQL") % VERSION, "title")
        ro = tr(" tylko odczyt ")
        info = self.last_info
        if info and W > 60 + sw(info):
            self.put(0, W - sw(ro) - sw(info) - 3, info, "title")
        self.put(0, W - sw(ro) - 1, ro, "title_ro")
        # formularz
        f_focus = self.focus == "form"
        self.box(1, 0, self.form_h, W, "frame", tr(" Połączenie "), "ptitle" if f_focus else "ptitle_in")
        for i, wd in enumerate(self.widgets):
            self.draw_widget(i, wd)
        self.draw_tabs()
        self.draw_panel()
        self.draw_status()
        self.draw_fbar()
        if self.cursor:
            self.set_cursor(True)
            try:
                s.move(*self.cursor)
            except curses.error:
                pass
        else:
            self.set_cursor(False)
        if refresh:
            s.noutrefresh()
            curses.doupdate()

    def draw_widget(self, i, wd):
        focused = self.focus == "form" and self.fidx == i
        if wd.kind == "button":
            label = "[ %s ]" % (tr("Czekaj…") if self.running else tr(wd.label))
            label = fit(label, wd.fw, "c")
            self.put(wd.y, wd.lx, label, "button_f" if focused else "button")
            self.hits.append((wd.y, wd.lx, wd.lx + wd.fw, ("widget", i)))
            return
        self.put(wd.y, wd.lx, tr(wd.label) + ":", "label_f" if focused else "label")
        self.hits.append((wd.y, wd.lx, wd.fx + wd.fw, ("widget", i)))
        attr = "field_f" if focused else "field"
        if wd.kind == "choice":
            self.put(wd.y, wd.fx, fit(wd.value, wd.fw - 2) + " ▾", attr)
            return
        val = wd.value if wd.kind != "password" else "*" * len(wd.value)
        ph = tr(wd.placeholder)
        if wd.key == "user":
            osf = [f for f in self.fields if f.key == "os_user"]
            if osf:
                ph = "(%s)" % osf[0].value
        if not wd.value and not focused and ph:
            self.put(wd.y, wd.fx, fit(ph, wd.fw), "field_ph")
            return
        wd.cur = max(0, min(wd.cur, len(val)))
        if wd.cur < wd.off:
            wd.off = wd.cur
        while wd.off < wd.cur and sw(U(val[wd.off:wd.cur])) > wd.fw - 1:
            wd.off += 1
        vis, n = clip(U(val[wd.off:]), wd.fw)
        self.put(wd.y, wd.fx, vis + " " * (wd.fw - n), attr)
        if focused:
            self.cursor = (wd.y, wd.fx + sw(U(val[wd.off:wd.cur])))

    def draw_tabs(self):
        y, x = self.tabs_y, 1
        for i, t in enumerate(self.tabs):
            lab = " %d %s" % (i + 1, t.title)
            if t.count is not None:
                lab += " (%d)" % t.count
            lab += " "
            active = i == self.tab
            role = ("tab_a" if self.focus == "table" else "tab_ai") if active else "tab"
            x0 = x
            self.put(y, x, lab, role)
            x += sw(U(lab))
            if t.badge >= WARN:
                self.put(y, x, "!", "sev%d" % t.badge)
                x += 1
            self.hits.append((y, x0, x, ("tab", i)))
            x += 1
            if x >= self.W - 2:
                break

    def draw_panel(self):
        t = self.cur_tab()
        top, bot, W = self.panel_top, self.panel_bot, self.W
        t_focus = self.focus == "table"
        self.box(top, 0, bot - top + 1, W, "frame", " %s " % t.title, "ptitle" if t_focus else "ptitle_in")
        x0, w = 1, W - 2
        y = top + 1
        if self.report is None:
            self.draw_welcome(y, bot - 1, x0, w)
            return
        if t.error:
            msg, hint = t.error
            self.put(y + 1, x0 + 2, tr(" BRAK DANYCH "), "sev3")
            yy = y + 3
            for ln in wrap(msg, w - 6):
                self.put(yy, x0 + 2, ln, "sev2")
                yy += 1
            if hint:
                yy += 1
                for ln in wrap(hint, w - 6):
                    self.put(yy, x0 + 2, ln, "normal")
                    yy += 1
            return
        rows = self.rows_now()
        avail = bot - y
        n_info = min(len(t.info), max(0, avail - 6))
        for segs in t.info[:n_info]:
            x = x0 + 1
            for text, role in segs:
                room = x0 + w - 1 - x
                if room <= 0:
                    break
                if sw(U(text)) > room:
                    self.put(y, x, fit(text, room), role)
                    break
                self.put(y, x, text, role)
                x += sw(U(text))
            y += 1
        self.draw_table(t, rows, y, bot - 1, x0, w)
        # informacja w dolnej ramce
        if rows:
            pos = " %d/%d " % (t.sel + 1, len(rows))
            self.put(bot, W - sw(pos) - 2, pos, "frame")
        if t.filter:
            self.put(bot, 2, tr(" Filtr: %s (Esc w filtrze czyści) ") % t.filter, "sev2", W - 20)
        elif t.key == "roles":
            hidden = len(t.rows) - len(t.visible(False))
            if not self.show_system and hidden:
                self.put(bot, 2, tr(" ukryto %d ról systemowych pg_* (F6) ") % hidden, "dim")

    def draw_welcome(self, y, ybot, x0, w):
        prog = os.path.basename(sys.argv[0]) or "pgdiag.py"
        lines = [
            (tr("PgDiag – diagnostyka PostgreSQL (tylko odczyt)"), "header"),
            ("", "normal"),
            (tr("1. Wpisz parametry połączenia w polach u góry (puste pole Host = lokalne gniazdo Unix)."), "normal"),
            (tr("2. Naciśnij Enter, F2 albo kliknij [ Uruchom ]."), "normal"),
            (tr("3. Zakładki zmieniasz strzałkami ← →, wiersze ↑ ↓, Enter pokazuje szczegóły, F1 – pomoc."), "normal"),
            ("", "normal"),
            (tr("Program pokaże: bazy danych, reguły dostępu pg_hba (skąd, dokąd, kto, jak) z oceną ryzyka"), "dim"),
            (tr("oraz role z atrybutami, członkostwami i uprawnieniami."), "dim"),
            ("", "normal"),
            (tr("Najpełniejsze dane widzi superużytkownik, np.:  sudo -u postgres python3 %s") % prog, "dim"),
            (tr("Wykonywane są wyłącznie zapytania SELECT w transakcji READ ONLY; w systemie nic nie jest zmieniane."), "sev0"),
            (tr("F8 – język (English / Polski), F9 – motyw (mc, gotar, dark, light, mono)."), "dim"),
            ("", "normal"),
            ("PgDiag %s · © %s %s <%s> · %s" % (VERSION, COPYRIGHT_YEAR, AUTHOR, AUTHOR_EMAIL,
                                                 tr("licencja MIT · F7 – o programie")), "dim"),
        ]
        yy = y + max(0, (ybot - y + 1 - len(lines)) // 3)
        for text, role in lines:
            if yy > ybot:
                break
            for ln in wrap(text, w - 4) if text else [""]:
                if yy > ybot:
                    break
                self.put(yy, x0 + max(2, (w - sw(U(ln))) // 2), ln, role)
                yy += 1

    def draw_table(self, t, rows, y, ybot, x0, w):
        cols = visible_columns(t.columns, rows, w, pad=1)
        n = len(cols)
        widths = fit_columns(cols, rows, w, pad=1)
        seps = []
        x = x0
        for i, c in enumerate(cols):
            self.put(y, x, " " + fit(c.title, widths[i] - 2, "r" if c.align == "r" else "l") + " ", "header")
            x += widths[i]
            if i < n - 1:
                seps.append(x)
                self.put_ch(y, x, curses.ACS_VLINE)
                x += 1
        yl = y + 1
        self.put_ch(yl, 0, curses.ACS_LTEE)
        self.hline(yl, 1, self.W - 2)
        self.put_ch(yl, self.W - 1, curses.ACS_RTEE)
        for sx in seps:
            self.put_ch(yl, sx, curses.ACS_PLUS)
        first = y + 2
        page = max(1, ybot - first + 1)
        self.page = page
        if rows:
            t.sel = max(0, min(t.sel, len(rows) - 1))
            if not rows[t.sel].selectable:
                self.fix_sel(t, rows, 1)
            if t.sel < t.top:
                t.top = t.sel
            if t.sel >= t.top + page:
                t.top = t.sel - page + 1
            t.top = max(0, min(t.top, max(0, len(rows) - page)))
            if t.sel < t.top:
                t.top = t.sel
            # pokaz naglowek sekcji nad pierwszym wierszem, jesli to mozliwe
            if t.top > 0 and t.top == t.sel and not rows[t.top - 1].selectable:
                t.top -= 1
        else:
            t.sel = t.top = 0
        for k in range(page):
            yy = first + k
            idx = t.top + k
            if idx >= len(rows):
                for sx in seps:
                    self.put_ch(yy, sx, curses.ACS_VLINE)
                continue
            r = rows[idx]
            if r.style == "section":
                self.hline(yy, x0, w, "dim")
                self.put(yy, x0 + 1, " %s " % r.cells.get(cols[0].key, ""), "section")
                continue
            selected = idx == t.sel
            base = {"system": "dim", "dim": "dim", "bold": "bold"}.get(r.style, "normal")
            if selected:
                base = "sel" if self.focus == "table" else "sel_in"
            x = x0
            for i, c in enumerate(cols):
                role = base
                if not selected and r.sev_col == c.key and r.sev is not None:
                    role = "sev%d" % r.sev
                self.put(yy, x, " " + fit(r.cells.get(c.key, ""), widths[i] - 2, c.align) + " ", role)
                x += widths[i]
                if i < n - 1:
                    self.put_ch(yy, x, curses.ACS_VLINE, base if selected else "frame")
                    x += 1
            self.hits.append((yy, x0, x0 + w, ("row", idx)))
        if not rows:
            msg = tr("(brak wierszy pasujących do filtra „%s”)") % t.filter if t.filter else tr("(brak danych)")
            self.put(first + 1, x0 + max(1, (w - sw(msg)) // 2), msg, "dim")

    def draw_status(self):
        y, W = self.status_y, self.W
        self.put(y, 0, " " * W, "status")
        right = ""
        if self.report:
            pr = self.report["params"]
            right = " %s · %s · %.1f s " % (self.conn_desc(pr), self.report.get("when", ""), self.report.get("elapsed", 0))
        if self.running:
            spin = "|/-\\"[int(time.time() * 8) % 4]
            msg, kind = tr("%s Łączenie i pobieranie danych… %.1f s") % (spin, time.time() - self.t_start), "warn"
        else:
            msg, kind = self.status
        rw = sw(U(right)) if W > 100 else 0
        self.put(y, 1, fit(msg, W - 2 - rw), "status_" + kind)
        if rw:
            self.put(y, W - rw, right, "dim")

    def draw_fbar(self):
        y, W = self.fbar_y, self.W
        slot = W // 10
        x = 0
        for i, (n, lab) in enumerate(FKEYS):
            width = slot if i < 9 else W - x
            num = "%d" % n
            self.put(y, x, num, "fnum")
            self.put(y, x + len(num), fit(tr(lab), width - len(num)), "flabel")
            if lab:
                self.hits.append((y, x, x + width, ("fkey", n)))
            x += width

    @staticmethod
    def conn_desc(pr):
        host = pr.get("host") or tr("lokalnie")
        user = pr.get("user") or pr.get("os_user") or getpass.getuser()
        return "%s@%s:%s/%s" % (user, host, pr.get("port") or "5432", pr.get("dbname") or "")

    # ------------------------------------------------------------- petla glowna
    def loop(self):
        if self.opts.run:
            self.start_run()
        while True:
            self.poll()
            if self.pending_error is not None:
                doc, self.pending_error = self.pending_error, None
                self.viewer(doc, style="e")
                continue
            self.draw()
            key = self.getkey()
            if key is None:
                continue
            if self.handle(key) == "quit":
                return

    def getkey(self):
        self.scr.timeout(120 if self.running else -1)
        try:
            k = self.scr.get_wch()
        except curses.error:
            return None
        key = norm_key(k)
        if key == "ESC":
            self.scr.timeout(300)
            try:
                k2 = self.scr.get_wch()
            except curses.error:
                k2 = None
            self.scr.timeout(120 if self.running else -1)
            if k2 is not None:
                if isinstance(k2, str) and k2 in "1234567890":
                    return "F10" if k2 == "0" else "F" + k2
                try:
                    curses.unget_wch(k2)
                except Exception:
                    pass
        if key == "RESIZE":
            self.layout()
        return key

    def handle(self, key):
        if key == "RESIZE" or key == "C-L":
            self.layout()
            if key == "C-L":
                self.scr.clear()            # pelne przerysowanie ekranu
            return
        if key == "MOUSE":
            return self.on_mouse()
        if key == "C-C":
            return "quit"
        if isinstance(key, str) and key.startswith("F") and key[1:].isdigit():
            return self.fkey(int(key[1:]))
        if key == "C-R":
            self.start_run()
            return
        if self.H < self.MIN_H or self.W < self.MIN_W:
            if key in ("q", "Q", "ESC"):
                return "quit"
            return
        if self.focus == "form":
            return self.form_key(key)
        return self.table_key(key)

    def fkey(self, n):
        if n == 1:
            self.viewer(help_doc())
        elif n == 2:
            self.start_run()
        elif n == 3:
            self.open_detail()
        elif n == 4:
            self.filter_prompt()
        elif n == 6:
            self.toggle_system()
        elif n == 7:
            self.viewer(about_doc(find_psql(self.opts.psql),
                                  curses.COLORS if curses.has_colors() else 2))
        elif n == 8:
            self.lang_dialog()
        elif n == 9:
            self.theme_dialog()
        elif n == 10:
            return "quit"

    def toggle_system(self):
        self.show_system = not self.show_system
        self.set_status(tr("Role systemowe pg_* są %s.") % (tr("widoczne") if self.show_system else tr("ukryte")), "info")

    def set_status(self, msg, kind="info"):
        self.status = (msg, kind)

    # ------------------------------------------------------------- formularz
    def row_of(self, wd):
        for ri, row in enumerate(self.form_rows):
            if wd in row:
                return ri
        return 0

    def focus_widget(self, idx, cursor="end"):
        self.focus = "form"
        self.fidx = max(0, min(idx, len(self.widgets) - 1))
        wd = self.widgets[self.fidx]
        if cursor == "start":
            wd.cur = 0
        elif cursor == "end":
            wd.cur = len(wd.value)

    def focus_table(self):
        self.focus = "table"

    def form_key(self, key):
        wd = self.widgets[self.fidx]
        if key == "TAB":
            if self.fidx == len(self.widgets) - 1:
                self.focus_table()
            else:
                self.focus_widget(self.fidx + 1)
            return
        if key == "BTAB":
            if self.fidx == 0:
                self.focus_table()
            else:
                self.focus_widget(self.fidx - 1)
            return
        if key in ("UP", "DOWN"):
            ri = self.row_of(wd)
            nr = ri + (1 if key == "DOWN" else -1)
            if nr < 0:
                return
            if nr >= len(self.form_rows):
                self.focus_table()
                return
            cx = wd.fx + wd.fw // 2
            best = min(self.form_rows[nr], key=lambda w: abs(w.fx + w.fw // 2 - cx))
            self.focus_widget(self.widgets.index(best))
            return
        if wd.kind == "button":
            if key in ("ENTER", " "):
                self.start_run()
            elif key == "LEFT":
                self.focus_widget(self.fidx - 1, "end")
            elif key == "RIGHT":
                self.focus_table()
            elif key in ("q", "Q"):
                return "quit"
            elif key == "?":
                self.viewer(help_doc())
            return
        if wd.kind == "choice":
            if key in ("ENTER", " "):
                self.dropdown(wd)
            elif key == "LEFT":
                self.focus_widget(self.fidx - 1, "end")
            elif key == "RIGHT":
                self.focus_widget(self.fidx + 1, "start")
            elif key in ("q", "Q"):
                return "quit"
            return
        # pole tekstowe
        if key == "ENTER":
            self.start_run()
        elif key == "LEFT":
            if wd.cur > 0:
                wd.cur -= 1
            elif self.fidx > 0:
                self.focus_widget(self.fidx - 1, "end")
        elif key == "RIGHT":
            if wd.cur < len(wd.value):
                wd.cur += 1
            else:
                self.focus_widget(self.fidx + 1, "start")
        elif key == "HOME":
            wd.cur = 0
        elif key == "END":
            wd.cur = len(wd.value)
        elif key == "BS":
            if wd.cur > 0:
                wd.value = wd.value[:wd.cur - 1] + wd.value[wd.cur:]
                wd.cur -= 1
        elif key == "DEL":
            wd.value = wd.value[:wd.cur] + wd.value[wd.cur + 1:]
        elif key == "C-U":
            wd.value, wd.cur, wd.off = "", 0, 0
        elif key == "C-K":
            wd.value = wd.value[:wd.cur]
        elif printable(key):
            wd.value = wd.value[:wd.cur] + key + wd.value[wd.cur:]
            wd.cur += 1

    # ------------------------------------------------------------- tabela
    def fix_sel(self, t, rows, step):
        n = len(rows)
        j = t.sel
        while 0 <= j < n and not rows[j].selectable:
            j += step
        if not 0 <= j < n:
            j = t.sel
            while 0 <= j < n and not rows[j].selectable:
                j -= step
        if 0 <= j < n:
            t.sel = j

    def first_selectable(self, rows):
        for i, r in enumerate(rows):
            if r.selectable:
                return i
        return 0

    def move_sel(self, delta):
        t, rows = self.cur_tab(), self.rows_now()
        if not rows:
            return
        t.sel = max(0, min(len(rows) - 1, t.sel + delta))
        self.fix_sel(t, rows, 1 if delta > 0 else -1)

    def switch_tab(self, i):
        self.tab = i % len(self.tabs)

    def table_key(self, key):
        t, rows = self.cur_tab(), self.rows_now()
        if key == "UP":
            if not rows or t.sel <= self.first_selectable(rows):
                self.focus_widget(len(self.widgets) - 1)
            else:
                self.move_sel(-1)
        elif key == "DOWN":
            self.move_sel(1)
        elif key == "PGUP":
            self.move_sel(-(self.page - 1))
        elif key == "PGDN":
            self.move_sel(self.page - 1)
        elif key == "HOME":
            t.sel = 0
            self.fix_sel(t, rows, 1)
        elif key == "END":
            t.sel = max(0, len(rows) - 1)
            self.fix_sel(t, rows, -1)
        elif key == "LEFT":
            self.switch_tab(self.tab - 1)
        elif key == "RIGHT":
            self.switch_tab(self.tab + 1)
        elif key in ("1", "2", "3", "4", "5"):
            self.switch_tab(int(key) - 1)
        elif key == "ENTER":
            self.open_detail()
        elif key in ("TAB", "BTAB"):
            self.focus_widget(0 if key == "TAB" else len(self.widgets) - 1)
        elif key == "/":
            self.filter_prompt()
        elif key in ("s", "S"):
            self.toggle_system()
        elif key in ("t", "T"):
            self.theme_dialog()
        elif key in ("l", "L"):
            self.lang_dialog()
        elif key in ("q", "Q"):
            return "quit"
        elif key == "?":
            self.viewer(help_doc())
        elif key == "ESC" and t.filter:
            t.filter = ""
            self.set_status(tr("Filtr wyczyszczony."), "info")

    # ------------------------------------------------------------- mysz
    def on_mouse(self):
        try:
            _id, mx, my, _z, b = curses.getmouse()
        except curses.error:
            return
        if b & BUTTON4:
            self.move_sel(-3)
            return
        if b & BUTTON5:
            self.move_sel(3)
            return
        if not b & CLICK:
            return
        for (y, x1, x2, act) in reversed(self.hits):
            if y == my and x1 <= mx < x2:
                return self.do_hit(act, mx, b)

    def do_hit(self, act, mx, b):
        kind, val = act
        if kind == "widget":
            wd = self.widgets[val]
            self.focus_widget(val, None)
            if wd.kind == "button":
                self.start_run()
            elif wd.kind == "choice":
                self.dropdown(wd)
            elif mx >= wd.fx:
                text = wd.value if wd.kind != "password" else "*" * len(wd.value)
                pos, acc = wd.off, 0
                while pos < len(text) and acc + chw(U(text[pos])[:1] or " ") <= mx - wd.fx:
                    acc += chw(U(text[pos])[:1] or " ")
                    pos += 1
                wd.cur = pos
            else:
                wd.cur = len(wd.value)
        elif kind == "tab":
            self.switch_tab(val)
        elif kind == "row":
            t, rows = self.cur_tab(), self.rows_now()
            now = time.time()
            same = self.last_click[1] == val and now - self.last_click[0] < 0.45
            self.focus_table()
            if 0 <= val < len(rows) and rows[val].selectable:
                t.sel = val
                if same or b & DOUBLE:
                    self.last_click = (0.0, -1)
                    self.open_detail()
                    return
            self.last_click = (now, val)
        elif kind == "fkey":
            return self.fkey(val)

    # ------------------------------------------------------------- uruchamianie
    def start_run(self):
        if self.running:
            self.set_status(tr("Diagnostyka już trwa…"), "warn")
            return
        vals = dict((f.key, f.value if f.kind == "password" else f.value.strip()) for f in self.fields)
        if vals["port"] and not vals["port"].isdigit():
            self.set_status(tr("Port musi być liczbą."), "err")
            self.focus_widget(1)
            return
        psql = find_psql(self.opts.psql)
        if not psql:
            d = Doc(tr("Nie znaleziono programu psql"))
            d.p(tr("PgDiag korzysta z klienta psql. Zainstaluj go (np. apt install postgresql-client, "
                "dnf install postgresql) albo wskaż ścieżkę opcją --psql /ścieżka/do/psql."))
            self.pending_error = d
            return
        params = dict((k, vals[k]) for k in ("host", "port", "dbname", "user", "password", "sslmode"))
        if vals.get("os_user") and vals["os_user"] != "root":
            params["os_user"] = vals["os_user"]
        self.running = True
        self.t_start = time.time()
        th = threading.Thread(target=self.worker, args=(params, psql, vals["hba"]))
        th.daemon = True
        th.start()

    def worker(self, params, psql, hba):
        try:
            rep = collect(params, psql, hba, skip_net=self.opts.no_net)
            model = Model(rep)
            tabs = build_tabs(model)
            self.q.put(("ok", (rep, model, tabs)))
        except PgError as e:
            if getattr(e, "net", None):
                try:
                    e.offline = offline_report(params, e.net)
                except Exception:
                    e.offline = None
            self.q.put(("err", e))
        except Exception:
            self.q.put(("crash", traceback.format_exc()))

    def poll(self):
        try:
            kind, val = self.q.get_nowait()
        except queue.Empty:
            return
        self.running = False
        if kind == "ok":
            rep, model, tabs = val
            for old, new in zip(self.tabs, tabs):
                new.filter = old.filter
                new.sel, new.top = old.sel, old.top
            self.report, self.model, self.tabs = rep, model, tabs
            ncrit, nwarn = getattr(tabs[0], "stats", (0, 0))
            p = model.p
            self.last_info = "%s@%s" % (p.get("cur_user"), p.get("server_addr") or (rep["params"].get("host") or tr("lokalnie")))
            def cnt(n, one, few, many):
                return "?" if n is None else "%d %s" % (n, plural(n, one, few, many))
            msg = tr("Gotowe: %s, %s pg_hba, %s.") % (cnt(tabs[1].count, tr("baza"), tr("bazy"), tr("baz")),
                                                  cnt(tabs[2].count, tr("reguła"), tr("reguły"), tr("reguł")),
                                                  cnt(tabs[3].count, tr("rola"), tr("role"), tr("ról")))
            if ncrit or nwarn:
                msg += tr(" Problemy: %s, %s (zakładka Serwer).") % (
                    cnt(ncrit, tr("krytyczny"), tr("krytyczne"), tr("krytycznych")),
                    cnt(nwarn, tr("ostrzeżenie"), tr("ostrzeżenia"), tr("ostrzeżeń")))
                self.set_status(msg, "warn")
            else:
                self.set_status(msg + tr(" Nie znaleziono problemów."), "ok")
            self.focus_table()
        elif kind == "err":
            e = val
            self.set_status(tr("Błąd: ") + e.message, "err")
            off = getattr(e, "offline", None)
            if off:
                self.report, self.model, self.tabs = off
                self.tab = 4
                self.last_info = ""
                self.set_status(tr("Brak połączenia z bazą – wyniki sieci i firewalla w zakładce 5. ") + e.message, "err")
            d = Doc(tr("Nie udało się połączyć") if e.kind == "connect" else tr("Błąd"))
            d.h(tr("Komunikat"))
            d.p(e.message)
            if e.hint:
                d.h(tr("Co zrobić"))
                d.p(e.hint)
            if off:
                d.p(tr("Sprawdzenie sieci i firewalla zostało wykonane – wyniki są w zakładce 5 „Sieć i firewall”."), "bold")
            d.h(tr("Użyte parametry"))
            osu = [f.value for f in self.fields if f.key == "os_user"]
            for f in self.fields:
                if f.kind != "password":
                    ph = "(%s)" % osu[0] if (f.key == "user" and osu) else tr(f.placeholder)
                    d.kv(tr(f.label), f.value or ph or "", keyw=16)
            d.kv(tr("Hasło"), tr("podane") if self.fields[4].value else tr("nie podano (psql użyje ~/.pgpass lub PGPASSWORD)"), keyw=16)
            self.pending_error = d
        else:
            self.set_status(tr("Wewnętrzny błąd programu – szczegóły w oknie."), "err")
            d = Doc(tr("Wewnętrzny błąd programu"))
            d.p(tr("Wystąpił nieoczekiwany błąd. Nic nie zostało zmienione na serwerze."))
            for ln in str(val).splitlines():
                d.p(ln)
            self.pending_error = d

    # ------------------------------------------------------------- okna
    def open_detail(self):
        if self.report is None:
            return
        t = self.cur_tab()
        rows = self.rows_now()
        if not rows:
            return
        i = t.sel
        while True:
            if not (0 <= i < len(rows)) or rows[i].detail is None:
                return
            res = self.viewer(rows[i].detail(), nav=True)
            if res in ("prev", "next"):
                step = -1 if res == "prev" else 1
                j = i + step
                while 0 <= j < len(rows) and (not rows[j].selectable or rows[j].detail is None):
                    j += step
                if 0 <= j < len(rows):
                    i = t.sel = j
                continue
            return

    def viewer(self, doc, style="p", nav=False):
        pos = 0
        while True:
            self.poll()
            self.draw(refresh=False)
            H, W = self.H, self.W
            pw = max(20, min(W - 4, 116))
            lines = doc.render(pw - 4)
            ph = max(5, min(H - 3, len(lines) + 2))
            py, px = max(1, (H - 1 - ph) // 2), (W - pw) // 2
            body = ph - 2
            maxpos = max(0, len(lines) - body)
            pos = max(0, min(pos, maxpos))
            for yy in range(py, py + ph):
                self.put(yy, px, " " * pw, style + "_text")
            self.box(py, px, ph, pw, style + "_frame")
            title = " %s " % doc.title
            if sw(U(title)) > pw - 4:
                title = fit(title, pw - 4)
            self.put(py, px + max(2, (pw - sw(U(title))) // 2), title, style + "_title")
            for i in range(body):
                li = pos + i
                if li >= len(lines):
                    break
                x = px + 2
                for text, role in lines[li]:
                    name = style + "_" + role
                    if name not in self.theme.attr:
                        name = style + "_text"
                    self.put(py + 1 + i, x, text, name, px + pw - 2 - x)
                    x += sw(U(text))
            hint = tr(" ↑↓ PgUp PgDn przewijanie%s  Esc zamknij ") % (tr("  ←→ poprzedni/następny") if nav else "")
            self.put(py + ph - 1, px + 2, fit(hint, max(0, pw - 14)).rstrip() + " ", style + "_frame")
            if maxpos:
                pct = " %d%% " % (100 * pos // maxpos)
                self.put(py + ph - 1, px + pw - 2 - sw(pct), pct, style + "_frame")
            self.set_cursor(False)
            self.scr.noutrefresh()
            curses.doupdate()
            key = self.getkey()
            if key is None or key == "RESIZE":
                continue
            if key == "UP":
                pos -= 1
            elif key == "DOWN":
                pos += 1
            elif key == "PGUP":
                pos -= body - 1
            elif key in ("PGDN", " "):
                pos += body - 1
            elif key == "HOME":
                pos = 0
            elif key == "END":
                pos = maxpos
            elif key == "LEFT" and nav:
                return "prev"
            elif key == "RIGHT" and nav:
                return "next"
            elif key in ("ESC", "ENTER", "q", "Q", "F3", "F10", "F1", "F7", "C-C"):
                return "close"
            elif key == "MOUSE":
                try:
                    _id, mx, my, _z, b = curses.getmouse()
                except curses.error:
                    continue
                if b & BUTTON4:
                    pos -= 3
                elif b & BUTTON5:
                    pos += 3
                elif b & CLICK and not (py <= my < py + ph and px <= mx < px + pw):
                    return "close"

    def apply_lang(self, code):
        """Zmienia jezyk i przebudowuje wszystkie teksty (analiza jest liczona od nowa z zebranych danych)."""
        set_lang(code)
        self.layout()
        old = self.tabs
        if self.report is not None:
            try:
                if self.report.get("offline"):
                    _r, model, tabs = offline_report(self.report["params"], self.report.get("net"))
                else:
                    model = Model(self.report)
                    tabs = build_tabs(model)
                self.model, self.tabs = model, tabs
            except Exception:
                self.tabs = empty_tabs()
        else:
            self.tabs = empty_tabs()
        for o, nw in zip(old, self.tabs):
            nw.sel, nw.top, nw.filter = o.sel, o.top, o.filter
        if self.report is not None and not self.report.get("offline") and self.model is not None:
            p = self.model.p
            self.last_info = "%s@%s" % (p.get("cur_user"), p.get("server_addr") or (
                self.report["params"].get("host") or tr("lokalnie")))
        self.scr.clear()

    def lang_dialog(self):
        """Wybor jezyka z podgladem na zywo; Enter zapisuje, Esc przywraca poprzedni."""
        orig = LANG
        codes = [c for c, _n in LANGS]
        idx = codes.index(orig) if orig in codes else 0
        shown = orig
        while True:
            if codes[idx] != shown:
                shown = codes[idx]
                self.apply_lang(shown)
            self.draw(refresh=False)
            H, W = self.H, self.W
            w = min(W - 4, 60)
            h = len(LANGS) + 6
            y, x = max(1, (H - h) // 2), (W - w) // 2
            for yy in range(y, y + h):
                self.put(yy, x, " " * w, "p_text")
            self.box(y, x, h, w, "p_frame")
            title = tr(" Język / Language ")
            self.put(y, x + (w - sw(U(title))) // 2, title, "p_title")
            for i, (code, name) in enumerate(LANGS):
                mark = ("(•)" if UNICODE else "(*)") if i == idx else "( )"
                self.put(y + 2 + i, x + 1, fit(" %s %-10s [%s]" % (mark, name, code), w - 2),
                         "p_sel" if i == idx else "p_text")
            path = config_path().replace(os.path.expanduser("~"), "~", 1)
            self.put(y + h - 3, x + 2, fit(tr("Enter – zapisz w %s") % path, w - 4), "p_dim")
            self.put(y + h - 2, x + 2, fit(tr("↑↓ – podgląd na żywo, Esc – anuluj"), w - 4), "p_dim")
            self.set_cursor(False)
            self.scr.noutrefresh()
            curses.doupdate()
            key = self.getkey()
            if key in ("UP", "LEFT"):
                idx = (idx - 1) % len(LANGS)
            elif key in ("DOWN", "RIGHT"):
                idx = (idx + 1) % len(LANGS)
            elif key in ("ENTER", " "):
                break
            elif key in ("ESC", "F8", "F10", "q", "Q"):
                if shown != orig:
                    self.apply_lang(orig)
                self.set_status(tr("Język bez zmian."), "info")
                return
            elif key == "MOUSE":
                try:
                    _id, mx, my, _z, b = curses.getmouse()
                except curses.error:
                    continue
                if b & CLICK:
                    if y + 2 <= my < y + 2 + len(LANGS) and x <= mx < x + w:
                        if my - y - 2 == idx:
                            break
                        idx = my - y - 2
                    elif not (y <= my < y + h and x <= mx < x + w):
                        if shown != orig:
                            self.apply_lang(orig)
                        return
        code = codes[idx]
        if code != LANG:
            self.apply_lang(code)
        try:
            path = save_config(lang=code)
            self.set_status(tr("Język „%s” zapamiętany w %s.") % (
                dict(LANGS)[code], path.replace(os.path.expanduser("~"), "~", 1)), "ok")
        except OSError as e:
            self.set_status(tr("Język „%s” włączony, ale nie udało się go zapisać: %s") % (
                dict(LANGS)[code], e.strerror or e), "warn")

    def apply_theme(self, name):
        self.theme.setup(name)
        self.scr.bkgd(" ", self.A("normal"))
        self.scr.clear()

    def theme_dialog(self):
        """Wybor motywu z podgladem na zywo; Enter zapisuje, Esc przywraca poprzedni."""
        orig = self.theme.name
        idx = THEME_NAMES.index(orig) if orig in THEME_NAMES else 0
        shown = orig
        while True:
            if THEME_NAMES[idx] != shown:
                shown = THEME_NAMES[idx]
                self.apply_theme(shown)
            self.draw(refresh=False)
            H, W = self.H, self.W
            w = min(W - 4, 84)
            h = len(THEMES) + 7
            y, x = max(1, (H - h) // 2), (W - w) // 2
            for yy in range(y, y + h):
                self.put(yy, x, " " * w, "p_text")
            self.box(y, x, h, w, "p_frame")
            title = tr(" Motyw interfejsu ")
            self.put(y, x + (w - sw(title)) // 2, title, "p_title")
            for i, (key, label, desc, _) in enumerate(THEMES):
                label, desc = tr(label), tr(desc)
                mark = "(•)" if i == idx else "( )"
                line = " %s %-18s %s" % (mark if UNICODE else ("(*)" if i == idx else "( )"), label, desc)
                self.put(y + 2 + i, x + 1, fit(line, w - 2), "p_sel" if i == idx else "p_text")
            path = config_path().replace(os.path.expanduser("~"), "~", 1)
            if curses.has_colors() and curses.COLORS >= 256:
                ctxt = tr("Terminal: %d kolorów (TERM=%s) – ciemny granat niezależny od palety terminala") % (
                    curses.COLORS, os.environ.get("TERM", "?"))
            else:
                ctxt = tr("Terminal: %d kolorów (TERM=%s) – odcienie zależą od palety terminala; "
                          "uruchom z --colors 256 lub TERM=xterm-256color") % (
                    curses.COLORS if curses.has_colors() else 2, os.environ.get("TERM", "?"))
            self.put(y + h - 4, x + 2, fit(ctxt, w - 4), "p_dim")
            self.put(y + h - 3, x + 2, fit(tr("Enter – zapisz w %s") % path, w - 4), "p_dim")
            self.put(y + h - 2, x + 2, fit(tr("↑↓ – podgląd na żywo, Esc – anuluj"), w - 4), "p_dim")
            self.set_cursor(False)
            self.scr.noutrefresh()
            curses.doupdate()
            key = self.getkey()
            if key == "UP":
                idx = (idx - 1) % len(THEMES)
            elif key == "DOWN":
                idx = (idx + 1) % len(THEMES)
            elif key == "HOME":
                idx = 0
            elif key == "END":
                idx = len(THEMES) - 1
            elif isinstance(key, str) and key.isdigit() and 1 <= int(key) <= len(THEMES):
                idx = int(key) - 1
            elif key in ("ENTER", " "):
                break
            elif key in ("ESC", "F9", "F10", "q", "Q"):
                if shown != orig:
                    self.apply_theme(orig)
                self.set_status(tr("Motyw bez zmian."), "info")
                return
            elif key == "MOUSE":
                try:
                    _id, mx, my, _z, b = curses.getmouse()
                except curses.error:
                    continue
                if b & BUTTON4:
                    idx = max(0, idx - 1)
                elif b & BUTTON5:
                    idx = min(len(THEMES) - 1, idx + 1)
                elif b & CLICK:
                    if y + 2 <= my < y + 2 + len(THEMES) and x <= mx < x + w:
                        if my - y - 2 == idx:
                            break
                        idx = my - y - 2
                    elif not (y <= my < y + h and x <= mx < x + w):
                        if shown != orig:
                            self.apply_theme(orig)
                        return
        name = THEME_NAMES[idx]
        if name != self.theme.name:
            self.apply_theme(name)
        try:
            path = save_config(theme=name)
            self.set_status(tr("Motyw „%s” zapamiętany w %s.") % (
                tr(THEMES[idx][1]), path.replace(os.path.expanduser("~"), "~", 1)), "ok")
        except OSError as e:
            self.set_status(tr("Motyw „%s” włączony, ale nie udało się go zapisać: %s") % (tr(THEMES[idx][1]), e.strerror or e),
                            "warn")

    def dropdown(self, f):
        opts = f.choices
        idx = opts.index(f.value) if f.value in opts else 0
        while True:
            self.draw(refresh=False)
            w = max(sw(o) for o in opts) + 4
            h = len(opts) + 2
            y, x = f.y + 1, f.fx
            if y + h > self.H - 1:
                y = max(0, f.y - h)
            if x + w > self.W:
                x = self.W - w
            for yy in range(y, y + h):
                self.put(yy, x, " " * w, "p_text")
            self.box(y, x, h, w, "p_frame")
            for i, o in enumerate(opts):
                self.put(y + 1 + i, x + 1, fit(" " + o, w - 2), "p_sel" if i == idx else "p_text")
            self.set_cursor(False)
            self.scr.noutrefresh()
            curses.doupdate()
            key = self.getkey()
            if key == "UP":
                idx = (idx - 1) % len(opts)
            elif key == "DOWN":
                idx = (idx + 1) % len(opts)
            elif key == "HOME":
                idx = 0
            elif key == "END":
                idx = len(opts) - 1
            elif key in ("ENTER", " "):
                f.value = opts[idx]
                return
            elif key in ("ESC", "TAB", "F10", "q"):
                return
            elif key == "MOUSE":
                try:
                    _id, mx, my, _z, b = curses.getmouse()
                except curses.error:
                    continue
                if b & BUTTON4:
                    idx = max(0, idx - 1)
                elif b & BUTTON5:
                    idx = min(len(opts) - 1, idx + 1)
                elif b & CLICK:
                    if y < my < y + h - 1 and x <= mx < x + w:
                        f.value = opts[my - y - 1]
                    return

    def filter_prompt(self):
        if self.report is None:
            self.set_status(tr("Najpierw uruchom diagnostykę (F2)."), "warn")
            return
        t = self.cur_tab()
        text = t.filter
        cur = len(text)
        self.focus_table()
        while True:
            t.filter = text
            self.draw(refresh=False)
            y, W = self.status_y, self.W
            lab = tr(" Filtr (%s): ") % t.title
            self.put(y, 0, " " * W, "status")
            self.put(y, 0, lab, "status_warn")
            fx = sw(U(lab))
            fw = max(10, W - fx - 36)
            vis, n = clip(U(text), fw)
            self.put(y, fx, vis + " " * (fw - n), "field_f")
            self.put(y, fx + fw + 1, tr("Enter – zatwierdź, Esc – wyczyść"), "dim")
            self.set_cursor(True)
            try:
                self.scr.move(y, fx + min(fw - 1, sw(U(text[:cur]))))
            except curses.error:
                pass
            self.scr.noutrefresh()
            curses.doupdate()
            key = self.getkey()
            if key in ("ENTER", "TAB", "F4"):
                t.filter = text
                nr = len(self.rows_now())
                self.set_status((tr("Filtr: „%s” – %d %s.") % (text, nr, plural(nr, tr("wiersz"), tr("wiersze"), tr("wierszy"))))
                                if text else tr("Filtr wyłączony."), "info")
                return
            if key in ("ESC", "F10"):
                t.filter = ""
                self.set_status(tr("Filtr wyczyszczony."), "info")
                return
            if key == "BS":
                if cur > 0:
                    text = text[:cur - 1] + text[cur:]
                    cur -= 1
            elif key == "DEL":
                text = text[:cur] + text[cur + 1:]
            elif key == "LEFT":
                cur = max(0, cur - 1)
            elif key == "RIGHT":
                cur = min(len(text), cur + 1)
            elif key == "HOME":
                cur = 0
            elif key == "END":
                cur = len(text)
            elif key == "C-U":
                text, cur = "", 0
            elif key in ("UP", "DOWN", "PGUP", "PGDN"):
                self.table_key(key)
            elif printable(key):
                text = text[:cur] + key + text[cur:]
                cur += 1
                t.sel = t.top = 0


# =============================================================================
#  Raport tekstowy (--report)
# =============================================================================

def print_report(model, out):
    print_tabs(build_tabs(model), out)


def print_tabs(tabs, out):
    for t in tabs:
        out.write("\n" + "=" * 100 + "\n " + U(t.title.upper()) + "\n" + "=" * 100 + "\n")
        for segs in t.info:
            out.write("  " + U("".join(s for s, _ in segs)).strip() + "\n")
        if t.error:
            out.write(tr("  BRAK DANYCH: %s\n") % U(t.error[0]))
            if t.error[1]:
                out.write("  %s\n" % U(t.error[1]))
            continue
        rows = t.visible(True)
        widths = []
        for c in t.columns:
            w = sw(U(c.title))
            for r in rows:
                if r.selectable:
                    w = max(w, sw(U(r.cells.get(c.key, ""))))
            widths.append(min(w, max(c.maxw, 12)))
        out.write("\n" + " | ".join(fit(c.title, widths[i], c.align) for i, c in enumerate(t.columns)).rstrip() + "\n")
        out.write("-+-".join("-" * w for w in widths) + "\n")
        for r in rows:
            if r.style == "section":
                out.write("\n[ %s ]\n" % U(r.cells.get(t.columns[0].key, "")))
                continue
            out.write(" | ".join(fit(r.cells.get(c.key, ""), widths[i], c.align)
                                 for i, c in enumerate(t.columns)).rstrip() + "\n")
    out.write("\n" + U("PgDiag %s · %s · %s" % (VERSION, COPYRIGHT, tr("licencja MIT"))) + "\n")


# =============================================================================
#  Tlumaczenia: tekst polski (w kodzie) -> angielski. Jezyk domyslny: EN.
# =============================================================================

TR_EN = {
    # --- ogolne
    'brak': 'none',
    'inne': 'other',
    'OK': 'OK',
    'info': 'info',
    'UWAGA': 'WARNING',
    'KRYTYCZNE': 'CRITICAL',
    'tak': 'yes',
    'nie': 'no',
    'rok': 'year',
    'lata': 'years',
    'lat': 'years',
    '%d mies.': '%d mo.',
    'dzień': 'day',
    'dni': 'days',
    # --- podpowiedzi przy bledach polaczenia
    'Metoda peer wymaga, aby konto systemowe miało tę samą nazwę co rola. W polu „psql jako” wybierz postgres (albo konto o nazwie roli) lub wpisz Host 127.0.0.1 i hasło.':
        'Peer authentication requires the OS account to have the same name as the role. In the "psql as" field choose postgres (or the account named like the role), or enter Host 127.0.0.1 and a password.',
    'Połączenie przez gniazdo lokalne metodą peer wymaga, aby nazwa użytkownika systemu była taka sama jak nazwa roli. Uruchom program jako ten użytkownik, np. „sudo -u postgres python3 %s”, albo wpisz Host 127.0.0.1 i hasło.':
        'Peer authentication over the local socket requires the OS user name to match the role name. Run the program as that user, e.g. "sudo -u postgres python3 %s", or enter Host 127.0.0.1 and a password.',
    'Serwer wymaga hasła. Wpisz je w polu Hasło albo dodaj wpis do pliku ~/.pgpass.':
        'The server requires a password. Enter it in the Password field or add an entry to ~/.pgpass.',
    'Nieprawidłowe hasło lub nazwa użytkownika.': 'Wrong password or user name.',
    'Serwer nie ma reguły pg_hba.conf dopuszczającej takie połączenie (adres, rola, baza, SSL). Spróbuj połączenia lokalnego (puste pole Host) jako postgres albo zmień tryb SSL.':
        'The server has no pg_hba.conf rule allowing this connection (address, role, database, SSL). Try a local connection (empty Host field) as postgres or change the SSL mode.',
    'Serwer nie działa albo nie nasłuchuje pod tym adresem/portem. Sprawdź Host, Port oraz parametr listen_addresses.':
        'The server is not running or is not listening on this address/port. Check Host, Port and the listen_addresses setting.',
    'Serwer nie odpowiada – sprawdź adres i zaporę sieciową.': 'The server does not respond – check the address and the firewall.',
    'Nieznana nazwa hosta – sprawdź pole Host.': 'Unknown host name – check the Host field.',
    'Podana baza nie istnieje. Wpisz w polu Baza np. postgres albo template1.':
        'This database does not exist. Enter e.g. postgres or template1 in the Database field.',
    'Na serwerze nie ma roli root. W polu „psql jako” wybierz postgres albo wpisz właściwą rolę w polu Użytkownik.':
        'There is no role "root" on the server. Choose postgres in the "psql as" field or enter the right role in the User field.',
    'Program działa jako root, a na serwerze nie ma roli root. Wpisz właściwą rolę w polu Użytkownik albo uruchom program jako postgres: „sudo -u postgres python3 %s”.':
        'The program runs as root and the server has no role "root". Enter the right role in the User field or run the program as postgres: "sudo -u postgres python3 %s".',
    'Taka rola nie istnieje na serwerze. Popraw pole Użytkownik.': 'This role does not exist on the server. Correct the User field.',
    'Serwer nie obsługuje SSL – zmień tryb SSL na prefer albo disable.': 'The server does not support SSL – change the SSL mode to prefer or disable.',
    'Problem z certyfikatem SSL. Użyj trybu require/prefer albo skonfiguruj certyfikat CA (~/.postgresql/root.crt lub PGSSLROOTCERT).':
        'SSL certificate problem. Use the require/prefer mode or configure a CA certificate (~/.postgresql/root.crt or PGSSLROOTCERT).',
    'Nie ma konta systemowego „%s”.': 'There is no OS account "%s".',
    'Nie można uruchomić psql (%s): %s': 'Cannot run psql (%s): %s',
    'Brak odpowiedzi serwera w ciągu %d s.': 'No response from the server within %d s.',
    'psql zakończył się kodem %d': 'psql exited with code %d',
    'Nieoczekiwana odpowiedź psql: %s': 'Unexpected psql output: %s',
    # --- parser pg_hba.conf
    'niezamknięty cudzysłów': 'unterminated quote',
    'nieprawidłowy typ połączenia "%s"': 'invalid connection type "%s"',
    'brak nazwy bazy': 'missing database name',
    'brak nazwy roli': 'missing role name',
    'brak adresu IP': 'missing IP address',
    'lista adresów jest niedozwolona': 'a list of addresses is not allowed',
    'nieprawidłowy adres IP "%s"': 'invalid IP address "%s"',
    'po adresie IP brakuje maski': 'netmask missing after the IP address',
    'nieprawidłowa maska "%s"': 'invalid netmask "%s"',
    'brak metody uwierzytelniania': 'missing authentication method',
    'nieprawidłowa metoda uwierzytelniania "%s"': 'invalid authentication method "%s"',
    'Zbyt głębokie zagnieżdżenie dyrektyw include': 'include directives nested too deeply',
    'Brak uprawnień do odczytu pliku %s (uruchom jako postgres lub przez sudo).':
        'No permission to read %s (run as postgres or via sudo).',
    'Nie można odczytać pliku %s: %s': 'Cannot read %s: %s',
    'dyrektywa %s bez nazwy pliku': '%s directive without a file name',
    'Brak uprawnień do widoku pg_hba_file_rules (wymaga superużytkownika lub nadania uprawnień). ':
        'No permission to read the pg_hba_file_rules view (requires a superuser or an explicit grant). ',
    'Serwer jest zdalny – połącz się jako superużytkownik albo wpisz w polu pg_hba.conf ścieżkę lokalnej kopii pliku.':
        'The server is remote – connect as a superuser or enter the path of a local copy of the file in the pg_hba.conf field.',
    'Nie można też odczytać pliku %s – uruchom program jako postgres (sudo -u postgres) lub root.':
        'The file %s cannot be read either – run the program as postgres (sudo -u postgres) or root.',
    'plik wykryty automatycznie – upewnij się, że należy do tego klastra': 'file detected automatically – make sure it belongs to this cluster',
    'Znaleziono kilka plików: %s – wpisz właściwy w polu pg_hba.conf.': 'Several files found: %s – enter the right one in the pg_hba.conf field.',
    'Pliki %s istnieją, ale bieżący użytkownik nie może ich czytać – uruchom program jako postgres lub root.':
        'The files %s exist but the current user cannot read them – run the program as postgres or root.',
    'Wpisz ścieżkę pliku w polu pg_hba.conf albo połącz się jako postgres.': 'Enter the file path in the pg_hba.conf field or connect as postgres.',
    'przekroczony czas oczekiwania': 'timed out',
    'Serwer nie zwrócił danych.': 'The server returned no data.',
    # --- opisy typow, metod, adresow
    'gniazdo Unix (połączenie z tego samego komputera)': 'Unix socket (connection from the same machine)',
    'TCP/IP – z SSL lub bez': 'TCP/IP – with or without SSL',
    'TCP/IP – tylko połączenia szyfrowane SSL': 'TCP/IP – SSL-encrypted connections only',
    'TCP/IP – tylko połączenia BEZ SSL': 'TCP/IP – non-SSL connections only',
    'TCP/IP – tylko z szyfrowaniem GSSAPI': 'TCP/IP – GSSAPI-encrypted only',
    'TCP/IP – tylko bez szyfrowania GSSAPI': 'TCP/IP – without GSSAPI encryption only',
    'brak uwierzytelniania – każdy pasujący do reguły loguje się bez hasła': 'no authentication – anyone matching the rule logs in without a password',
    'połączenie jest odrzucane': 'the connection is rejected',
    'hasło weryfikowane metodą SCRAM-SHA-256 (zalecane)': 'password verified with SCRAM-SHA-256 (recommended)',
    'hasło MD5 (dla haseł zapisanych jako SCRAM użyje SCRAM) – przestarzałe': 'MD5 password (uses SCRAM for passwords stored as SCRAM) – deprecated',
    'hasło przesyłane jawnym tekstem': 'password sent in clear text',
    'nazwa użytkownika systemu operacyjnego musi odpowiadać roli (tylko lokalnie)': 'the OS user name must match the role (local only)',
    'nazwa użytkownika podana przez serwer ident komputera klienta': "user name reported by the client machine's ident server",
    'Kerberos / GSSAPI': 'Kerberos / GSSAPI',
    'Windows SSPI': 'Windows SSPI',
    'hasło sprawdzane w serwerze LDAP': 'password checked against an LDAP server',
    'hasło sprawdzane w serwerze RADIUS': 'password checked against a RADIUS server',
    'certyfikat klienta SSL': 'SSL client certificate',
    'PAM (moduły uwierzytelniania systemu)': 'PAM (system authentication modules)',
    'BSD Authentication': 'BSD Authentication',
    'OAuth': 'OAuth',
    'linia %s': 'line %s',
    '(lokalnie)': '(local)',
    'połączenia lokalne przez gniazdo Unix': 'local connections through the Unix socket',
    'dowolny adres IP (IPv4 i IPv6) – cały świat': 'any IP address (IPv4 and IPv6) – the whole world',
    'dowolny z adresów IP tego serwera': "any of this server's IP addresses",
    'dowolny adres z podsieci, do których bezpośrednio podłączony jest serwer': 'any address in the subnets the server is directly connected to',
    'dowolny host z domeny %s (sprawdzane przez DNS)': 'any host in the %s domain (checked via DNS)',
    'host o nazwie %s (sprawdzane przez DNS)': 'host named %s (checked via DNS)',
    'dowolny adres %s – cały świat': 'any %s address – the whole world',
    'tylko ten komputer (loopback)': 'this machine only (loopback)',
    'sieć prywatna': 'private network',
    'adresy publiczne': 'public addresses',
    'pojedynczy host %s (%s)': 'single host %s (%s)',
    '2^%d adresów': '2^%d addresses',
    'adres': 'address',
    'adresy': 'addresses',
    'adresów': 'addresses',
    'wszystkie role': 'all roles',
    'członkowie roli %s (także pośrednio)': 'members of role %s (also indirect)',
    'role pasujące do wyrażenia %s': 'roles matching the expression %s',
    'role wymienione w pliku %s': 'roles listed in file %s',
    'rola %s': 'role %s',
    'wszystkie bazy (bez połączeń replikacyjnych)': 'all databases (not replication connections)',
    'baza o nazwie takiej jak rola': 'database named like the role',
    'baza, której nazwa to rola, do której należy użytkownik': 'database named after a role the user belongs to',
    'połączenia replikacyjne (fizyczne)': 'replication connections (physical)',
    'bazy pasujące do wyrażenia %s': 'databases matching the expression %s',
    'bazy wymienione w pliku %s': 'databases listed in file %s',
    'baza %s': 'database %s',
    # --- firewall: werdykty i warunki
    'dozwolone': 'allowed',
    'zablokowane (DROP)': 'blocked (DROP)',
    'odrzucane (REJECT)': 'rejected (REJECT)',
    'dopuszcza': 'allows',
    'blokuje (DROP)': 'blocks (DROP)',
    'odrzuca (REJECT)': 'rejects (REJECT)',
    'przechodzi do': 'jumps to',
    'wraca': 'returns',
    'mapa werdyktów': 'verdict map',
    'reguła: %s': 'rule: %s',
    'polityka domyślna łańcucha %s (%s)': 'default policy of chain %s (%s)',
    'tylko interfejs %s': 'interface %s only',
    'oprócz interfejsu %s': 'except interface %s',
    'tylko część adresów (%s%s)': 'only some addresses (%s%s)',
    'poza ': 'except ',
    'łańcuch %s nieznany': 'chain %s unknown',
    'nieznany zbiór': 'unknown set',
    'port docelowy': 'destination port',
    'adres źródłowy': 'source address',
    'adres docelowy': 'destination address',
    'warunek %s': 'condition %s',
    'cel iptables %s': 'iptables target %s',
    'dopasowanie iptables %s': 'iptables match %s',
    '(reguła #%s)': '(rule #%s)',
    'moduł %s': 'module %s',
    'cel %s': 'target %s',
    'ruch przychodzący': 'incoming traffic',
    'adres docelowy %s': 'destination address %s',
    'port/aplikacja %s': 'port/application %s',
    'źródło %s': 'source %s',
    'port źródłowy %s': 'source port %s',
    'LIMIT (ograniczenie liczby połączeń)': 'LIMIT (connection rate limit)',
    'strefa %s': 'zone %s',
    'port źródłowy': 'source port',
    'usługa %s': 'service %s',
    'usługa %s (%s)': 'service %s (%s)',
    'firewalld (strefa %s – źródło)': 'firewalld (zone %s – source)',
    'źródła strefy %s': 'sources of zone %s',
    'część adresów należy do strefy %s': 'some addresses belong to zone %s',
    'firewalld (strefa %s)': 'firewalld (zone %s)',
    'strefy %s': 'zones %s',
    'wynik zależy od interfejsu sieciowego': 'the result depends on the network interface',
    'Analiza sieci nie powiodła się: %s: %s': 'Network analysis failed: %s: %s',
    # --- ocena regul pg_hba i rol
    'błąd w pliku: %s': 'error in file: %s',
    'jako dowolna rola': 'as any role',
    'jako ': 'as ',
    'trust lokalnie: każdy użytkownik systemu zaloguje się %s bez hasła': 'local trust: every OS user can log in %s without a password',
    'trust z localhost: każdy proces na serwerze loguje się bez hasła': 'trust from localhost: every process on the server logs in without a password',
    'trust z sieci: logowanie BEZ HASŁA z adresów %s': 'trust from the network: login WITHOUT A PASSWORD from %s',
    'hasło przesyłane przez sieć jawnym tekstem (SSL nie jest wymagany)': 'password sent over the network in clear text (SSL not required)',
    'metoda password wysyła hasło jawnym tekstem – lepiej scram-sha-256': 'the password method sends the password in clear text – prefer scram-sha-256',
    'md5 jest przestarzałe – zalecane scram-sha-256': 'md5 is deprecated – scram-sha-256 recommended',
    'ident przez TCP opiera się na deklaracji komputera klienta': "ident over TCP trusts the client machine's own claim",
    'wszystkie bazy': 'all databases',
    'dostęp z dowolnego adresu%s': 'access from any address%s',
    'obejmuje publiczne adresy IP': 'includes public IP addresses',
    'reguła dotyczy wyłącznie połączeń bez SSL': 'the rule applies only to non-SSL connections',
    'SSL nie jest wymagany – rozważ hostssl': 'SSL not required – consider hostssl',
    'replikacja dozwolona z dowolnego adresu': 'replication allowed from any address',
    'blokuje pasujące połączenia': 'blocks matching connections',
    'rola %s nie istnieje': 'role %s does not exist',
    'baza %s nie istnieje': 'database %s does not exist',
    'nigdy nie zadziała – wcześniejsza reguła (%s) obejmuje te same połączenia': 'never takes effect – an earlier rule (%s) covers the same connections',
    'superużytkownik instalacyjny': 'bootstrap superuser',
    'superużytkownik z prawem logowania': 'superuser with login',
    'superużytkownik (bez logowania)': 'superuser (no login)',
    'hasło wygasło (VALID UNTIL %s)': 'password expired (VALID UNTIL %s)',
    'hasło zapisane jako MD5 (przestarzałe) – ustaw je ponownie jako SCRAM': 'password stored as MD5 (deprecated) – reset it as SCRAM',
    'brak hasła – logowanie tylko metodami bez hasła (peer, cert, trust…)': 'no password – login only via password-less methods (peer, cert, trust…)',
    'uprawnienie REPLICATION': 'REPLICATION privilege',
    'omija zabezpieczenia wierszy (BYPASSRLS)': 'bypasses row-level security (BYPASSRLS)',
    'może tworzyć i zmieniać role (CREATEROLE)': 'can create and alter roles (CREATEROLE)',
    'żadna reguła pg_hba nie pozwala tej roli się zalogować': 'no pg_hba rule lets this role log in',
    'brak prawa CONNECT do jakiejkolwiek bazy': 'no CONNECT privilege on any database',
    'baza oznaczona jako nieprawidłowa (przerwane DROP DATABASE)': 'database marked invalid (interrupted DROP DATABASE)',
    'połączenia zablokowane (datallowconn = false)': 'connections disabled (datallowconn = false)',
    'żadna reguła pg_hba nie pozwala połączyć się z tą bazą': 'no pg_hba rule allows connecting to this database',
    # --- nazwy zrodel danych
    'Ustawienia serwera': 'Server settings',
    'Lista baz': 'Database list',
    'Uprawnienia baz': 'Database privileges',
    'Członkostwa ról': 'Role memberships',
    'Uprawnienia ról do baz': 'Role privileges on databases',
    'Ustawienia ról': 'Role settings',
    'Widok pg_hba_file_rules': 'pg_hba_file_rules view',
    'Mapowania pg_ident': 'pg_ident mappings',
    'Status SSL': 'SSL status',
    # --- zakladka Bazy danych
    'Bazy danych': 'Databases',
    'Baza': 'Database',
    'Łączenie': 'Connect',
    'Prawo CONNECT mają': 'CONNECT granted to',
    'Uwagi': 'Notes',
    'Nie udało się pobrać listy baz.': 'Could not read the database list.',
    'NIE (uszkodzona)': 'NO (invalid)',
    'NIE': 'NO',
    'tak, limit %d': 'yes, limit %d',
    ', szablon': ', template',
    '%d %s, łącznie %s, aktywne sesje: %s': '%d %s, %s in total, active sessions: %s',
    'Rozmiar nieznany dla %d %s – brak prawa CONNECT (potrzebne pg_read_all_stats).':
        'Size unknown for %d %s – no CONNECT privilege (pg_read_all_stats needed).',
    'Uprawnienia baz niedostępne: ': 'Database privileges unavailable: ',
    'wszyscy (PUBLIC)': 'everyone (PUBLIC)',
    'tylko superużytkownicy': 'superusers only',
    'Baza danych: %s': 'Database: %s',
    'Informacje': 'Information',
    'Właściciel': 'Owner',
    'Rozmiar': 'Size',
    'nieznany (brak prawa CONNECT)': 'unknown (no CONNECT privilege)',
    'Aktywne sesje': 'Active sessions',
    'Kodowanie': 'Encoding',
    'Przestrzeń tabel': 'Tablespace',
    'Szablon': 'Template',
    'Połączenia dozwolone': 'Connections allowed',
    'Limit połączeń': 'Connection limit',
    'bez limitu': 'unlimited',
    'baza nieprawidłowa': 'invalid database',
    'Komentarz': 'Comment',
    'Uprawnienia do bazy (ACL)': 'Database privileges (ACL)',
    'Brak danych o uprawnieniach.': 'No privilege data.',
    'Uprawnienia domyślne (nie było GRANT/REVOKE): PUBLIC ma CONNECT i TEMPORARY, właściciel ma wszystkie prawa.':
        'Default privileges (no GRANT/REVOKE yet): PUBLIC has CONNECT and TEMPORARY, the owner has all privileges.',
    ' (z GRANT OPTION)': ' (WITH GRANT OPTION)',
    'Komu': 'Grantee',
    'Uprawnienia': 'Privileges',
    'Nadał': 'Grantor',
    'CONNECT – łączenie się z bazą; CREATE – tworzenie schematów; TEMPORARY – tworzenie tabel tymczasowych.':
        'CONNECT – connect to the database; CREATE – create schemas; TEMPORARY – create temporary tables.',
    'Role z logowaniem, które mogą łączyć się z bazą (CONNECT)': 'Login roles that can connect to the database (CONNECT)',
    'Brak danych.': 'No data.',
    'żadna': 'none',
    'Reguły pg_hba dotyczące tej bazy (w kolejności sprawdzania)': 'pg_hba rules for this database (in evaluation order)',
    'Reguły pg_hba są niedostępne.': 'pg_hba rules are unavailable.',
    ' (przesłonięta)': ' (shadowed)',
    ' – być może': ' – possibly',
    'Skąd': 'From',
    'Kto': 'Who',
    'Żadna reguła nie obejmuje tej bazy – połączenie nie jest możliwe.': 'No rule covers this database – connecting is not possible.',
    # --- zakladka pg_hba
    'Dostęp pg_hba': 'pg_hba access',
    'Typ': 'Type',
    'Metoda': 'Method',
    'Najprościej: uruchom „sudo -u postgres python3 %s” i połącz się bez hasła przez gniazdo lokalne (puste pole Host). Można też wpisać ścieżkę pliku w polu pg_hba.conf.':
        'Easiest: run "sudo -u postgres python3 %s" and connect without a password through the local socket (empty Host field). You can also enter the file path in the pg_hba.conf field.',
    'BŁĄD': 'ERROR',
    'Źródło: ': 'Source: ',
    'widok pg_hba_file_rules': 'pg_hba_file_rules view',
    ' – plik %s': ' – file %s',
    'plik %s': 'file %s',
    ' (odczyt lokalny%s)': ' (read locally%s)',
    'Reguły są sprawdzane od góry – użyta zostaje pierwsza pasująca (typ, baza, rola, adres). Enter – szczegóły reguły.':
        'Rules are evaluated top-down – the first match (type, database, role, address) is used. Enter – rule details.',
    ' KRYTYCZNE ': ' CRITICAL ',
    ' Plik zawiera %d %s – przy przeładowaniu serwer odrzuca zmiany i nadal używa poprzedniej wersji reguł.':
        ' The file contains %d %s – on reload the server rejects the changes and keeps using the previous rules.',
    'błąd': 'error',
    'błędy': 'errors',
    'błędów': 'errors',
    'Reguła pg_hba – %s': 'pg_hba rule – %s',
    'Błąd w regule': 'Error in the rule',
    'PostgreSQL odrzuca cały plik pg_hba.conf, jeśli zawiera błąd: przy przeładowaniu (pg_ctl reload / SIGHUP) zostaje stara wersja reguł, a przy starcie serwer się nie uruchomi.':
        'PostgreSQL rejects the whole pg_hba.conf if it contains an error: on reload (pg_ctl reload / SIGHUP) the old rules stay in effect, and at startup the server will not start.',
    'Co oznacza ta reguła': 'What this rule means',
    'Kanał (typ)': 'Channel (type)',
    'Skąd (adres)': 'From (address)',
    'Dokąd (bazy)': 'To (databases)',
    'Kto (role)': 'Who (roles)',
    'Jak (metoda)': 'How (method)',
    'Opcje': 'Options',
    'Plik': 'File',
    'Linia': 'Line',
    'Numer reguły': 'Rule number',
    'Ocena': 'Rating',
    ' (obecnie nie działa, bo reguła jest przesłonięta – ale zadziała po zmianie kolejności lub usunięciu reguły %s)':
        ' (currently inactive because the rule is shadowed – but it will apply if rules are reordered or %s is removed)',
    'Wcześniejsza reguła (%s: %s; bazy %s; role %s) pasuje do wszystkich połączeń, które pasowałyby do tej reguły, więc ta nigdy nie jest używana.':
        'An earlier rule (%s: %s; databases %s; roles %s) matches every connection this rule would match, so this one is never used.',
    'Role z logowaniem, których dotyczy': 'Login roles it applies to',
    'Lista ról niedostępna.': 'Role list unavailable.',
    'Być może (zależy od pliku @ lub wyrażenia): ': 'Possibly (depends on an @ file or an expression): ',
    'Bazy, których dotyczy': 'Databases it applies to',
    'połączenia replikacyjne (np. pg_basebackup, standby)': 'replication connections (e.g. pg_basebackup, standby)',
    'żadna z istniejących baz': 'none of the existing databases',
    'Mapowanie użytkowników (pg_ident.conf: %s)': 'User mapping (pg_ident.conf: %s)',
    'Mapa': 'Map',
    'Użytkownik systemu': 'OS user',
    'Rola PostgreSQL': 'PostgreSQL role',
    'Błąd': 'Error',
    'Brak wpisów dla tej mapy w pg_ident.conf.': 'No entries for this map in pg_ident.conf.',
    'Jak PostgreSQL stosuje reguły': 'How PostgreSQL applies the rules',
    'Serwer przegląda reguły od góry i bierze pierwszą, która pasuje do typu połączenia, adresu klienta, bazy i roli. Dalsze reguły nie są sprawdzane – także wtedy, gdy uwierzytelnienie się nie powiedzie. Po przejściu reguły rola potrzebuje jeszcze prawa CONNECT do bazy.':
        'The server scans the rules top-down and takes the first one matching the connection type, client address, database and role. Later rules are not checked – even if authentication fails. After passing the rule the role still needs the CONNECT privilege on the database.',
    # --- zakladka Role
    'Role': 'Roles',
    'Rola': 'Role',
    'Ważne do': 'Valid until',
    'Należy do': 'Member of',
    'Nie udało się pobrać listy ról.': 'Could not read the role list.',
    '%d %s użytkownika (+%d systemowych pg_*): %d z logowaniem, %d %s': '%d user %s (+%d system pg_* roles): %d with login, %d %s',
    'superużytkownik': 'superuser',
    'superużytkowników': 'superusers',
    'Typ hasła (SCRAM/MD5/brak) widzi tylko superużytkownik – kolumna Hasło pokazuje „?”.':
        'Only a superuser can see the password type (SCRAM/MD5/none) – the Password column shows "?".',
    'Rola: %s': 'Role: %s',
    'Atrybuty': 'Attributes',
    'Logowanie (LOGIN)': 'Login (LOGIN)',
    'Superużytkownik': 'Superuser',
    'Tworzenie baz (CREATEDB)': 'Create databases (CREATEDB)',
    'Tworzenie ról (CREATEROLE)': 'Create roles (CREATEROLE)',
    'Replikacja (REPLICATION)': 'Replication (REPLICATION)',
    'Omijanie RLS (BYPASSRLS)': 'Bypass RLS (BYPASSRLS)',
    'Dziedziczenie (INHERIT)': 'Inherit (INHERIT)',
    'SCRAM-SHA-256 (zalecane)': 'SCRAM-SHA-256 (recommended)',
    'MD5 (przestarzałe)': 'MD5 (deprecated)',
    'brak hasła': 'no password',
    'nieznany (wymaga superużytkownika)': 'unknown (requires a superuser)',
    'inny format': 'other format',
    'Hasło': 'Password',
    'Hasło ważne do': 'Password valid until',
    'bez ograniczenia': 'no expiry',
    ' – WYGASŁO': ' – EXPIRED',
    'Należy do ról': 'Member of roles',
    'Dziedziczy': 'Inherits',
    'Pośrednio także: ': 'Indirectly also: ',
    '— nie należy do żadnej roli': '— not a member of any role',
    'Członkowie tej roli': 'Members of this role',
    '— brak': '— none',
    '(wszystkie)': '(all)',
    'Ustawienia (ALTER ROLE … SET)': 'Settings (ALTER ROLE … SET)',
    'Ustawienie': 'Setting',
    'Właściciel baz': 'Owner of databases',
    'Uprawnienia do baz': 'Database privileges',
    'Rola systemowa – uprawnienia wbudowane.': 'System role – built-in privileges.',
    'brak uprawnień do baz': 'no database privileges',
    'brak danych': 'no data',
    'Skąd i dokąd może się połączyć (reguły pg_hba)': 'Where it can connect from and to (pg_hba rules)',
    'Rola nie ma prawa logowania (NOLOGIN) – nie można się nią połączyć; służy do nadawania uprawnień swoim członkom.':
        'The role cannot log in (NOLOGIN) – it is used to grant privileges to its members.',
    'Żadna reguła pg_hba nie dotyczy tej roli – nie może się zalogować.': 'No pg_hba rule applies to this role – it cannot log in.',
    'przesłonięta': 'shadowed',
    ', być może': ', possibly',
    'Dokąd': 'To',
    'Podsumowanie: do jakich baz i skąd może się połączyć': 'Summary: which databases it can connect to, and from where',
    'brak pasującej reguły pg_hba – połączenie niemożliwe': 'no matching pg_hba rule – cannot connect',
    ' (blokada)': ' (blocked)',
    'Rola nie ma prawa CONNECT do żadnej bazy przyjmującej połączenia.': 'The role has no CONNECT privilege on any database that accepts connections.',
    'Dla danego adresu klienta decyduje pierwsza pasująca reguła z listy.': 'For a given client address the first matching rule in the list decides.',
    # --- stan firewalla
    'błąd odczytu': 'read error',
    'nie zainstalowany': 'not installed',
    'nie działa (%s)': 'not running (%s)',
    'działa – brak uprawnień do odczytu stref': 'running – no permission to read zones',
    'uruchom program jako root': 'run the program as root',
    'działa – strefy: %s (domyślna: %s)': 'running – zones: %s (default: %s)',
    'aktywny – domyślnie dla ruchu przychodzącego: %s, reguł: %d': 'active – default for incoming traffic: %s, rules: %d',
    'nieaktywny': 'inactive',
    '%s (wg /etc/ufw/ufw.conf)': '%s (per /etc/ufw/ufw.conf)',
    'szczegóły reguł widzi tylko root': 'only root can see the rule details',
    'nie zainstalowany (polecenie nft)': 'not installed (nft command)',
    'nieaktywny – moduł jądra nf_tables nie jest załadowany': 'inactive – the nf_tables kernel module is not loaded',
    'brak uprawnień do odczytu reguł': 'no permission to read the rules',
    'uruchom program jako root (sudo)': 'run the program as root (sudo)',
    'nie udało się przeanalizować reguł': 'could not parse the rules',
    'brak reguł (pusty zestaw)': 'no rules (empty ruleset)',
    '%s (polityka %s)': '%s (policy %s)',
    'tabele: %s; reguł: %d': 'tables: %s; rules: %d',
    'brak łańcuchów dla ruchu przychodzącego': 'no chains for incoming traffic',
    'łańcuchy wejściowe: %s': 'input chains: %s',
    'legacy – zarządzany przez ufw': 'legacy – managed by ufw',
    'legacy: reguł %d, polityka INPUT: %s': 'legacy: %d rules, INPUT policy: %s',
    'aktywne są jednocześnie reguły iptables-legacy i nftables – oba zestawy filtrują ruch, łatwo przeoczyć jeden z nich':
        'iptables-legacy and nftables rules are both active – both rulesets filter traffic and one is easy to overlook',
    'legacy – brak uprawnień do odczytu': 'legacy – no permission to read',
    'nf_tables – brak uprawnień': 'nf_tables – no permission',
    'nf_tables: %d reguł (widoczne też w nftables)': 'nf_tables: %d rules (also visible in nftables)',
    'brak reguł': 'no rules',
    'nie wszystkie reguły firewalla są czytelne – uruchom program jako root': 'not all firewall rules are readable – run the program as root',
    'brak filtrowania – dozwolone': 'no filtering – allowed',
    ' (z zastrzeżeniami)': ' (with caveats)',
    'Żaden aktywny mechanizm firewalla nie filtruje ruchu przychodzącego – pakiety na port %d docierają do serwera.':
        'No active firewall filters incoming traffic – packets to port %d reach the server.',
    'Wynik': 'Result',
    'Rozstrzyga': 'Decided by',
    'Powód': 'Reason',
    'Wyniki poszczególnych mechanizmów': 'Results of each mechanism',
    'Reguły, które mogą zmienić wynik (dotyczą tylko części ruchu)': 'Rules that may change the result (apply to part of the traffic only)',
    # --- zakladka Siec i firewall
    'Sieć i firewall': 'Network & firewall',
    'Element': 'Item',
    'Stan': 'State',
    'Ocena / uwagi': 'Rating / notes',
    'Sprawdzanie sieci i firewalla zostało pominięte (opcja --no-net).': 'Network and firewall checks were skipped (--no-net option).',
    'Nie udało się sprawdzić sieci.': 'Could not check the network.',
    'sieć: %s': 'network: %s',
    'Nasłuch serwera': 'Server listening',
    '%s:%d (zdalny)': '%s:%d (remote)',
    'nasłuch zdalnego serwera oceniany testem połączenia poniżej': 'listening of a remote server is assessed by the connection test below',
    '(brak połączenia z bazą)': '(no database connection)',
    '(niedostępne bez uprawnień)': '(not available without privileges)',
    'zmiana czeka na restart serwera – obecny nasłuch może być inny': 'change pending a server restart – current listening may differ',
    'zmiana portu czeka na restart serwera': 'port change pending a server restart',
    'Gniazda TCP': 'TCP sockets',
    'nie można odczytać /proc/net/tcp': 'cannot read /proc/net/tcp',
    'Gniazda TCP i Unix': 'TCP and Unix sockets',
    'brak – na porcie %d nic nie nasłuchuje': 'none – nothing listens on port %d',
    'serwer nie działa albo używa innego portu': 'the server is not running or uses another port',
    ' – lokalne serwery PostgreSQL działają na portach: %s': ' – local PostgreSQL servers run on ports: %s',
    'brak – serwer nie nasłuchuje na porcie %d w sieci': 'none – the server does not listen on port %d on the network',
    'pg_hba ma reguły dla sieci, ale klienci z sieci nie połączą się (listen_addresses)': 'pg_hba has network rules, but network clients cannot connect (listen_addresses)',
    'dostęp tylko przez gniazdo Unix': 'access through the Unix socket only',
    'wszystkie interfejsy IPv%d': 'all IPv%d interfaces',
    'tylko lokalnie (loopback)': 'local only (loopback)',
    'interfejs %s': 'interface %s',
    'proces niewidoczny (inne konto)': 'process not visible (another account)',
    'proces %s (pid %d)': 'process %s (pid %d)',
    'Gniazdo TCP %s:%d': 'TCP socket %s:%d',
    'Adres': 'Address',
    'Rodzina': 'Family',
    'Proces': 'Process',
    'UID właściciela': 'Owner UID',
    'Adres 0.0.0.0 lub :: oznacza nasłuch na wszystkich interfejsach; o tym, kto faktycznie się połączy, decydują dalej firewall i reguły pg_hba.':
        'Address 0.0.0.0 or :: means listening on all interfaces; who can actually connect is decided further by the firewall and pg_hba rules.',
    'Gniazdo Unix': 'Unix socket',
    'połączenia lokalne (typ local w pg_hba)': 'local connections (type local in pg_hba)',
    'Niezgodność': 'Mismatch',
    'serwer nasłuchuje w sieci, choć listen_addresses = %s': 'the server listens on the network although listen_addresses = %s',
    'prawdopodobnie zmiana czeka na restart': 'a change is probably pending a restart',
    'Test połączenia TCP (z tego komputera)': 'TCP connection test (from this machine)',
    'Nazwa hosta': 'Host name',
    'nie można ustalić adresu: %s': 'cannot resolve the address: %s',
    'port dostępny': 'port reachable',
    'otwarty – odpowiedź w %s ms': 'open – answered in %s ms',
    'odrzucone (connection refused)': 'refused (connection refused)',
    'serwer nie nasłuchuje na tym adresie (listen_addresses)': 'the server does not listen on this address (listen_addresses)',
    'odrzucone mimo nasłuchu – prawdopodobnie firewall (REJECT)': 'refused despite listening – probably a firewall (REJECT)',
    'port zamknięty na serwerze albo odrzucony przez firewall': 'port closed on the server or rejected by a firewall',
    'brak odpowiedzi w %s s': 'no answer within %s s',
    'pakiety prawdopodobnie odrzucane po cichu przez firewall (DROP)': 'packets probably silently dropped by a firewall (DROP)',
    'brak odpowiedzi – firewall po drodze (DROP) albo host niedostępny': 'no answer – a firewall on the way (DROP) or the host is unreachable',
    'błąd: %s': 'error: %s',
    'odrzucone przez firewall (ICMP) lub brak trasy': 'rejected by a firewall (ICMP) or no route',
    'Interpretacja': 'Interpretation',
    'Jak działa test': 'How the test works',
    'Program otwiera połączenie TCP na port %d i od razu je zamyka – nic nie jest wysyłane, serwer nie widzi próby logowania.':
        'The program opens a TCP connection to port %d and closes it immediately – nothing is sent and the server sees no login attempt.',
    'Uwaga: połączenie z tego samego komputera – nawet na adres interfejsu sieciowego – przechodzi przez interfejs lo i zwykle nie podlega regułom firewalla dla ruchu z zewnątrz. O dostępności z innych komputerów mówi sekcja „Port w firewallu” poniżej.':
        'Note: a connection from the same machine – even to a network interface address – goes through the lo interface and is usually not subject to firewall rules for external traffic. Reachability from other machines is shown in the "Port in the firewall" section below.',
    'brak adresów do sprawdzenia': 'no addresses to check',
    'Firewall – stan': 'Firewall – state',
    'Konfiguracja (wynik polecenia tylko do odczytu)': 'Configuration (output of a read-only command)',
    'Znaczenie': 'Relevance',
    'serwer jest zdalny': 'the server is remote',
    'firewall tego komputera nie wpływa na ruch przychodzący do bazy – sprawdź firewall na serwerze':
        "this machine's firewall does not affect traffic to the database – check the firewall on the server",
    'Ruch przychodzący': 'Incoming traffic',
    'filtrowany – %s': 'filtered – %s',
    'nieznane – brak uprawnień': 'unknown – no permission',
    'uruchom jako root': 'run as root',
    'niefiltrowany – brak aktywnych reguł': 'not filtered – no active rules',
    'port %d dostępny z każdej sieci; chroni go tylko pg_hba%s': 'port %d reachable from any network; only pg_hba protects it%s',
    ' (są reguły dla dowolnego adresu)': ' (there are rules for any address)',
    'serwer i tak nie nasłuchuje w sieci': 'the server does not listen on the network anyway',
    'Polityka domyślna': 'Default policy',
    'Reguł': 'Rules',
    'Reguły (w kolejności sprawdzania)': 'Rules (in evaluation order)',
    'polityka %s, reguł: %d': 'policy %s, rules: %d',
    'Enter – lista reguł': 'Enter – rule list',
    'Port %d/tcp w firewallu (ruch z sieci)': 'Port %d/tcp in the firewall (network traffic)',
    'port otwarty dla wszystkich adresów IPv%d': 'port open to all IPv%d addresses',
    'otwarty, ale część reguł zależy od dodatkowych warunków': 'open, but some rules depend on extra conditions',
    'zablokowany poza wybranymi sieciami – szczegóły pod Enter': 'blocked except for selected networks – details with Enter',
    'port zablokowany dla całego ruchu z sieci': 'port blocked for all network traffic',
    'Port %d z dowolnego adresu IPv%d': 'Port %d from any IPv%d address',
    'Z dowolnego adresu IPv%d': 'From any IPv%d address',
    'wszyscy': 'everyone',
    'wszyscy oprócz ': 'everyone except ',
    'Reguła %s': 'Rule %s',
    'Reguła': 'Rule',
    'Łańcuch': 'Chain',
    'Działanie': 'Action',
    'brak (np. log/licznik)': 'none (e.g. log/counter)',
    'Źródło': 'Source',
    'Interfejs': 'Interface',
    'oprócz ': 'except ',
    'Stan połączenia': 'Connection state',
    'nie ': 'not ',
    'Inne warunki': 'Other conditions',
    '%s – źródło: %s': '%s – source: %s',
    'Reguły pg_hba a nasłuch i firewall': 'pg_hba rules vs. listening and firewall',
    'serwer nie nasłuchuje w sieci – reguła nie jest używana': 'the server does not listen on the network – the rule is unused',
    'adres typu %s – zgodności z firewallem nie da się ocenić automatycznie': 'address of type %s – firewall compatibility cannot be assessed automatically',
    'brak filtrowania (firewall nie ogranicza)': 'no filtering (the firewall does not restrict)',
    'firewall nieczytelny – brak uprawnień': 'firewall unreadable – no permission',
    'firewall przepuszcza': 'firewall allows',
    'firewall przepuszcza tylko część (np. jedną rodzinę adresów)': 'firewall allows only part (e.g. one address family)',
    'firewall blokuje większość adresów tej sieci – przepuszcza tylko część': 'firewall blocks most of this network – allows only part of it',
    'firewall BLOKUJE – pg_hba dopuszcza tę sieć, ale połączenia nie dotrą do serwera': 'firewall BLOCKS – pg_hba allows this network, but connections will not reach the server',
    'pg_hba %s a firewall': 'pg_hba %s vs. firewall',
    'Reguła pg_hba': 'pg_hba rule',
    '%s; bazy %s; role %s': '%s; databases %s; roles %s',
    'Ruch z %s': 'Traffic from %s',
    'Żeby klient się połączył, muszą zgodzić się wszystkie warstwy: nasłuch serwera (listen_addresses), firewall i reguła pg_hba, a na końcu uprawnienie CONNECT do bazy.':
        'For a client to connect, all layers must agree: server listening (listen_addresses), the firewall and a pg_hba rule, and finally the CONNECT privilege on the database.',
    'Port %d · serwer %s · sprawdzono w %.1f s': 'Port %d · server: %s · checked in %.1f s',
    'lokalny': 'local',
    'zdalny (%s)': 'remote (%s)',
    '   konto: %s': '   account: %s',
    ' – reguły firewalla widzi tylko root': ' – only root can see firewall rules',
    'Tylko odczyt: /proc/net, nft list ruleset, iptables-save, firewall-cmd --list-all, ufw status; test TCP jedynie otwiera i zamyka połączenie.':
        'Read-only: /proc/net, nft list ruleset, iptables-save, firewall-cmd --list-all, ufw status; the TCP test only opens and closes a connection.',
    # --- zakladka Serwer
    'Serwer': 'Server',
    'Parametr': 'Parameter',
    'Wartość': 'Value',
    'Parametr konfiguracji': 'Configuration parameter',
    'Nazwa': 'Name',
    'Wartość surowa': 'Raw value',
    'niedostępna – wymaga superużytkownika lub roli pg_read_all_settings': 'unavailable – requires a superuser or the pg_read_all_settings role',
    '(niedostępne – wymaga superużytkownika lub pg_read_all_settings)': '(unavailable – requires a superuser or pg_read_all_settings)',
    'Nasłuch (listen_addresses)': 'Listening (listen_addresses)',
    '(puste)': '(empty)',
    'tylko gniazdo Unix – brak dostępu sieciowego': 'Unix socket only – no network access',
    'nasłuchuje na wszystkich interfejsach sieciowych': 'listens on all network interfaces',
    'tylko lokalnie': 'local only',
    'wybrane interfejsy': 'selected interfaces',
    'Katalog gniazd Unix': 'Unix socket directory',
    'SSL na serwerze': 'Server SSL',
    'wyłączony': 'off',
    'SSL wyłączony – hasła i dane w sieci bez szyfrowania': 'SSL off – passwords and data travel unencrypted',
    'SSL wyłączony': 'SSL off',
    'włączony': 'on',
    'Min. wersja TLS': 'Min. TLS version',
    'przestarzała wersja TLS': 'outdated TLS version',
    'Szyfrowanie nowych haseł': 'New password encryption',
    'nowe hasła zapisywane jako MD5 – ustaw scram-sha-256': 'new passwords are stored as MD5 – set scram-sha-256',
    'Logowanie połączeń': 'Connection logging',
    'wyłączone': 'off',
    'włączone (%s)': 'on (%s)',
    'połączenia nie są zapisywane w logu – trudniej audytować dostęp': 'connections are not logged – access is harder to audit',
    'Czas na uwierzytelnienie': 'Authentication timeout',
    'serwer: %s': 'server: %s',
    'Podsumowanie': 'Summary',
    'krytyczny': 'critical',
    'krytyczne': 'critical',
    'krytycznych': 'critical',
    'ostrzeżenie': 'warning',
    'ostrzeżenia': 'warnings',
    'ostrzeżeń': 'warnings',
    'Krytyczne': 'Critical',
    'Ostrzeżenia': 'Warnings',
    'Informacje o niższej wadze (info) są widoczne w kolumnach Uwagi na poszczególnych zakładkach.':
        'Lower-severity findings (info) are shown in the Notes columns on each tab.',
    'Enter – pełna lista': 'Enter – full list',
    'Znalezione problemy': 'Problems found',
    'brak problemów krytycznych i ostrzeżeń': 'no critical problems or warnings',
    '%d (w tym %d %s)': '%d (including %d %s)',
    'szablon': 'template',
    'szablony': 'templates',
    'szablonów': 'templates',
    '%d (z logowaniem: %d, superużytkownicy: %d, systemowe pg_*: %d)': '%d (with login: %d, superusers: %d, system pg_*: %d)',
    'Reguły pg_hba': 'pg_hba rules',
    '%d (błędne: %d, przesłonięte: %d)': '%d (invalid: %d, shadowed: %d)',
    'plik zawiera błędy': 'the file contains errors',
    'niedostępne': 'unavailable',
    'serwer zdalny – firewall oceniany tylko testem połączenia': 'remote server – firewall assessed by the connection test only',
    'aktywny: ': 'active: ',
    'nieznany (brak uprawnień – uruchom jako root)': 'unknown (no permission – run as root)',
    'brak aktywnych reguł filtrujących': 'no active filtering rules',
    'szczegóły: zakładka 5': 'details: tab 5',
    'Połączenie': 'Connection',
    'gniazdo Unix %s, port %s': 'Unix socket %s, port %s',
    'Zalogowano jako': 'Logged in as',
    ' (superużytkownik)': ' (superuser)',
    'część danych może być niedostępna – pełny obraz daje superużytkownik': 'some data may be unavailable – a superuser gets the full picture',
    'Baza połączenia': 'Connected database',
    'Szyfrowanie połączenia': 'Connection encryption',
    'nie dotyczy (gniazdo lokalne)': 'not applicable (local socket)',
    'brak – połączenie nieszyfrowane': 'none – unencrypted connection',
    'Wersja': 'Version',
    'Pełny opis': 'Full description',
    'Instancja': 'Instance',
    'Rola serwera': 'Server role',
    'standby (tryb odtwarzania)': 'standby (recovery mode)',
    'główny (primary)': 'primary',
    'Uruchomiony': 'Started',
    'Sesje': 'Sessions',
    ' (zarezerwowane dla superużytkowników: %s)': ' (reserved for superusers: %s)',
    'Kodowanie serwera': 'Server encoding',
    'Strefa czasowa': 'Time zone',
    'Pliki konfiguracyjne': 'Configuration files',
    'Katalog danych': 'Data directory',
    'Sieć i bezpieczeństwo': 'Network & security',
    'Problemy z pobraniem danych': 'Problems collecting data',
    'Klastry na tym komputerze (pg_lsclusters)': 'Clusters on this machine (pg_lsclusters)',
    'port %s, %s, właściciel %s': 'port %s, %s, owner %s',
    'Plik logu': 'Log file',
    ' · %s · pobrano o %s w %.1f s': ' · %s · collected at %s in %.1f s',
    'zwykły użytkownik': 'regular user',
    'Nie udało się połączyć z bazą – brak danych w tej zakładce.': 'Could not connect to the database – no data on this tab.',
    'Sprawdź zakładkę 5 (Sieć i firewall): czy serwer nasłuchuje, czy port odpowiada i czy firewall go nie blokuje.':
        'See tab 5 (Network & firewall): whether the server listens, whether the port answers and whether a firewall blocks it.',
    # --- pomoc
    'Pomoc – PgDiag %s': 'Help – PgDiag %s',
    'Klawisze – ogólne': 'Keys – general',
    'ta pomoc': 'this help',
    'uruchom diagnostykę (to samo co przycisk [ Uruchom ])': 'run the diagnostics (same as the [ Run ] button)',
    'przejście między polami formularza i tabelą wyników': 'move between the form fields and the results table',
    'wyjście (q – gdy kursor nie stoi w polu tekstowym)': 'quit (q – when the cursor is not in a text field)',
    'przerysuj ekran': 'redraw the screen',
    'Esc, cyfra': 'Esc, digit',
    'zamiennik klawiszy F (Esc 1 = F1 … Esc 0 = F10), jak w Midnight Commanderze': 'F-key substitute (Esc 1 = F1 … Esc 0 = F10), as in Midnight Commander',
    'Formularz (górna część ekranu)': 'Form (top of the screen)',
    'poprzedni / następny wiersz pól; ↓ z ostatniego wiersza przechodzi do tabeli': 'previous / next row of fields; ↓ from the last row moves to the table',
    'kursor w polu; na początku/końcu pola – przejście do poprzedniego/następnego pola': 'cursor in the field; at the start/end of a field – move to the previous/next field',
    'uruchom diagnostykę; w polu SSL – lista wyboru (także Spacja)': 'run the diagnostics; in the SSL field – pick list (also Space)',
    'początek / koniec pola': 'start / end of the field',
    'wyczyść pole': 'clear the field',
    'Tabela wyników': 'Results table',
    'wybór wiersza (↑ w pierwszym wierszu wraca do formularza)': 'select a row (↑ on the first row goes back to the form)',
    'pierwszy / ostatni wiersz': 'first / last row',
    '← → lub 1–5': '← → or 1–5',
    'zmiana zakładki': 'switch tab',
    'szczegóły wybranego wiersza': 'details of the selected row',
    '/ lub F4': '/ or F4',
    'filtr – tylko wiersze zawierające wpisany tekst (Esc czyści filtr)': 'filter – only rows containing the typed text (Esc clears the filter)',
    'pokaż lub ukryj role systemowe pg_* (zakładka Role)': 'show or hide system roles pg_* (Roles tab)',
    'wybór motywu kolorów (także z formularza: F9)': 'choose the color theme (also from the form: F9)',
    'wybór języka: English / Polski (także z formularza: F8)': 'choose the language: English / Polski (also from the form: F8)',
    'Okno szczegółów': 'Details window',
    'przewijanie': 'scroll',
    'poprzedni / następny wiersz tabeli': 'previous / next table row',
    'zamknięcie': 'close',
    'Motywy (F9)': 'Themes (F9)',
    'Wybrany motyw i język są zapamiętywane w pliku %s – to jedyny plik, który program zapisuje, i tylko wtedy, gdy zmienisz motyw (F9) lub język (F8). Na jedno uruchomienie można je wskazać opcjami --theme i --lang.':
        'The chosen theme and language are remembered in %s – the only file the program writes, and only when you change the theme (F9) or the language (F8). For a single run use the --theme and --lang options.',
    'Mysz': 'Mouse',
    'Kliknięcie pola, przycisku, zakładki, wiersza lub klawisza na dolnym pasku. Dwuklik wiersza – szczegóły. Kółko – przewijanie. Kliknięcie poza oknem – zamknięcie okna. Zaznaczanie tekstu w terminalu: Shift + przeciągnięcie myszą.':
        'Click a field, button, tab, row or a key on the bottom bar. Double-click a row – details. Wheel – scroll. Click outside a window – close it. Selecting text in the terminal: Shift + mouse drag.',
    'Pola połączenia': 'Connection fields',
    'puste = lokalne gniazdo Unix; nazwa, adres IP albo katalog gniazda (np. /var/run/postgresql)': 'empty = local Unix socket; a name, an IP address or a socket directory (e.g. /var/run/postgresql)',
    'domyślnie 5432': 'default 5432',
    'baza, do której program się łączy (domyślnie postgres); dane o wszystkich bazach pochodzą z katalogu systemowego':
        'the database the program connects to (default postgres); data about all databases comes from the system catalog',
    'Użytkownik': 'User',
    'puste = nazwa bieżącego użytkownika systemu': "empty = the current OS user's name",
    'puste = psql użyje ~/.pgpass lub PGPASSWORD; hasło trafia do psql przez zmienną środowiskową, nie przez linię poleceń':
        'empty = psql uses ~/.pgpass or PGPASSWORD; the password is passed to psql in an environment variable, not on the command line',
    'tryb sslmode: prefer, disable, allow, require, verify-ca, verify-full': 'sslmode: prefer, disable, allow, require, verify-ca, verify-full',
    'Plik pg_hba.conf': 'pg_hba.conf file',
    'opcjonalnie: ścieżka do pliku czytanego lokalnie. Puste = widok pg_hba_file_rules z serwera; gdy brak uprawnień – próba odczytu pliku na tym komputerze':
        'optional: path of a file read locally. Empty = the pg_hba_file_rules view from the server; without permission – an attempt to read the file on this machine',
    'psql jako': 'psql as',
    'tylko gdy program działa jako root: konto systemowe, z którego uruchamiany jest psql. Wybierz postgres, aby połączyć się metodą peer jako superużytkownik, a jednocześnie (jako root) odczytać reguły firewalla':
        'only when the program runs as root: the OS account psql runs as. Choose postgres to connect via peer as a superuser while (as root) still reading the firewall rules',
    'Zakładki': 'Tabs',
    'podsumowanie problemów, połączenie, wersja, pliki konfiguracyjne, nasłuch, SSL, szyfrowanie haseł, klastry na tym komputerze':
        'problem summary, connection, version, configuration files, listening, SSL, password encryption, clusters on this machine',
    'bazy w instancji: rozmiar, właściciel, kodowanie, kto ma prawo CONNECT': 'databases in the instance: size, owner, encoding, who has CONNECT',
    'Dostęp (pg_hba)': 'Access (pg_hba)',
    'reguły: skąd (adres), dokąd (bazy), kto (role), jak (metoda) – z oceną ryzyka i wykrywaniem reguł przesłoniętych':
        'rules: from (address), to (databases), who (roles), how (method) – with risk rating and shadowed-rule detection',
    'atrybuty, typ hasła, członkostwa, uprawnienia do baz i pasujące reguły pg_hba': 'attributes, password type, memberships, database privileges and matching pg_hba rules',
    'na jakich adresach serwer nasłuchuje, test połączenia TCP, stan firewalla (nftables, iptables, firewalld, ufw), czy port bazy jest otwarty z sieci i czy firewall nie blokuje sieci dopuszczonych w pg_hba':
        'which addresses the server listens on, a TCP connection test, firewall state (nftables, iptables, firewalld, ufw), whether the database port is open from the network and whether the firewall blocks networks allowed in pg_hba',
    'poważne ryzyko, np. trust z sieci albo błąd w pliku pg_hba.conf': 'serious risk, e.g. trust from the network or an error in pg_hba.conf',
    'warto poprawić, np. dostęp z dowolnego adresu, hasło jawnym tekstem, hasło MD5, reguła przesłonięta':
        'worth fixing, e.g. access from any address, clear-text password, MD5 password, shadowed rule',
    'informacja lub dobra praktyka': 'information or good practice',
    'brak uwag': 'no remarks',
    'Bezpieczeństwo – program niczego nie zmienia': 'Safety – the program changes nothing',
    'wykonuje wyłącznie stałe zapytania SELECT do katalogów systemowych': 'runs only fixed SELECT queries against system catalogs',
    'każde zapytanie działa w transakcji BEGIN READ ONLY zakończonej ROLLBACK': 'every query runs in a BEGIN READ ONLY transaction ended with ROLLBACK',
    'psql jest uruchamiany z -X (bez ~/.psqlrc) i -w (bez pytań o hasło)': 'psql runs with -X (no ~/.psqlrc) and -w (never prompts for a password)',
    'program nie zmienia niczego w systemie; plik pg_hba.conf jest tylko czytany; jedyny zapisywany plik to własne ustawienia interfejsu (motyw i język) w katalogu domowym – tylko po ich zmianie':
        'the program changes nothing on the system; pg_hba.conf is only read; the only file written is its own UI settings (theme and language) in the home directory – only when you change them',
    'stan sieci i firewalla: odczyt /proc/net oraz wyłącznie polecenia listujące – nft list ruleset, iptables-save, firewall-cmd --state/--list-all, ufw status; moduły jądra firewalla nie są ładowane, jeśli nie są aktywne':
        'network and firewall state: reads /proc/net and runs listing commands only – nft list ruleset, iptables-save, firewall-cmd --state/--list-all, ufw status; firewall kernel modules are not loaded if inactive',
    'test połączenia TCP tylko otwiera i od razu zamyka połączenie – nic nie jest wysyłane': 'the TCP connection test only opens and immediately closes a connection – nothing is sent',
    'Wskazówki': 'Tips',
    'Najpełniejsze dane (typy haseł, reguły pg_hba, ścieżki plików) widzi superużytkownik bazy, a reguły firewalla – root. Najprościej uruchomić program jako root; psql zostanie wtedy uruchomiony z konta postgres (pole „psql jako”):':
        'A database superuser sees the most complete data (password types, pg_hba rules, file paths), and root sees the firewall rules. The simplest way is to run the program as root; psql then runs as the postgres account ("psql as" field):',
    'Bez uprawnień roota (bez sprawdzenia reguł firewalla):': 'Without root privileges (no firewall rule check):',
    'Raport tekstowy bez interfejsu:': 'Plain-text report without the UI:',
    # --- motywy i pasek klawiszy
    'Midnight Commander': 'Midnight Commander',
    'klasyczny niebieski (domyślny)': 'classic blue (default)',
    'GoTaR': 'GoTaR',
    'skórka gotar z MC – czarne tło, zielone pola, turkusowe okna': 'MC gotar skin – black background, green fields, cyan windows',
    'Dark': 'Dark',
    'skórka dark z MC – czarne tło, turkusowe zaznaczenie': 'MC dark skin – black background, cyan selection',
    'Jasny': 'Light',
    'ciemny tekst na jasnym tle': 'dark text on a light background',
    'Monochromatyczny': 'Monochrome',
    'bez kolorów – inwersja i pogrubienie': 'no colors – reverse video and bold',
    'Pomoc': 'Help',
    'Szczeg.': 'Details',
    'Filtr': 'Filter',
    'Systemowe': 'System',
    'Język': 'Language',
    'Motyw': 'Theme',
    'Wyjście': 'Quit',
    'bieżący': 'current',
    # --- formularz i ekran
    'Host': 'Host',
    '(gniazdo lokalne)': '(local socket)',
    'Port': 'Port',
    '(brak/.pgpass)': '(none/.pgpass)',
    'SSL': 'SSL',
    'pg_hba.conf': 'pg_hba.conf',
    '(z serwera)': '(from server)',
    'Uruchom': 'Run',
    'Wpisz parametry połączenia i naciśnij Enter lub F2. Program niczego nie zmienia na serwerze.':
        'Enter the connection parameters and press Enter or F2. The program changes nothing on the server.',
    'Za mały terminal: %dx%d': 'Terminal too small: %dx%d',
    'Powiększ okno lub F10/q': 'Enlarge the window or F10/q',
    'PgDiag %s – diagnostyka PostgreSQL': 'PgDiag %s – PostgreSQL diagnostics',
    ' tylko odczyt ': ' read-only ',
    ' Połączenie ': ' Connection ',
    'Czekaj…': 'Wait…',
    ' BRAK DANYCH ': ' NO DATA ',
    ' Filtr: %s (Esc w filtrze czyści) ': ' Filter: %s (Esc in the filter clears) ',
    ' ukryto %d ról systemowych pg_* (F6) ': ' %d system roles pg_* hidden (F6) ',
    'PgDiag – diagnostyka PostgreSQL (tylko odczyt)': 'PgDiag – PostgreSQL diagnostics (read-only)',
    '1. Wpisz parametry połączenia w polach u góry (puste pole Host = lokalne gniazdo Unix).':
        '1. Enter the connection parameters in the fields at the top (empty Host = local Unix socket).',
    '2. Naciśnij Enter, F2 albo kliknij [ Uruchom ].': '2. Press Enter, F2 or click [ Run ].',
    '3. Zakładki zmieniasz strzałkami ← →, wiersze ↑ ↓, Enter pokazuje szczegóły, F1 – pomoc.':
        '3. Switch tabs with ← →, rows with ↑ ↓, Enter shows details, F1 – help.',
    'Program pokaże: bazy danych, reguły dostępu pg_hba (skąd, dokąd, kto, jak) z oceną ryzyka':
        'The program shows: databases, pg_hba access rules (from, to, who, how) with a risk rating',
    'oraz role z atrybutami, członkostwami i uprawnieniami.': 'and roles with attributes, memberships and privileges.',
    'Najpełniejsze dane widzi superużytkownik, np.:  sudo -u postgres python3 %s': 'A superuser sees the most complete data, e.g.:  sudo -u postgres python3 %s',
    'F8 – język (English / Polski), F9 – motyw (mc, gotar, dark, light, mono).': 'F8 – language (English / Polski), F9 – theme (mc, gotar, dark, light, mono).',
    '(brak danych)': '(no data)',
    '(brak wierszy pasujących do filtra „%s”)': '(no rows match the filter "%s")',
    '%s Łączenie i pobieranie danych… %.1f s': '%s Connecting and collecting data… %.1f s',
    'lokalnie': 'local',
    'Role systemowe pg_* są %s.': 'System roles pg_* are %s.',
    'widoczne': 'shown',
    'ukryte': 'hidden',
    'Diagnostyka już trwa…': 'Diagnostics already running…',
    'Port musi być liczbą.': 'The port must be a number.',
    'Nie znaleziono programu psql': 'psql not found',
    'PgDiag korzysta z klienta psql. Zainstaluj go (np. apt install postgresql-client, dnf install postgresql) albo wskaż ścieżkę opcją --psql /ścieżka/do/psql.':
        'PgDiag uses the psql client. Install it (e.g. apt install postgresql-client, dnf install postgresql) or give its path with --psql /path/to/psql.',
    'Gotowe: %s, %s pg_hba, %s.': 'Done: %s, %s (pg_hba), %s.',
    'baza': 'database',
    'bazy': 'databases',
    'baz': 'databases',
    'reguła': 'rule',
    'reguły': 'rules',
    'reguł': 'rules',
    'rola': 'role',
    'role': 'roles',
    'ról': 'roles',
    ' Problemy: %s, %s (zakładka Serwer).': ' Problems: %s, %s (Server tab).',
    ' Nie znaleziono problemów.': ' No problems found.',
    'Błąd: ': 'Error: ',
    'Brak połączenia z bazą – wyniki sieci i firewalla w zakładce 5. ': 'No database connection – network and firewall results on tab 5. ',
    'Nie udało się połączyć': 'Could not connect',
    'Komunikat': 'Message',
    'Co zrobić': 'What to do',
    'Sprawdzenie sieci i firewalla zostało wykonane – wyniki są w zakładce 5 „Sieć i firewall”.':
        'The network and firewall check was performed – see tab 5 "Network & firewall".',
    'Użyte parametry': 'Parameters used',
    'podane': 'given',
    'nie podano (psql użyje ~/.pgpass lub PGPASSWORD)': 'not given (psql uses ~/.pgpass or PGPASSWORD)',
    'Wewnętrzny błąd programu – szczegóły w oknie.': 'Internal program error – see the window for details.',
    'Wewnętrzny błąd programu': 'Internal program error',
    'Wystąpił nieoczekiwany błąd. Nic nie zostało zmienione na serwerze.': 'An unexpected error occurred. Nothing was changed on the server.',
    ' ↑↓ PgUp PgDn przewijanie%s  Esc zamknij ': ' ↑↓ PgUp PgDn scroll%s  Esc close ',
    '  ←→ poprzedni/następny': '  ←→ previous/next',
    ' Język / Language ': ' Language / Język ',
    'Enter – zapisz w %s': 'Enter – save to %s',
    '↑↓ – podgląd na żywo, Esc – anuluj': '↑↓ – live preview, Esc – cancel',
    'Język bez zmian.': 'Language unchanged.',
    'Język „%s” zapamiętany w %s.': 'Language "%s" saved to %s.',
    'Język „%s” włączony, ale nie udało się go zapisać: %s': 'Language "%s" applied but could not be saved: %s',
    ' Motyw interfejsu ': ' UI theme ',
    'Motyw bez zmian.': 'Theme unchanged.',
    'Motyw „%s” zapamiętany w %s.': 'Theme "%s" saved to %s.',
    'Motyw „%s” włączony, ale nie udało się go zapisać: %s': 'Theme "%s" applied but could not be saved: %s',
    'Najpierw uruchom diagnostykę (F2).': 'Run the diagnostics first (F2).',
    ' Filtr (%s): ': ' Filter (%s): ',
    'Enter – zatwierdź, Esc – wyczyść': 'Enter – apply, Esc – clear',
    'Filtr: „%s” – %d %s.': 'Filter: "%s" – %d %s.',
    'wiersz': 'row',
    'wiersze': 'rows',
    'wierszy': 'rows',
    'Filtr wyłączony.': 'Filter off.',
    'Filtr wyczyszczony.': 'Filter cleared.',
    '  BRAK DANYCH: %s\n': '  NO DATA: %s\n',
    # --- wiersz polecen
    'PgDiag – diagnostyka PostgreSQL w konsoli (wyłącznie odczyt): bazy, reguły pg_hba, role, sieć i firewall.':
        'PgDiag – PostgreSQL console diagnostics (read-only): databases, pg_hba rules, roles, network and firewall.',
    'Przykład: sudo python3 %s     (firewall jako root, psql jako postgres)':
        'Example: sudo python3 %s     (firewall as root, psql as postgres)',
    'host lub katalog gniazda (domyślnie: gniazdo lokalne)': 'host or socket directory (default: local socket)',
    'port (domyślnie 5432)': 'port (default 5432)',
    'rola do zalogowania': 'role to log in as',
    'baza do połączenia (domyślnie postgres)': 'database to connect to (default postgres)',
    'tryb SSL (domyślnie prefer)': 'SSL mode (default prefer)',
    'ścieżka do lokalnego pliku pg_hba.conf (zamiast widoku z serwera)': 'path to a local pg_hba.conf (instead of the server view)',
    'ścieżka do programu psql': 'path to the psql program',
    'gdy program działa jako root: konto systemowe, z którego uruchamiany jest psql (domyślnie postgres, jeśli istnieje)':
        'when running as root: the OS account psql runs as (default postgres, if it exists)',
    'pomiń sprawdzanie sieci i firewalla': 'skip the network and firewall checks',
    'zapytaj o hasło przy starcie': 'prompt for the password at startup',
    'uruchom diagnostykę od razu po starcie': 'run the diagnostics right after startup',
    'wypisz raport tekstowy zamiast interfejsu': 'print a plain-text report instead of the UI',
    'nie przechwytuj myszy': 'do not capture the mouse',
    'język interfejsu na to uruchomienie (bez zapisywania): en, pl': 'UI language for this run (not saved): en, pl',
    'motyw interfejsu na to uruchomienie (bez zapisywania): %s': 'UI theme for this run (not saved): %s',
    'Hasło: ': 'Password: ',
    'O progr.': 'About',
    'O programie – PgDiag %s': 'About – PgDiag %s',
    'Konsolowe narzędzie diagnostyczne PostgreSQL działające wyłącznie w trybie odczytu: bazy danych, reguły dostępu pg_hba, role, nasłuch sieciowy i firewall.':
        'A read-only console diagnostic tool for PostgreSQL: databases, pg_hba access rules, roles, network listening and firewall.',
    'Autor': 'Author',
    'Imię i nazwisko': 'Name',
    'Rodzaj': 'Type',
    'Prawa autorskie': 'Copyright',
    'Licencja': 'License',
    'MIT – licencja otwarta, permisywna': 'MIT – open-source, permissive',
    'program można bezpłatnie używać, kopiować, modyfikować, łączyć z innym oprogramowaniem, publikować, rozpowszechniać, udzielać sublicencji i sprzedawać – także w zastosowaniach komercyjnych':
        'you may use, copy, modify, merge, publish, distribute, sublicense and sell the program free of charge – including for commercial use',
    'warunek: do wszystkich kopii lub istotnych części programu trzeba dołączyć informację o prawach autorskich i treść licencji':
        'condition: the copyright notice and the license text must be included in all copies or substantial portions of the program',
    'program jest dostarczany „tak jak jest”, bez jakiejkolwiek gwarancji; autor nie odpowiada za szkody wynikłe z jego użycia':
        'the program is provided "as is", without warranty of any kind; the author is not liable for any damages arising from its use',
    'Tekst licencji': 'License text',
    'Wiążący jest oryginalny tekst w języku angielskim:': 'The original English text is binding:',
    'Środowisko': 'Environment',
    'System': 'System',
    'nie znaleziono': 'not found',
    'Terminal': 'Terminal',
    'TERM=%s, kolorów: %d': 'TERM=%s, colors: %d',
    'Plik ustawień': 'Settings file',
    '(jeszcze nie utworzony)': '(not created yet)',
    'Autor i licencja': 'Author and license',
    'MIT – pełny tekst: F7 (O programie) lub opcja --license': 'MIT – full text: F7 (About) or the --license option',
    'o programie: wersja, autor, licencja MIT': 'about: version, author, MIT license',
    'licencja MIT · F7 – o programie': 'MIT license · F7 – about',
    'licencja MIT': 'MIT License',
    'wypisz tekst licencji (MIT) i zakończ': 'print the license text (MIT) and exit',
    'Terminal: %d kolorów (TERM=%s) – ciemny granat niezależny od palety terminala':
        'Terminal: %d colors (TERM=%s) – dark navy independent of the terminal palette',
    'Terminal: %d kolorów (TERM=%s) – odcienie zależą od palety terminala; uruchom z --colors 256 lub TERM=xterm-256color':
        'Terminal: %d colors (TERM=%s) – shades depend on the terminal palette; run with --colors 256 or TERM=xterm-256color',
    'głębia kolorów: auto (TERM=xterm/putty → wersja -256color, jeśli dostępna), 8 lub 256':
        'color depth: auto (TERM=xterm/putty → the -256color variant if available), 8 or 256',
    '%s (od %s)': '%s (up %s)',
    'wykonuje wyłącznie stałe zapytania SELECT do katalogów systemowych': 'runs only fixed SELECT queries against system catalogs',
    'Wykonywane są wyłącznie zapytania SELECT w transakcji READ ONLY; w systemie nic nie jest zmieniane.':
        'Only SELECT queries in a READ ONLY transaction are executed; nothing on the system is changed.',
    'Nie znaleziono programu psql (użyj --psql ŚCIEŻKA).\n': 'psql not found (use --psql PATH).\n',
    'Błąd: %s\n': 'Error: %s\n',
    'Wskazówka: %s\n': 'Hint: %s\n',
    'Interfejs pełnoekranowy wymaga terminala. Użyj --report, aby wypisać raport tekstowy.\n':
        'The full-screen UI needs a terminal. Use --report to print a plain-text report.\n',
    'Błąd terminala (%s). Sprawdź zmienną TERM albo użyj --report.\n': 'Terminal error (%s). Check the TERM variable or use --report.\n',
}


# =============================================================================
#  Start
# =============================================================================

def terminfo_exists(name):
    dirs = [os.environ.get("TERMINFO"), os.path.expanduser("~/.terminfo")]
    dirs += (os.environ.get("TERMINFO_DIRS") or "").split(":")
    dirs += ["/etc/terminfo", "/lib/terminfo", "/usr/share/terminfo", "/usr/lib/terminfo",
             "/usr/share/lib/terminfo", "/usr/local/share/terminfo"]
    for d in dirs:
        if d and (os.path.exists(os.path.join(d, name[0], name)) or
                  os.path.exists(os.path.join(d, "%02x" % ord(name[0]), name))):
            return True
    return False


def choose_term(mode):
    """MobaXterm, PuTTY i wiele innych emulatorow zglasza TERM=xterm (8 kolorow), choc obsluguje 256.
    W trybie auto dla takich nazw wybieramy wariant -256color (tylko dla tego procesu)."""
    term = os.environ.get("TERM", "")
    if mode == "8" or not term or term.endswith("-256color"):
        return
    base = {"xterm": "xterm", "xterm-color": "xterm", "xterm-new": "xterm", "putty": "putty",
            "screen": "screen", "tmux": "tmux", "rxvt-unicode": "rxvt-unicode"}.get(term)
    if base is None:
        return
    if mode == "auto" and base in ("screen", "tmux") and not os.environ.get("COLORTERM"):
        return
    cand = base + "-256color"
    if terminfo_exists(cand):
        os.environ["TERM"] = cand


def parse_args():
    env = os.environ
    # jezyk trzeba znac przed zbudowaniem opisu opcji: --lang, plik ustawien, domyslnie EN
    cfg = load_config()
    lang = cfg.get("lang") or "en"
    for i, a in enumerate(sys.argv[1:]):
        if a.startswith("--lang="):
            lang = a.split("=", 1)[1]
        elif a == "--lang" and i + 2 < len(sys.argv):
            lang = sys.argv[i + 2]
    set_lang(lang)
    ap = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]),
        description="\n".join(textwrap.wrap(tr("PgDiag – diagnostyka PostgreSQL w konsoli (wyłącznie odczyt): bazy, "
                                                 "reguły pg_hba, role, sieć i firewall."), 78)),
        epilog=(tr("Przykład: sudo python3 %s     (firewall jako root, psql jako postgres)")
                % os.path.basename(sys.argv[0])) + "\n\n%s · %s" % (COPYRIGHT, tr("licencja MIT")),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-H", "--host", default=env.get("PGHOST", ""), help=tr("host lub katalog gniazda (domyślnie: gniazdo lokalne)"))
    ap.add_argument("-p", "--port", default=env.get("PGPORT", "5432"), help=tr("port (domyślnie 5432)"))
    ap.add_argument("-U", "--user", default=env.get("PGUSER", ""), help=tr("rola do zalogowania"))
    ap.add_argument("-d", "--dbname", default=env.get("PGDATABASE", "postgres"), help=tr("baza do połączenia (domyślnie postgres)"))
    ap.add_argument("--sslmode", default=env.get("PGSSLMODE", "prefer"), help=tr("tryb SSL (domyślnie prefer)"))
    ap.add_argument("--hba-file", default="", help=tr("ścieżka do lokalnego pliku pg_hba.conf (zamiast widoku z serwera)"))
    ap.add_argument("--psql", default=None, help=tr("ścieżka do programu psql"))
    ap.add_argument("--os-user", default=None,
                    help=tr("gdy program działa jako root: konto systemowe, z którego uruchamiany jest psql "
                         "(domyślnie postgres, jeśli istnieje)"))
    ap.add_argument("--no-net", action="store_true", help=tr("pomiń sprawdzanie sieci i firewalla"))
    ap.add_argument("-W", "--password-prompt", action="store_true", help=tr("zapytaj o hasło przy starcie"))
    ap.add_argument("--run", action="store_true", help=tr("uruchom diagnostykę od razu po starcie"))
    ap.add_argument("--report", action="store_true", help=tr("wypisz raport tekstowy zamiast interfejsu"))
    ap.add_argument("--no-mouse", action="store_true", help=tr("nie przechwytuj myszy"))
    ap.add_argument("--colors", choices=["auto", "8", "256"], default="auto",
                    help=tr("głębia kolorów: auto (TERM=xterm/putty → wersja -256color, jeśli dostępna), 8 lub 256"))
    ap.add_argument("--lang", choices=["en", "pl"], default=None,
                    help=tr("język interfejsu na to uruchomienie (bez zapisywania): en, pl"))
    ap.add_argument("--theme", choices=THEME_NAMES + sorted(THEME_ALIASES), default=None,
                    help=tr("motyw interfejsu na to uruchomienie (bez zapisywania): %s") % ", ".join(THEME_NAMES))
    ap.add_argument("--version", action="version",
                    version="PgDiag %s – %s – %s" % (VERSION, COPYRIGHT, tr("licencja MIT")))
    ap.add_argument("--license", action="store_true", help=tr("wypisz tekst licencji (MIT) i zakończ"))
    a = ap.parse_args()
    a.password = env.get("PGPASSWORD", "")
    a.theme = THEME_ALIASES.get(a.theme, a.theme)
    if a.os_user is None and os.geteuid() == 0 and user_exists("postgres"):
        a.os_user = "postgres"
    if a.password_prompt:
        a.password = getpass.getpass(tr("Hasło: "))
    return a


def main():
    global UNICODE
    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error:
        pass
    opts = parse_args()
    if opts.license:
        sys.stdout.write(LICENSE_TEXT)
        return 0
    if opts.report:
        enc = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "")
        UNICODE = enc == "utf8"
        psql = find_psql(opts.psql)
        if not psql:
            sys.stderr.write(tr("Nie znaleziono programu psql (użyj --psql ŚCIEŻKA).\n"))
            return 2
        params = {"host": opts.host, "port": opts.port, "dbname": opts.dbname, "user": opts.user,
                  "password": opts.password, "sslmode": opts.sslmode}
        if opts.os_user and opts.os_user != "root":
            params["os_user"] = opts.os_user
        try:
            rep = collect(params, psql, opts.hba_file, skip_net=opts.no_net)
        except PgError as e:
            sys.stderr.write(U(tr("Błąd: %s\n") % e.message))
            if e.hint:
                sys.stderr.write(U(tr("Wskazówka: %s\n") % e.hint))
            if getattr(e, "net", None):
                _, _, tabs = offline_report(params, e.net)
                print_tabs(tabs[4:], sys.stdout)
            return 1
        print_report(Model(rep), sys.stdout)
        return 0
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        sys.stderr.write(tr("Interfejs pełnoekranowy wymaga terminala. Użyj --report, aby wypisać raport tekstowy.\n"))
        return 2
    try:
        codeset = locale.nl_langinfo(locale.CODESET)   # kodowanie biblioteki C – to samo widzi ncurses
    except Exception:
        codeset = locale.getpreferredencoding(False)
    UNICODE = (codeset or "").lower().replace("-", "") == "utf8"
    os.environ.setdefault("ESCDELAY", "25")
    choose_term(opts.colors)

    def run(scr):
        init_keymap()
        App(scr, opts).loop()
    try:
        curses.wrapper(run)
    except KeyboardInterrupt:
        pass
    except curses.error as e:
        sys.stderr.write(tr("Błąd terminala (%s). Sprawdź zmienną TERM albo użyj --report.\n") % e)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

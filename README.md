<a name="english"></a>
# PgDiag

**English** · [Polski ↓](#polski)

Read-only PostgreSQL diagnostics for the Linux console. A full-screen, Midnight Commander–style tool that shows
which databases exist, who may connect from where (`pg_hba.conf`), which roles are defined, and whether the
network and the firewall actually let clients in. **It never changes anything.**

```text
 PgDiag 1.5 – PostgreSQL diagnostics                                postgres@local   read-only
┌─ Connection ─────────────────────────────────────────────────────────────────────────────────┐
│ Host: (local socket)        Port: 5432     Database: postgres          User: (postgres)      │
│ Password: (none/.pgpass)   SSL: prefer      ▾   pg_hba.conf: (from server)                   │
│ psql as: postgres ▾                                                                  [ Run ] │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
  1 Server !  2 Databases (6)   3 pg_hba access (14) !  4 Roles (10) !  5 Network & firewall !
┌─ pg_hba access ──────────────────────────────────────────────────────────────────────────────┐
│ Source: pg_hba_file_rules view – file /etc/postgresql/16/main/pg_hba.conf                    │
│ Rules are evaluated top-down – the first match (type, database, role, address) is used. Ent… │
│  Line │ Type     │ From (addres… │ To (databas… │ Who (roles)       │ Method     │ Rating    │
├───────┼──────────┼───────────────┼──────────────┼───────────────────┼────────────┼───────────┤
│   118 │ local    │ (local)       │ all          │ postgres          │ peer       │ OK        │
│   123 │ local    │ (local)       │ all          │ all               │ peer       │ OK        │
│   125 │ host     │ 127.0.0.1     │ all          │ all               │ scram-sha… │ OK        │
│   127 │ host     │ ::1           │ all          │ all               │ scram-sha… │ OK        │
│   130 │ local    │ (local)       │ replication  │ all               │ peer       │ OK        │
│   131 │ host     │ 127.0.0.1     │ replication  │ all               │ scram-sha… │ OK        │
│   132 │ host     │ ::1           │ replication  │ all               │ scram-sha… │ OK        │
│   134 │ hostssl  │ 10.0.0.0/8    │ crm          │ app_user          │ scram-sha… │ OK        │
│   135 │ host     │ 192.168.1.0/… │ sklep        │ +admins           │ password   │ WARNING   │
│   136 │ host     │ 0.0.0.0/0     │ all          │ all               │ md5        │ WARNING   │
│   137 │ host     │ 192.168.50.0… │ all          │ all               │ trust      │ WARNING   │
└────────────────────────────────────────────────────────────────────────────────────── 10/14 ─┘
 Done: 6 databases, 14 rules (pg_hba), 10 roles. Problems: 0 critical, 11 warnings (Server tab…
1Help    2Run     3Details 4Filter  5        6System  7About   8Language9Theme   10Quit
```

## Features

- **Databases** – size, owner, encoding, collation, connection limits and who has the `CONNECT` privilege.
- **Access rules (pg_hba)** – every rule as *from / to / who / how*, with a risk rating. Detects rules that never
  take effect because an earlier rule shadows them, syntax errors in the file, and references to roles or
  databases that do not exist.
- **Roles** – attributes, password type (SCRAM / MD5 / none), expiry, memberships (including indirect ones),
  database privileges and, for each role, which databases it can reach and from where.
- **Network & firewall** – addresses the server really listens on, a TCP connection probe, the state of
  nftables, iptables (including legacy tables), firewalld and ufw, whether the database port is open from the
  network, and whether the firewall blocks networks that `pg_hba.conf` allows.
- **Server summary** – all findings in one place, version, configuration files, SSL, password encryption and
  local clusters (`pg_lsclusters`).
- Keyboard and mouse, filter, detail windows, five color themes (including the MC *gotar* skin), English and
  Polish UI, and a plain-text report mode for scripts and tickets.
- A single file using only the Python standard library.

## Read-only by design

- Only fixed `SELECT` queries against system catalogs; every query runs inside
  `BEGIN TRANSACTION READ ONLY … ROLLBACK`.
- `psql` runs with `-X` (no `~/.psqlrc`) and `-w` (never prompts). The password is passed in an environment
  variable, never on the command line.
- Firewall information comes from listing commands only: `nft list ruleset`, `iptables-save`,
  `firewall-cmd --state` / `--list-all`, `ufw status`. Inactive firewall kernel modules are not loaded.
- The TCP probe opens a connection and closes it immediately. Nothing is sent, so the server sees no login
  attempt; with `log_connections = on` it logs only a `connection received` line.
- The only file PgDiag writes is its own settings file, `~/.config/pgdiag/pgdiag.conf`, and only when you change
  the theme or the language.

## Requirements

- Linux with Python 3.6 or newer (standard library only)
- The `psql` client (package `postgresql-client` or `postgresql`)
- PostgreSQL server: tested with version 16. The `pg_hba_file_rules` view needs PostgreSQL 10 or newer; on older
  servers PgDiag reads `pg_hba.conf` from the local disk instead.
- Optional: root privileges, to read firewall rules

## Installation

PgDiag is a single file. Copy `pgdiag.py` to the database server and make it executable:

```bash
chmod +x pgdiag.py
```

## Usage

```bash
# Complete picture in one run: firewall rules read as root, psql runs as the postgres OS account (peer auth)
sudo python3 pgdiag.py

# Without root (firewall rules are not checked), as the postgres superuser
sudo -u postgres python3 pgdiag.py

# Remote server, prompt for the password
python3 pgdiag.py -H db.example.com -U admin -W

# Plain-text report, e.g. to attach to a ticket
sudo python3 pgdiag.py --report > pgdiag-report.txt
```

When PgDiag runs as root, `psql` is started as the `postgres` OS account (the *psql as* field, `--os-user`).
That lets it log in with peer authentication while PgDiag itself can still read the firewall rules.

A regular user sees less: password types, the `pg_hba_file_rules` view and configuration file paths require a
database superuser, and firewall rules require root. Missing data is marked as such, never guessed.

The standard `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGSSLMODE` and `PGPASSWORD` environment variables are
used as defaults.

## Keyboard and mouse

| Key | Action |
|---|---|
| `F1` / `?` | Help |
| `F2` / `Ctrl+R` / `Enter` in the form | Run the diagnostics |
| `F3` / `Enter` | Details of the selected row |
| `F4` / `/` | Filter rows (`Esc` clears the filter) |
| `F6` / `s` | Show or hide system roles `pg_*` |
| `F7` | About: version, author, license |
| `F8` / `l` | Language (English / Polski) |
| `F9` / `t` | Color theme |
| `F10` / `q` | Quit |
| `←` `→` / `1`–`5` | Switch tab |
| `↑` `↓` `PgUp` `PgDn` `Home` `End` | Move through rows; in a detail window `←` `→` go to the previous / next row |
| `Tab` / `Shift+Tab` | Move between the form and the results table |
| `Ctrl+L` | Redraw the screen |
| `Esc` + digit | F-key substitute (`Esc 1` = `F1` … `Esc 0` = `F10`), as in Midnight Commander |

Mouse: click fields, buttons, tabs, rows and the bottom key bar; double-click a row to open its details; the
wheel scrolls. To select text in the terminal, hold `Shift` while dragging.

## Command-line options

| Option | Description |
|---|---|
| `-H`, `--host HOST` | Host or socket directory (default: local socket) |
| `-p`, `--port PORT` | Port (default 5432) |
| `-U`, `--user USER` | Role to log in as |
| `-d`, `--dbname DBNAME` | Database to connect to (default `postgres`) |
| `--sslmode SSLMODE` | SSL mode (default `prefer`) |
| `--hba-file PATH` | Read a local `pg_hba.conf` instead of the server view |
| `--psql PATH` | Path to the `psql` program |
| `--os-user USER` | When running as root: the OS account `psql` runs as (default `postgres`, if it exists) |
| `--no-net` | Skip the network and firewall checks |
| `-W`, `--password-prompt` | Prompt for the password at startup |
| `--run` | Run the diagnostics right after startup |
| `--report` | Print a plain-text report instead of the UI |
| `--no-mouse` | Do not capture the mouse |
| `--colors {auto,8,256}` | Color depth (see below) |
| `--lang {en,pl}` | UI language for this run only |
| `--theme {mc,gotar,dark,light,mono}` | UI theme for this run only |
| `--version` | Show version, author and license |
| `--license` | Print the license text and exit |

## Themes and language

Themes: **mc** (classic blue, default), **gotar** (Midnight Commander's gotar skin), **dark** (MC's dark skin),
**light** and **mono**. Languages: **English** (default) and **Polski**.

Press `F9` (theme) or `F8` (language): the screen changes as you move through the list, `Enter` saves the choice
and `Esc` restores the previous one. The choice is stored in `~/.config/pgdiag/pgdiag.conf`:

```ini
[ui]
theme = gotar
lang = en
```

**Terminal colors.** MobaXterm, PuTTY and many other terminals report `TERM=xterm` (8 colors) even though they
support 256. With `--colors auto` (the default) PgDiag switches its own process to `xterm-256color` when that
terminfo entry exists, so the dark themes use a fixed dark navy instead of the terminal's palette blue, which is
often too light. Use `--colors 8` if your terminal misbehaves.

## Limitations

- The TCP probe runs on the same machine, so it goes through the `lo` interface and normally bypasses firewall
  rules for external traffic. Reachability from other hosts is assessed from the firewall rules themselves.
- For a remote server the local firewall is irrelevant and only the TCP probe is shown. Run PgDiag on the
  database server for the full picture.
- Firewall evaluation is a static analysis of the ruleset. Conditions it cannot evaluate exactly (ipsets, rate
  limits, marks, destination addresses) are reported as *with caveats* rather than guessed.
- `pg_hba.conf` entries with host names, `samehost` or `samenet` cannot be matched against firewall rules
  automatically.

## License

MIT © 2026 Mariusz Bak <dev@mariuszbak.eu>

The full license text is in the header of `pgdiag.py`, under `F7` in the program, and is printed by
`python3 pgdiag.py --license`.

---

<a name="polski"></a>
# PgDiag (po polsku)

[English ↑](#english) · **Polski**

Diagnostyka PostgreSQL w konsoli Linuksa, wyłącznie do odczytu. Pełnoekranowe narzędzie w stylu Midnight
Commandera, które pokazuje, jakie bazy są zainstalowane, kto i skąd może się połączyć (`pg_hba.conf`), jakie role
są zdefiniowane oraz czy sieć i firewall faktycznie wpuszczają klientów. **Niczego nie zmienia.**

```text
 PgDiag 1.5 – diagnostyka PostgreSQL                          postgres@lokalnie   tylko odczyt
┌─ Połączenie ─────────────────────────────────────────────────────────────────────────────────┐
│ Host: (gniazdo lokalne)    Port: 5432     Baza: postgres         Użytkownik: (postgres)      │
│ Hasło: (brak/.pgpass)   SSL: prefer      ▾   pg_hba.conf: (z serwera)                        │
│ psql jako: postgres ▾                                                            [ Uruchom ] │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
  1 Serwer !  2 Bazy danych (6)   3 Dostęp pg_hba (14) !  4 Role (10) !  5 Sieć i firewall !
┌─ Sieć i firewall ────────────────────────────────────────────────────────────────────────────┐
│ Port 5432 · serwer lokalny · sprawdzono w 0.0 s   konto: root                                │
│ Tylko odczyt: /proc/net, nft list ruleset, iptables-save, firewall-cmd --list-all, ufw stat… │
│ Element                │ Stan                               │ Ocena / uwagi                  │
├────────────────────────┼────────────────────────────────────┼────────────────────────────────┤
│ iptables (IPv4)        │ brak reguł                         │                                │
│ ip6tables (IPv6)       │ brak reguł                         │                                │
│ Ruch przychodzący      │ filtrowany – nftables              │                                │
│ ↳ nft inet filter/inp… │ polityka drop, reguł: 5            │ Enter – lista reguł            │
│─ Port 5432/tcp w firewallu (ruch z sieci) ───────────────────────────────────────────────────│
│ Z dowolnego adresu IP… │ zablokowane (DROP) (z zastrzeżeni… │ zablokowany poza wybranymi si… │
│ ↳ nft input #4         │ tcp dport 5432 ip saddr 10.0.0.0/… │ dopuszcza – źródło: 10.0.0.0/8 │
│ ↳ nft input #5         │ ip saddr 192.168.1.0/24 tcp dport… │ blokuje (DROP) – źródło: 192.… │
│─ Reguły pg_hba a nasłuch i firewall ─────────────────────────────────────────────────────────│
│ pg_hba linia 134       │ hostssl 10.0.0.0/8 → scram-sha-256 │ firewall przepuszcza           │
│ pg_hba linia 135       │ host 192.168.1.0/24 → password     │ firewall BLOKUJE – pg_hba dop… │
│ pg_hba linia 136       │ host 0.0.0.0/0 → md5               │ firewall blokuje większość ad… │
│ pg_hba linia 140       │ hostnossl ::/0 → scram-sha-256     │ firewall BLOKUJE – pg_hba dop… │
└────────────────────────────────────────────────────────────────────────────────────── 24/24 ─┘
 Gotowe: 6 baz, 14 reguł pg_hba, 10 ról. Problemy: 0 krytycznych, 11 ostrzeżeń (zakładka Serwe…
1Pomoc   2Uruchom 3Szczeg. 4Filtr   5        6Systemo…7O progr.8Język   9Motyw   10Wyjście
```

## Możliwości

- **Bazy danych** – rozmiar, właściciel, kodowanie, collation, limity połączeń i kto ma prawo `CONNECT`.
- **Reguły dostępu (pg_hba)** – każda reguła jako *skąd / dokąd / kto / jak*, z oceną ryzyka. Wykrywa reguły,
  które nigdy nie zadziałają, bo przesłania je wcześniejsza, błędy składni w pliku oraz odwołania do
  nieistniejących ról i baz.
- **Role** – atrybuty, typ hasła (SCRAM / MD5 / brak), ważność, członkostwa (także pośrednie), uprawnienia do baz
  i – dla każdej roli – do jakich baz i skąd może się połączyć.
- **Sieć i firewall** – adresy, na których serwer faktycznie nasłuchuje, test połączenia TCP, stan nftables,
  iptables (także tabel legacy), firewalld i ufw, czy port bazy jest otwarty z sieci oraz czy firewall nie blokuje
  sieci dopuszczonych w `pg_hba.conf`.
- **Podsumowanie serwera** – wszystkie znalezione problemy w jednym miejscu, wersja, pliki konfiguracyjne, SSL,
  szyfrowanie haseł i lokalne klastry (`pg_lsclusters`).
- Obsługa klawiaturą i myszą, filtr, okna szczegółów, pięć motywów kolorów (w tym skórka *gotar* z MC),
  interfejs po angielsku i po polsku oraz raport tekstowy do skryptów i zgłoszeń.
- Jeden plik, wyłącznie biblioteka standardowa Pythona.

## Tylko odczyt – z założenia

- Wyłącznie stałe zapytania `SELECT` do katalogów systemowych; każde w transakcji
  `BEGIN TRANSACTION READ ONLY … ROLLBACK`.
- `psql` jest uruchamiany z `-X` (bez `~/.psqlrc`) i `-w` (nigdy nie pyta o hasło). Hasło trafia do niego przez
  zmienną środowiskową, nigdy przez linię poleceń.
- Informacje o firewallu pochodzą wyłącznie z poleceń listujących: `nft list ruleset`, `iptables-save`,
  `firewall-cmd --state` / `--list-all`, `ufw status`. Nieaktywne moduły jądra firewalla nie są ładowane.
- Test TCP otwiera połączenie i od razu je zamyka. Nic nie jest wysyłane, więc serwer nie widzi próby logowania;
  przy `log_connections = on` w logu pojawia się tylko wpis `connection received`.
- Jedyny plik, który PgDiag zapisuje, to jego własne ustawienia, `~/.config/pgdiag/pgdiag.conf` – i tylko wtedy,
  gdy zmienisz motyw albo język.

## Wymagania

- Linux z Pythonem 3.6 lub nowszym (tylko biblioteka standardowa)
- Klient `psql` (pakiet `postgresql-client` albo `postgresql`)
- Serwer PostgreSQL: testowane na wersji 16. Widok `pg_hba_file_rules` wymaga PostgreSQL 10 lub nowszego; przy
  starszych serwerach PgDiag czyta `pg_hba.conf` z lokalnego dysku.
- Opcjonalnie: uprawnienia roota, aby odczytać reguły firewalla

## Instalacja

PgDiag to jeden plik. Skopiuj `pgdiag.py` na serwer bazy danych i nadaj mu prawo wykonywania:

```bash
chmod +x pgdiag.py
```

## Użycie

```bash
# Komplet danych w jednym przebiegu: reguły firewalla czytane jako root, psql działa z konta postgres (peer)
sudo python3 pgdiag.py

# Bez roota (bez sprawdzenia reguł firewalla), jako superużytkownik postgres
sudo -u postgres python3 pgdiag.py

# Serwer zdalny, zapytanie o hasło
python3 pgdiag.py -H db.example.com -U admin -W

# Raport tekstowy, np. do dołączenia do zgłoszenia
sudo python3 pgdiag.py --report > pgdiag-raport.txt
```

Gdy PgDiag działa jako root, `psql` jest uruchamiany z konta systemowego `postgres` (pole *psql jako*,
`--os-user`). Dzięki temu loguje się metodą peer, a sam PgDiag nadal może odczytać reguły firewalla.

Zwykły użytkownik widzi mniej: typy haseł, widok `pg_hba_file_rules` i ścieżki plików konfiguracyjnych wymagają
superużytkownika bazy, a reguły firewalla – roota. Brakujące dane są wyraźnie oznaczone, nigdy zgadywane.

Standardowe zmienne środowiskowe `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGSSLMODE` i `PGPASSWORD` służą
jako wartości domyślne.

## Klawiatura i mysz

| Klawisz | Działanie |
|---|---|
| `F1` / `?` | Pomoc |
| `F2` / `Ctrl+R` / `Enter` w formularzu | Uruchom diagnostykę |
| `F3` / `Enter` | Szczegóły wybranego wiersza |
| `F4` / `/` | Filtr wierszy (`Esc` czyści filtr) |
| `F6` / `s` | Pokaż lub ukryj role systemowe `pg_*` |
| `F7` | O programie: wersja, autor, licencja |
| `F8` / `l` | Język (English / Polski) |
| `F9` / `t` | Motyw kolorów |
| `F10` / `q` | Wyjście |
| `←` `→` / `1`–`5` | Zmiana zakładki |
| `↑` `↓` `PgUp` `PgDn` `Home` `End` | Ruch po wierszach; w oknie szczegółów `←` `→` – poprzedni / następny wiersz |
| `Tab` / `Shift+Tab` | Przejście między formularzem a tabelą wyników |
| `Ctrl+L` | Przerysowanie ekranu |
| `Esc` + cyfra | Zamiennik klawiszy F (`Esc 1` = `F1` … `Esc 0` = `F10`), jak w Midnight Commanderze |

Mysz: kliknięcie pola, przycisku, zakładki, wiersza lub klawisza na dolnym pasku; dwuklik wiersza otwiera
szczegóły; kółko przewija. Aby zaznaczyć tekst w terminalu, przytrzymaj `Shift` podczas przeciągania.

## Opcje wiersza poleceń

| Opcja | Opis |
|---|---|
| `-H`, `--host HOST` | Host lub katalog gniazda (domyślnie: gniazdo lokalne) |
| `-p`, `--port PORT` | Port (domyślnie 5432) |
| `-U`, `--user USER` | Rola do zalogowania |
| `-d`, `--dbname DBNAME` | Baza do połączenia (domyślnie `postgres`) |
| `--sslmode SSLMODE` | Tryb SSL (domyślnie `prefer`) |
| `--hba-file ŚCIEŻKA` | Odczyt lokalnego pliku `pg_hba.conf` zamiast widoku z serwera |
| `--psql ŚCIEŻKA` | Ścieżka do programu `psql` |
| `--os-user KONTO` | Gdy program działa jako root: konto systemowe, z którego uruchamiany jest `psql` (domyślnie `postgres`, jeśli istnieje) |
| `--no-net` | Pomiń sprawdzanie sieci i firewalla |
| `-W`, `--password-prompt` | Zapytaj o hasło przy starcie |
| `--run` | Uruchom diagnostykę od razu po starcie |
| `--report` | Wypisz raport tekstowy zamiast interfejsu |
| `--no-mouse` | Nie przechwytuj myszy |
| `--colors {auto,8,256}` | Głębia kolorów (patrz niżej) |
| `--lang {en,pl}` | Język interfejsu tylko na to uruchomienie |
| `--theme {mc,gotar,dark,light,mono}` | Motyw interfejsu tylko na to uruchomienie |
| `--version` | Wersja, autor i licencja |
| `--license` | Wypisz tekst licencji i zakończ |

## Motywy i język

Motywy: **mc** (klasyczny niebieski, domyślny), **gotar** (skórka gotar z Midnight Commandera), **dark**
(skórka dark z MC), **light** (jasny) i **mono**. Języki: **English** (domyślny) i **Polski**.

Naciśnij `F9` (motyw) albo `F8` (język): ekran zmienia się na bieżąco podczas przesuwania po liście, `Enter`
zapisuje wybór, a `Esc` przywraca poprzedni. Wybór jest zapamiętywany w `~/.config/pgdiag/pgdiag.conf`:

```ini
[ui]
theme = gotar
lang = pl
```

**Kolory terminala.** MobaXterm, PuTTY i wiele innych terminali zgłasza `TERM=xterm` (8 kolorów), choć obsługuje
256. W trybie `--colors auto` (domyślnym) PgDiag przełącza własny proces na `xterm-256color`, jeśli taka
definicja terminala istnieje. Dzięki temu ciemne motywy używają stałego ciemnego granatu zamiast „niebieskiego”
z palety terminala, który często jest zbyt jasny. Jeśli terminal źle to wyświetla, użyj `--colors 8`.

## Ograniczenia

- Test TCP jest wykonywany z tego samego komputera, więc przechodzi przez interfejs `lo` i zwykle omija reguły
  firewalla dla ruchu z zewnątrz. Dostępność z innych komputerów jest oceniana na podstawie samych reguł
  firewalla.
- Przy serwerze zdalnym lokalny firewall nie ma znaczenia i pokazywany jest tylko test połączenia. Pełny obraz
  daje uruchomienie PgDiag na serwerze bazy danych.
- Ocena firewalla to statyczna analiza reguł. Warunki, których nie da się dokładnie ocenić (ipsety, limity
  połączeń, znaczniki, adresy docelowe), są oznaczane jako *z zastrzeżeniami* zamiast zgadywania.
- Wpisów `pg_hba.conf` z nazwami hostów, `samehost` lub `samenet` nie da się automatycznie zestawić z regułami
  firewalla.

## Licencja

MIT © 2026 Mariusz Bak <dev@mariuszbak.eu>

Pełny tekst licencji znajduje się w nagłówku pliku `pgdiag.py`, pod klawiszem `F7` w programie i jest
wypisywany przez `python3 pgdiag.py --license`.

#!/usr/bin/env bash
# =============================================================================
# SecuScan v2 — external tool installer (no root required)
#
# Installs every CLI tool the plugin catalog can drive into ~/tools:
#   nmap, nikto, nuclei (+templates), gobuster, sqlmap, whatweb, ffuf,
#   subfinder, dalfox, testssl.sh, wafw00f, whois, traceroute, wordlists
#
# Everything lands in $HOME/tools — wrappers in tools/bin (put on PATH),
# extracted .debs in tools/root, Go binaries and clones in tools/opt.
# Re-running the script is safe: installed pieces are skipped.
#
# After installing, start the server with the wrappers on PATH:
#   PATH="$HOME/tools/bin:$PATH" secuscan-server
# =============================================================================
set -euo pipefail

TOOLS="$HOME/tools"
BIN="$TOOLS/bin"
ROOT="$TOOLS/root"
OPT="$TOOLS/opt"
PREFIXES="~/tools"

mkdir -p "$BIN" "$ROOT" "$OPT" "$TOOLS/wordlists"

log()  { printf '\033[1;32m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- helpers ---

# fetch_deb PKGS... — download debs (with dependency closure) and extract
fetch_debs() {
    local pkgs=("$@")
    local tmp
    tmp="$(mktemp -d)"
    # full recursive dependency closure (skips installed-sys filtering on
    # purpose: extracted copies are harmless and make the tree self-contained)
    local list
    list="$(apt-cache depends --recurse --no-recommends --no-suggests \
            --no-conflicts --no-breaks --no-replaces --no-enhances \
            "${pkgs[@]}" 2>/dev/null | grep '^\w' | sort -u || true)"
    [ -z "$list" ] && list="${pkgs[*]}"
    log "downloading debs: $(echo "$list" | tr '\n' ' ')"
    (cd "$tmp" && xargs --no-run-if-empty apt-get download >/dev/null 2>&1 <<<"$list" || true)
    # make sure the primary packages were fetched even if dep resolution hiccupped
    (cd "$tmp" && apt-get download "${pkgs[@]}" >/dev/null 2>&1 || true)
    local count=0
    for f in "$tmp"/*.deb; do
        [ -e "$f" ] || continue
        dpkg -x "$f" "$ROOT"
        count=$((count + 1))
    done
    rm -rf "$tmp"
    log "extracted $count deb(s) into $ROOT"
}

# gh_release OWNER REPO ASSET_SUBSTR — download+untar a release asset.
# Uses GITHUB_TOKEN when set (avoids anonymous API rate limits); falls back
# to the unauthenticated API otherwise.
gh_asset() {
    local owner="$1" repo="$2" substr="$3" dest="$4"
    local -a auth=()
    [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
    local url
    url="$(curl -fsSL "${auth[@]}" "https://api.github.com/repos/$owner/$repo/releases/latest" \
        | python3 -c "import json,sys
for a in json.load(sys.stdin).get('assets', []):
    if '$substr' in a['name'] and 'arm' not in a['name'].lower():
        print(a['browser_download_url']); break" 2>/dev/null || true)"
    if [ -z "$url" ]; then
        warn "no release asset matched '$substr' for $owner/$repo"
        return 1
    fi
    mkdir -p "$dest"
    case "$url" in
        *.zip)  curl -fsSL "$url" -o /tmp/gh.zip && unzip -qo /tmp/gh.zip -d "$dest" && rm -f /tmp/gh.zip ;;
        *)      curl -fsSL "$url" -o /tmp/gh.tgz && tar -xzf /tmp/gh.tgz -C "$dest" && rm -f /tmp/gh.tgz ;;
    esac
    log "installed $repo -> $dest"
}

LD="$ROOT/usr/lib/x86_64-linux-gnu"
run_with_libs() {  # run_with_libs <real-binary> args...
    local real="$1"; shift
    LD_LIBRARY_PATH="$LD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$real" "$@"
}

# ------------------------------------------------------------------- nmap ---
if [ ! -x "$ROOT/usr/bin/nmap" ]; then
    fetch_debs nmap nmap-common libpcap0.8 liblinear4
    cat > "$BIN/nmap" <<EOF
#!/bin/sh
# nmap wrapper: self-contained install (data files + libs under ~/tools)
NMAPDIR="$ROOT/usr/share/nmap"
export NMAPDIR
export LD_LIBRARY_PATH="$ROOT/usr/lib/x86_64-linux-gnu\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
exec "$ROOT/usr/bin/nmap" --datadir "$ROOT/usr/share/nmap" "\$@"
EOF
    chmod +x "$BIN/nmap"
    log "nmap wrapper created (with libpcap/liblinear paths)"
else log "nmap: present"; fi

# --------------------------------------------------------------- whois/vvv ---
if [ ! -x "$ROOT/usr/bin/whois" ]; then
    fetch_debs whois traceroute
    for t in whois traceroute; do
        [ -x "$ROOT/usr/bin/$t" ] && ln -sf "$ROOT/usr/bin/$t" "$BIN/$t"
    done
    log "whois/traceroute linked"
else log "whois: present"; fi

# ------------------------------------------------------------------ nikto ---
if [ ! -d "$OPT/nikto" ]; then
    git clone --depth 1 https://github.com/sullo/nikto.git "$OPT/nikto" >/dev/null 2>&1 || warn "nikto clone failed"
    # nikto needs XML::Writer (and friends) — extract the Debian Perl
    # module packages into a parallel tree and put them on PERL5LIB.
    mkdir -p "$OPT/nikto/perllib-root"
    fetch_debs libxml-writer-perl libxml-parser-perl libxml-twig-perl
    # fetch_debs extracts into $ROOT, but we want a nikto-scoped tree;
    # re-extract the .debs manually into the perllib-root.
    local_tmp="$(mktemp -d)"
    (cd "$local_tmp" && apt-get download libxml-writer-perl libxml-parser-perl libxml-twig-perl >/dev/null 2>&1 || true)
    for f in "$local_tmp"/*.deb; do
        [ -e "$f" ] || continue
        dpkg -x "$f" "$OPT/nikto/perllib-root"
    done
    rm -rf "$local_tmp"
    cat > "$BIN/nikto" <<EOF
#!/bin/sh
PERL5LIB="$OPT/nikto/perllib-root/usr/share/perl5:$OPT/nikto/perllib-root/usr/lib/x86_64-linux-gnu/perl5:$OPT/nikto/local-lib:\$PERL5LIB"
export PERL5LIB
exec perl "$OPT/nikto/program/nikto.pl" "\$@"
EOF
    chmod +x "$BIN/nikto"
    log "nikto cloned + wrapper (with XML::Writer perl libs)"
else log "nikto: present"; fi

# ----------------------------------------------------------------- sqlmap ---
if [ ! -d "$OPT/sqlmap" ]; then
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$OPT/sqlmap" >/dev/null 2>&1
    cat > "$BIN/sqlmap" <<EOF
#!/bin/sh
exec python3 "$OPT/sqlmap/sqlmap.py" "\$@"
EOF
    chmod +x "$BIN/sqlmap"
    log "sqlmap cloned + wrapper"
else log "sqlmap: present"; fi

# ------------------------------------------------------- nuclei + templates ---
if ! have nuclei && [ ! -x "$OPT/nuclei/nuclei" ]; then
    gh_asset projectdiscovery nuclei "linux_amd64.zip" "$OPT/nuclei" \
        && ln -sf "$OPT/nuclei/nuclei" "$BIN/nuclei" \
        || warn "nuclei binary install failed"
else log "nuclei: present"; fi
if [ ! -d "$HOME/nuclei-templates" ]; then
    log "cloning nuclei templates (~100MB, one-time)…"
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git \
        "$HOME/nuclei-templates" >/dev/null 2>&1 || warn "template clone failed"
else log "nuclei templates: present"; fi

# --------------------------------------------------------------- gobuster ---
if ! have gobuster && [ ! -x "$OPT/gobuster/gobuster" ]; then
    gh_asset OJ gobuster "Linux_x86_64.tar.gz" "$OPT/gobuster" \
        || gh_asset OJ gobuster "Linux_amd64" "$OPT/gobuster" \
        || warn "gobuster install failed"
    [ -x "$OPT/gobuster/gobuster" ] && ln -sf "$OPT/gobuster/gobuster" "$BIN/gobuster"
else log "gobuster: present"; fi

# ------------------------------------------------------------------- ffuf ---
if ! have ffuf && [ ! -x "$OPT/ffuf/ffuf" ]; then
    gh_asset ffuf ffuf "linux_amd64" "$OPT/ffuf" || warn "ffuf install failed"
    [ -x "$OPT/ffuf/ffuf" ] && ln -sf "$OPT/ffuf/ffuf" "$BIN/ffuf"
else log "ffuf: present"; fi

# --------------------------------------------------------------- subfinder ---
if ! have subfinder && [ ! -x "$OPT/subfinder/subfinder" ]; then
    gh_asset projectdiscovery subfinder "linux_amd64.zip" "$OPT/subfinder" \
        || warn "subfinder install failed"
    [ -x "$OPT/subfinder/subfinder" ] && ln -sf "$OPT/subfinder/subfinder" "$BIN/subfinder"
else log "subfinder: present"; fi

# ----------------------------------------------------------------- dalfox ---
if ! have dalfox && [ ! -x "$BIN/dalfox" ]; then
    gh_asset hahwul dalfox "linux-x86_64.tar.gz" "$OPT/dalfox" || warn "dalfox install failed"
    # asset may ship the binary at top level or inside a versioned dir
    for b in "$OPT"/dalfox/dalfox* "$OPT"/dalfox/*/dalfox; do
        [ -x "$b" ] && ln -sfn "$b" "$BIN/dalfox" && break
    done
else log "dalfox: present"; fi

# -------------------------------------------------------------- testssl.sh ---
if [ ! -d "$OPT/testssl.sh" ]; then
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$OPT/testssl.sh" >/dev/null 2>&1
    # testssl.sh shells out to hexdump (bsdextrautils). Extract the deb
    # so the wrapper can prepend the bundled /usr/bin to PATH.
    fetch_debs bsdextrautils
    cat > "$BIN/testssl.sh" <<EOF
#!/bin/sh
export PATH="$ROOT/usr/bin:\${PATH:-}"
exec bash "$OPT/testssl.sh/testssl.sh" "\$@"
EOF
    chmod +x "$BIN/testssl.sh"
    have openssl || warn "openssl not found — testssl.sh needs it"
    log "testssl.sh cloned + wrapper (with hexdump from bsdextrautils)"
else log "testssl.sh: present"; fi

# ---------------------------------------------------------------- whatweb ---
if [ ! -x "$ROOT/usr/bin/whatweb" ]; then
    fetch_debs whatweb ruby-addressable
    cat > "$BIN/whatweb" <<EOF
#!/bin/sh
R="$ROOT"
export LD_LIBRARY_PATH="\$R/usr/lib/x86_64-linux-gnu\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
export RUBYLIB="\$R/usr/lib/ruby/3.3.0:\$R/usr/lib/ruby:\$R/usr/lib/x86_64-linux-gnu/ruby/3.3.0:\$R/usr/lib/x86_64-linux-gnu/ruby:\$R/usr/share/whatweb/lib:\$R/usr/share/rubygems-integration/all/gems/addressable-2.8.7/lib:\$R/var/lib/gems/3.2.0:\$R/usr/lib/ruby/vendor_ruby:\$R/usr/lib/x86_64-linux-gnu/ruby/vendor_ruby"
export GEM_PATH="\$R/usr/lib/ruby/gems/3.3.0:\$R/usr/share/rubygems-integration/all:\$R/var/lib/gems/3.3.0\${GEM_PATH:+:\$GEM_PATH}"
export GEM_SPECIFICATION_DIR="\$R/usr/share/rubygems-integration/all/specifications\${GEM_SPECIFICATION_DIR:+:\$GEM_SPECIFICATION_DIR}"
export GEM_HOME=""
for r in \$R/usr/bin/ruby3.3 \$R/usr/bin/ruby3.2 \$R/usr/bin/ruby; do
  [ -x "\$r" ] && exec "\$r" "\$R/usr/bin/whatweb" "\$@"
done
echo "whatweb: no ruby interpreter found in \$R" >&2; exit 127
EOF
    chmod +x "$BIN/whatweb"
    log "whatweb extracted + wrapper (with ruby3.3, addressable gem, stdlib paths)"
else log "whatweb: present"; fi

# ---------------------------------------------------------------- wafw00f ---
if [ ! -x "$BIN/wafw00f" ]; then
    if have pip3 || python3 -m pip --version >/dev/null 2>&1; then
        python3 -m venv "$OPT/wafw00f-venv" 2>/dev/null || true
        "$OPT/wafw00f-venv/bin/pip" -q install wafw00f 2>/dev/null \
            && ln -sf "$OPT/wafw00f-venv/bin/wafw00f" "$BIN/wafw00f" \
            && log "wafw00f installed (venv)"
    else
        warn "pip unavailable — wafw00f not installed"
    fi
else log "wafw00f: present"; fi

# -------------------------------------------------------------- wordlists ---
if [ ! -f "$TOOLS/wordlists/common.txt" ]; then
    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/danielmiessler/SecLists.git "$OPT/SecLists" >/dev/null 2>&1 \
    && (cd "$OPT/SecLists" && git sparse-checkout set Discovery/Web-Content Discovery/DNS >/dev/null 2>&1 || true)
    ln -sf "$OPT/SecLists/Discovery/Web-Content/common.txt" "$TOOLS/wordlists/common.txt" 2>/dev/null || true
    ln -sf "$OPT/SecLists/Discovery/DNS/subdomains-top1million-5000.txt" "$TOOLS/wordlists/subdomains-5000.txt" 2>/dev/null || true
    log "SecLists wordlists linked"
else log "wordlists: present"; fi

# --------------------------------------------------------- v4.1.0 engines ---
# Seven additional power engines wired in v4.1.0 "Stronger Attack Vectors":
#   subzy        subdomain takeover (pentest-tools.com has nothing like this)
#   httpx        fast HTTP probe + tech fingerprint + title/status
#   katana       next-gen crawler (replaces legacy spiders)
#   naabu        fast port scanner (top ports in seconds, faster than nmap)
#   smuggler     HTTP request smuggling (CL.TE / TE.CL / TE.TE detection)
#   commix       command injection (auto-exploitation of OS-cmd-inj sinks)
#   gitleaks     secrets detection (AWS/GitHub/Slack/JWT/key patterns)
#
# All seven ship pre-built linux_amd64 Go binaries on GitHub releases, so the
# gh_asset helper handles them without per-tool ceremony.

install_go_binary() {
    # install_go_binary OWNER REPO BINARY_NAME ASSET_SUBSTR
    # Re-usable installer for Go-release binaries (one binary inside the archive).
    local owner="$1" repo="$2" bin="$3" substr="$4"
    if have "$bin" || [ -x "$OPT/$repo/$bin" ]; then
        log "$bin: present"
        return 0
    fi
    if gh_asset "$owner" "$repo" "$substr" "$OPT/$repo"; then
        # The asset may ship the binary at top level, in a versioned dir, or
        # under a config-style subdir -- walk the tree and symlink the first
        # executable we find.
        local found=""
        for b in "$OPT/$repo/$bin" "$OPT/$repo"/*/"$bin" "$OPT/$repo"/*/*/"$bin"; do
            if [ -x "$b" ] && [ -f "$b" ]; then found="$b"; break; fi
        done
        if [ -n "$found" ]; then
            ln -sfn "$found" "$BIN/$bin"
            log "$bin -> $found"
        else
            warn "$bin: asset extracted but binary not located"
        fi
    else
        warn "$bin install failed (no asset matched '$substr')"
    fi
}

# subzy -- L4ys/subzy: subdomain takeover checker (Go).
install_go_binary "L4ys" "subzy" "subzy" "linux_amd64"

# httpx -- projectdiscovery/httpx: fast HTTP probe + tech fingerprint.
# PD release naming convention: <tool>_<version>_linux_amd64.zip
install_go_binary "projectdiscovery" "httpx" "httpx" "linux_amd64.zip"

# katana -- projectdiscovery/katana: next-generation crawler.
install_go_binary "projectdiscovery" "katana" "katana" "linux_amd64.zip"

# naabu -- projectdiscovery/naabu: fast port scanner.
install_go_binary "projectdiscovery" "naabu" "naabu" "linux_amd64.zip"

# smuggler --defparam/smuggler: HTTP request smuggling scanner (Go).
# Releases ship as smuggler_Linux_x86_64.tar.gz with a single `smuggler` bin.
install_go_binary "defparam" "smuggler" "smuggler" "Linux_x86_64"

# commix -- commixproject/commix is Python; use the Go port
# 1N3/commix ships pre-built binaries since v3.7.
# Fallback: clone the python repo + python wrapper (like sqlmap).
if ! have commix && [ ! -d "$OPT/commix" ]; then
    git clone --depth 1 https://github.com/commixproject/commix.git "$OPT/commix" >/dev/null 2>&1 || warn "commix clone failed"
    cat > "$BIN/commix" <<EOF
#!/bin/sh
exec python3 "$OPT/commix/commix.py" --batch "\$@"
EOF
    chmod +x "$BIN/commix"
    log "commix cloned + wrapper (python3 + --batch)"
else log "commix: present"; fi

# gitleaks -- gitleaks/gitleaks: secrets detection (Go, single binary).
install_go_binary "gitleaks" "gitleaks" "gitleaks" "linux-amd64.tar.gz"

# ------------------------------------------------------------------ report ---
log "=========================================================="
log "tool availability (with $BIN on PATH):"
export PATH="$BIN:$PATH"
MISSING=0
for t in nmap nikto nuclei gobuster sqlmap whatweb ffuf subfinder dalfox testssl.sh wafw00f whois traceroute subzy httpx katana naabu smuggler commix gitleaks; do
    if have "$t"; then
        printf '  \033[1;32m%-12s OK\033[0m  (%s)\n' "$t" "$(command -v "$t")"
    else
        printf '  \033[1;31m%-12s MISSING\033[0m\n' "$t"
        MISSING=$((MISSING + 1))
    fi
done
log "wordlists: $(ls "$TOOLS/wordlists" 2>/dev/null | tr '\n' ' ')"
log "missing: $MISSING"
log "remember: PATH=\"$HOME/tools/bin:\$PATH\" before starting secuscan-server"

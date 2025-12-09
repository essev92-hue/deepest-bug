#!/bin/bash
# fix_setup.sh - Perbaiki semua masalah sekaligus

echo "[*] Memperbaiki setup scanning..."

# 1. Fix nama file config
if [ -f "config.yan1" ]; then
    echo "[+] Memperbaiki config.yan1 → config.yaml"
    mv config.yan1 config.yaml
elif [ -f "config.yanl" ]; then
    echo "[+] Memperbaiki config.yanl → config.yaml"
    mv config.yanl config.yaml
fi

# 2. Berikan permission yang benar
echo "[+] Memberikan permission executable"
chmod +x *.sh
chmod +x *.py 2>/dev/null

# 3. Buat struktur folder
echo "[+] Membuat struktur folder"
mkdir -p tools
mkdir -p scripts
mkdir -p configs
mkdir -p wordlists
mkdir -p targets/{recon,scan,results}
mkdir -p logs
mkdir -p reports
mkdir -p backups

# 4. Buat config.yaml jika tidak ada
if [ ! -f "config.yaml" ]; then
    echo "[+] Membuat config.yaml"
    cat > config.yaml << 'EOF'
# Konfigurasi Bug Hunting
scanning:
  threads: 30
  rate_limit: 100
  timeout: 10
  user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

tools:
  httpx:
    ports: "80,443,8080,8443,3000,8000"
    
  nuclei:
    severity: "medium,high,critical"
    exclude_tags: "intrusive,dos,brute"
    
  dalfox:
    blind: ""
    worker: 50
EOF
fi

# 5. Pindah script ke folder scripts
echo "[+] Mengorganisir script"
mv full_scan.sh scripts/ 2>/dev/null
mv passive_recon.sh scripts/ 2>/dev/null
mv install_all.sh scripts/ 2>/dev/null

# 6. Buat runner utama
echo "[+] Membuat scan runner"
cat > scan_runner.sh << 'EOF'
#!/bin/bash
# scan_runner.sh - Runner utama

DOMAIN=$1
MODE=$2

echo "======================================"
echo "   BUG HUNTING TOOLKIT v1.0"
echo "======================================"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [mode]"
    echo ""
    echo "Modes:"
    echo "  recon    - Passive reconnaissance only"
    echo "  scan     - Full scan (recon + vuln scan)"
    echo "  install  - Install all tools"
    echo ""
    echo "Example: $0 example.com recon"
    exit 1
fi

case $MODE in
    "recon")
        echo "[*] Mode: Passive Reconnaissance"
        ./scripts/passive_recon.sh $DOMAIN
        ;;
    "scan")
        echo "[*] Mode: Full Scan"
        ./scripts/full_scan.sh $DOMAIN
        ;;
    "install")
        echo "[*] Mode: Install Tools"
        ./scripts/install_all.sh
        ;;
    *)
        echo "[*] Mode: Auto (recon + quick scan)"
        ./scripts/passive_recon.sh $DOMAIN
        ./scripts/quick_scan.sh $DOMAIN
        ;;
esac

echo "[+] Selesai! Cek folder targets/ dan reports/"
EOF

chmod +x scan_runner.sh

# 7. Buat quick_scan.sh jika tidak ada
if [ ! -f "scripts/quick_scan.sh" ]; then
    cat > scripts/quick_scan.sh << 'EOF'
#!/bin/bash
# quick_scan.sh - Quick vulnerability scan

DOMAIN=$1
echo "[*] Quick scan untuk: $DOMAIN"

# Cek jika live hosts ada
if [ -f "targets/recon/live_hosts.txt" ]; then
    echo "[+] Menjalankan nuclei quick scan"
    ./tools/nuclei -l targets/recon/live_hosts.txt \
        -severity high,critical \
        -etags intrusive \
        -rate-limit 30 \
        -c 10 \
        -timeout 5 \
        -o targets/results/quick_scan.txt
        
    echo "[+] Hasil: targets/results/quick_scan.txt"
else
    echo "[!] File live_hosts.txt tidak ditemukan"
    echo "[!] Jalankan recon terlebih dahulu: ./scan_runner.sh $DOMAIN recon"
fi
EOF
    chmod +x scripts/quick_scan.sh
fi

echo "[+] Setup diperbaiki!"
echo "[+] Struktur folder:"
tree -L 2

echo ""
echo "[+] Cara penggunaan:"
echo "    1. Install tools:   ./scan_runner.sh example.com install"
echo "    2. Recon:           ./scan_runner.sh example.com recon"
echo "    3. Full scan:       ./scan_runner.sh example.com scan"

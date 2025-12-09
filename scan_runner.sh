#!/bin/bash
# scan_runner.sh - Bug Hunting Toolkit Runner

# Set working directory to script location
cd "$(dirname "$0")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_banner() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════╗"
    echo "║      BUG HUNTING TOOLKIT v1.0        ║"
    echo "║      Security Researcher Tools       ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
}

check_tools() {
    echo -e "${YELLOW}[*] Checking tools...${NC}"
    
    required_tools=("assetfinder" "subfinder" "httpx" "nuclei")
    missing=0
    
    for tool in "${required_tools[@]}"; do
        if [ -f "./tools/$tool" ]; then
            echo -e "  ${GREEN}✅ $tool${NC}"
        else
            echo -e "  ${RED}❌ $tool (missing)${NC}"
            missing=1
        fi
    done
    
    if [ $missing -eq 1 ]; then
        echo -e "${RED}[!] Some tools are missing. Run install first.${NC}"
        echo -e "${YELLOW}[*] Run: $0 <domain> install${NC}"
        exit 1
    fi
}

show_help() {
    echo -e "${YELLOW}Usage: $0 <domain> [mode]${NC}"
    echo ""
    echo "Available modes:"
    echo "  recon    - Passive reconnaissance (subdomain discovery)"
    echo "  scan     - Full vulnerability scan (nuclei)"
    echo "  quick    - Quick security assessment"
    echo "  full     - Complete pipeline (7 tools integration)"
    echo "  install  - Install/update all tools"
    echo "  tools    - Check tool status"
    echo ""
    echo "Examples:"
    echo "  $0 example.com recon"
    echo "  $0 example.com full"
    echo "  $0 example.com install"
}

run_full_pipeline() {
    DOMAIN=$1
    echo -e "${GREEN}[+] Starting FULL pipeline (7 tools)...${NC}"
    
    if [ ! -f "full_pipeline.sh" ]; then
        echo -e "${RED}[!] full_pipeline.sh not found${NC}"
        echo -e "${YELLOW}[*] Creating it now...${NC}"
        create_full_pipeline
    fi
    
    ./full_pipeline.sh "$DOMAIN"
}

create_full_pipeline() {
    cat > full_pipeline.sh << 'EOP'
#!/bin/bash
# full_pipeline.sh - Complete bug hunting pipeline with 7 tools

DOMAIN=\$1
if [ -z "\$DOMAIN" ]; then
    echo "Usage: \$0 <domain>"
    exit 1
fi

echo "🚀 COMPLETE BUG HUNTING PIPELINE - 7 TOOLS"
echo "=========================================="
echo "Target: \$DOMAIN"
echo "Start time: \$(date)"
echo ""

# 1. SUBFINDER
echo "[1/7] 🔍 Subfinder: Subdomain enumeration..."
./tools/subfinder -d \$DOMAIN -silent -o targets/recon/subfinder_\$DOMAIN.txt

# 2. ASSETFINDER
echo "[2/7] 🔍 Assetfinder: Additional assets..."
./tools/assetfinder --subs-only \$DOMAIN > targets/recon/assetfinder_\$DOMAIN.txt

# Merge results
cat targets/recon/*_\$DOMAIN.txt | sort -u > targets/recon/all_subs.txt
SUBS_COUNT=\$(wc -l < targets/recon/all_subs.txt)
echo "✅ Found \$SUBS_COUNT unique subdomains"

# 3. HTTPX - Find live hosts
echo "[3/7] 🌐 HTTPX: Finding live hosts..."
./tools/httpx -l targets/recon/all_subs.txt -silent -threads 20 \\
    -ports 80,443,8080,8443,3000 -o targets/recon/live_hosts.txt
LIVE_COUNT=\$(wc -l < targets/recon/live_hosts.txt 2>/dev/null || echo 0)
echo "✅ Found \$LIVE_COUNT live hosts"

# 4. KATANA - Crawling
echo "[4/7] 🕷️ Katana: Crawling URLs..."
if [ \$LIVE_COUNT -gt 0 ]; then
    cat targets/recon/live_hosts.txt | ./tools/katana -d 2 -jc -kf -c 10 \\
        -o targets/scan/crawled_urls.txt 2>/dev/null
    URLS_COUNT=\$(wc -l < targets/scan/crawled_urls.txt 2>/dev/null || echo 0)
    echo "✅ Crawled \$URLS_COUNT URLs"
else
    echo "⚠️  No live hosts to crawl"
    URLS_COUNT=0
fi

# 5. NUCLEI - Vulnerability scanning
echo "[5/7] 🎯 Nuclei: Vulnerability scanning..."
if [ \$LIVE_COUNT -gt 0 ]; then
    ./tools/nuclei -l targets/recon/live_hosts.txt \\
        -severity medium,high,critical \\
        -etags intrusive \\
        -rate-limit 30 \\
        -c 10 \\
        -o targets/results/nuclei_\$DOMAIN.txt
    NUCLEI_COUNT=\$(wc -l < targets/results/nuclei_\$DOMAIN.txt 2>/dev/null || echo 0)
    echo "✅ Found \$NUCLEI_COUNT potential vulnerabilities"
else
    echo "⚠️  No live hosts to scan"
    NUCLEI_COUNT=0
fi

# 6. DALFOX - XSS scanning
echo "[6/7] ✨ Dalfox: XSS scanning..."
if [ -f "targets/scan/crawled_urls.txt" ] && [ \$URLS_COUNT -gt 0 ]; then
    # Extract URLs with parameters
    grep "?" targets/scan/crawled_urls.txt > targets/scan/param_urls.txt 2>/dev/null
    PARAM_COUNT=\$(wc -l < targets/scan/param_urls.txt 2>/dev/null || echo 0)
    
    if [ \$PARAM_COUNT -gt 0 ]; then
        ./tools/dalfox file targets/scan/param_urls.txt \\
            --skip-bav \\
            --only-custom-payload \\
            -o targets/results/xss_\$DOMAIN.txt 2>/dev/null
        XSS_COUNT=\$(wc -l < targets/results/xss_\$DOMAIN.txt 2>/dev/null || echo 0)
        echo "✅ Checked \$PARAM_COUNT parameter URLs, found \$XSS_COUNT XSS issues"
    else
        echo "⚠️  No parameter URLs found for XSS testing"
        XSS_COUNT=0
    fi
else
    echo "⚠️  No crawled URLs for XSS testing"
    XSS_COUNT=0
fi

# 7. FFUF - Directory fuzzing (limited)
echo "[7/7] 🔎 FFUF: Quick directory fuzzing..."
if [ -f "targets/recon/live_hosts.txt" ] && [ \$LIVE_COUNT -gt 0 ]; then
    mkdir -p targets/results/ffuf/
    counter=0
    while read url && [ \$counter -lt 3 ]; do
        echo "   Scanning: \$url"
        domain_clean=\$(echo \$url | sed 's|[^a-zA-Z0-9]|_|g')
        ./tools/ffuf -u \$url/FUZZ \\
            -w wordlists/common.txt \\
            -t 5 \\
            -rate 10 \\
            -timeout 3 \\
            -mc 200,301,302 \\
            -o targets/results/ffuf/\${domain_clean}.json \\
            -quiet 2>/dev/null
        counter=\$((counter + 1))
    done < <(head -3 targets/recon/live_hosts.txt)
    echo "✅ Directory fuzzing completed for top 3 hosts"
else
    echo "⚠️  No live hosts for directory fuzzing"
fi

echo ""
echo "=========================================="
echo "🎉 PIPELINE COMPLETED!"
echo "⏰ End time: \$(date)"
echo ""
echo "📊 RESULTS SUMMARY:"
echo "   Subdomains found: \$SUBS_COUNT"
echo "   Live hosts: \$LIVE_COUNT"
echo "   Crawled URLs: \$URLS_COUNT"
echo "   Nuclei findings: \$NUCLEI_COUNT"
echo "   XSS findings: \$XSS_COUNT"
echo ""
echo "📁 Output folders:"
echo "   targets/recon/    - Reconnaissance data"
echo "   targets/scan/     - Crawled URLs"
echo "   targets/results/  - Vulnerability findings"
echo "=========================================="
EOP
    
    chmod +x full_pipeline.sh
    echo -e "${GREEN}[+] full_pipeline.sh created${NC}"
}

check_all_tools() {
    echo -e "${GREEN}[+] Checking all 7 tools...${NC}"
    echo ""
    
    declare -A tools
    tools=(
        ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
        ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
        ["ffuf"]="github.com/ffuf/ffuf@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    )
    
    for tool in "${!tools[@]}"; do
        echo -n "🔧 $tool: "
        if [ -f "tools/$tool" ]; then
            if [ -x "tools/$tool" ]; then
                echo -e "${GREEN}✅ READY${NC}"
            else
                echo -e "${YELLOW}⚠️  NOT EXECUTABLE${NC}"
                chmod +x tools/$tool 2>/dev/null && echo "   Fixed permissions"
            fi
        else
            echo -e "${RED}❌ MISSING${NC}"
            echo "   Install: go install ${tools[$tool]}"
        fi
    done
    
    echo ""
    echo "📊 Summary: $(ls tools/ 2>/dev/null | wc -l)/7 tools available"
}

main() {
    DOMAIN=$1
    MODE=$2
    
    print_banner
    
    if [ -z "$DOMAIN" ]; then
        show_help
        exit 1
    fi
    
    echo -e "${YELLOW}[*] Target:${NC} $DOMAIN"
    echo -e "${YELLOW}[*] Mode:${NC} ${MODE:-auto}"
    echo ""
    
    # Special modes
    case $MODE in
        "install")
            echo -e "${GREEN}[+] Installing/Updating tools...${NC}"
            ./scripts/install_all.sh
            exit 0
            ;;
        "tools")
            check_all_tools
            exit 0
            ;;
    esac
    
    # Check tools for scanning modes
    if [ "$MODE" != "install" ] && [ "$MODE" != "tools" ]; then
        check_tools
        echo ""
    fi
    
    # Main modes
    case $MODE in
        "recon")
            echo -e "${GREEN}[+] Starting reconnaissance...${NC}"
            ./scripts/passive_recon.sh "$DOMAIN"
            ;;
        "scan")
            echo -e "${GREEN}[+] Starting vulnerability scan...${NC}"
            ./scripts/full_scan.sh "$DOMAIN"
            ;;
        "quick")
            echo -e "${GREEN}[+] Starting quick scan...${NC}"
            ./scripts/quick_scan.sh "$DOMAIN"
            ;;
        "full")
            run_full_pipeline "$DOMAIN"
            ;;
        *)
            echo -e "${GREEN}[+] Starting auto mode (recon only)...${NC}"
            ./scripts/passive_recon.sh "$DOMAIN"
            ;;
    esac
    
    if [ "$MODE" != "install" ] && [ "$MODE" != "tools" ]; then
        echo ""
        echo -e "${GREEN}[+] Operation completed!${NC}"
        echo -e "${YELLOW}[*] Check results in:${NC}"
        [ -d "targets/recon" ] && echo "    - targets/recon/     : Reconnaissance data"
        [ -d "targets/results" ] && echo "    - targets/results/   : Vulnerability findings"
        [ -d "reports" ] && echo "    - reports/           : Generated reports"
    fi
}

main "$@"

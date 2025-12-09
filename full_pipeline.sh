#!/bin/bash
# full_pipeline.sh - Complete bug hunting pipeline with 7 tools

DOMAIN=$1
if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

echo "🚀 COMPLETE BUG HUNTING PIPELINE - 7 TOOLS"
echo "=========================================="
echo "Target: $DOMAIN"
echo "Start time: $(date)"
echo ""

# Create necessary directories
mkdir -p targets/{recon,scan,results} logs reports

# 1. SUBFINDER
echo "[1/7] 🔍 Subfinder: Subdomain enumeration..."
./tools/subfinder -d $DOMAIN -silent -o targets/recon/subfinder_$DOMAIN.txt

# 2. ASSETFINDER
echo "[2/7] 🔍 Assetfinder: Additional assets..."
./tools/assetfinder --subs-only $DOMAIN > targets/recon/assetfinder_$DOMAIN.txt

# Merge results
cat targets/recon/*_$DOMAIN.txt | sort -u > targets/recon/all_subs.txt
SUBS_COUNT=$(wc -l < targets/recon/all_subs.txt)
echo "✅ Found $SUBS_COUNT unique subdomains"

# 3. HTTPX - Find live hosts
echo "[3/7] 🌐 HTTPX: Finding live hosts..."
./tools/httpx -l targets/recon/all_subs.txt -silent -threads 20 \
    -ports 80,443,8080,8443,3000 -o targets/recon/live_hosts.txt
LIVE_COUNT=$(wc -l < targets/recon/live_hosts.txt 2>/dev/null || echo 0)
echo "✅ Found $LIVE_COUNT live hosts"

# 4. KATANA - Crawling (FIXED PARAMETERS)
echo "[4/7] 🕷️ Katana: Crawling URLs..."
if [ $LIVE_COUNT -gt 0 ]; then
    # Fixed katana parameters
    cat targets/recon/live_hosts.txt | ./tools/katana \
        -d 2 \
        -jc \
        -kf all \
        -c 10 \
        -silent \
        -o targets/scan/crawled_urls.txt
    
    if [ $? -eq 0 ] && [ -f "targets/scan/crawled_urls.txt" ]; then
        URLS_COUNT=$(wc -l < targets/scan/crawled_urls.txt)
        echo "✅ Crawled $URLS_COUNT URLs"
    else
        echo "⚠️  Katana crawling failed or no URLs found"
        URLS_COUNT=0
        touch targets/scan/crawled_urls.txt
    fi
else
    echo "⚠️  No live hosts to crawl"
    URLS_COUNT=0
    touch targets/scan/crawled_urls.txt
fi

# 5. NUCLEI - Vulnerability scanning
echo "[5/7] 🎯 Nuclei: Vulnerability scanning..."
if [ $LIVE_COUNT -gt 0 ]; then
    echo "   Scanning with nuclei (medium+ severity)..."
    ./tools/nuclei -l targets/recon/live_hosts.txt \
        -severity medium,high,critical \
        -etags intrusive \
        -rate-limit 30 \
        -c 10 \
        -silent \
        -o targets/results/nuclei_$DOMAIN.txt
    
    if [ -f "targets/results/nuclei_$DOMAIN.txt" ]; then
        NUCLEI_COUNT=$(wc -l < targets/results/nuclei_$DOMAIN.txt)
        echo "✅ Found $NUCLEI_COUNT potential vulnerabilities"
        
        # Show top findings
        if [ $NUCLEI_COUNT -gt 0 ]; then
            echo "   Top findings:"
            head -3 targets/results/nuclei_$DOMAIN.txt | while read line; do
                echo "   • $(echo $line | cut -d' ' -f1)"
            done
        fi
    else
        echo "✅ No critical vulnerabilities found"
        NUCLEI_COUNT=0
    fi
else
    echo "⚠️  No live hosts to scan"
    NUCLEI_COUNT=0
fi

# 6. DALFOX - XSS scanning
echo "[6/7] ✨ Dalfox: XSS scanning..."
if [ -f "targets/scan/crawled_urls.txt" ] && [ $URLS_COUNT -gt 0 ]; then
    # Extract URLs with parameters
    grep "?" targets/scan/crawled_urls.txt > targets/scan/param_urls.txt 2>/dev/null
    PARAM_COUNT=$(wc -l < targets/scan/param_urls.txt 2>/dev/null || echo 0)
    
    if [ $PARAM_COUNT -gt 0 ]; then
        echo "   Testing $PARAM_COUNT parameterized URLs..."
        ./tools/dalfox file targets/scan/param_urls.txt \
            --skip-bav \
            --only-custom-payload \
            --silence \
            -o targets/results/xss_$DOMAIN.txt
        
        if [ -f "targets/results/xss_$DOMAIN.txt" ]; then
            XSS_COUNT=$(wc -l < targets/results/xss_$DOMAIN.txt)
            echo "✅ Found $XSS_COUNT XSS issues"
        else
            echo "✅ No XSS vulnerabilities found"
            XSS_COUNT=0
        fi
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
if [ -f "targets/recon/live_hosts.txt" ] && [ $LIVE_COUNT -gt 0 ]; then
    mkdir -p targets/results/ffuf/
    counter=0
    
    # Use common wordlist or create minimal one
    if [ ! -f "wordlists/common.txt" ]; then
        echo "   Creating minimal wordlist..."
        mkdir -p wordlists
        echo -e "admin\napi\ndashboard\nlogin\nwp-admin\nphpmyadmin\ntest\ndev" > wordlists/common.txt
    fi
    
    echo "   Scanning top 2 hosts..."
    while read url && [ $counter -lt 2 ]; do
        echo "     → $url"
        domain_clean=$(echo $url | sed 's|[^a-zA-Z0-9]|_|g')
        
        ./tools/ffuf -u $url/FUZZ \
            -w wordlists/common.txt \
            -t 5 \
            -rate 5 \
            -timeout 3 \
            -mc 200,301,302,403 \
            -o targets/results/ffuf/${domain_clean}.json \
            -of json \
            -quiet 2>/dev/null
        
        if [ -f "targets/results/ffuf/${domain_clean}.json" ]; then
            results=$(jq '.results | length' targets/results/ffuf/${domain_clean}.json 2>/dev/null || echo 0)
            echo "       Found $results directories"
        fi
        
        counter=$((counter + 1))
        sleep 1
    done < <(head -2 targets/recon/live_hosts.txt)
    
    echo "✅ Directory fuzzing completed"
else
    echo "⚠️  No live hosts for directory fuzzing"
fi

echo ""
echo "=========================================="
echo "🎉 PIPELINE COMPLETED!"
echo "⏰ End time: $(date)"
echo ""
echo "📊 RESULTS SUMMARY:"
echo "   • Subdomains found: $SUBS_COUNT"
echo "   • Live hosts: $LIVE_COUNT"
echo "   • Crawled URLs: $URLS_COUNT"
echo "   • Nuclei findings: $NUCLEI_COUNT"
echo "   • XSS findings: $XSS_COUNT"
echo ""
echo "📁 Output locations:"
echo "   • Recon data: targets/recon/"
echo "   • Crawled URLs: targets/scan/crawled_urls.txt"
echo "   • Findings: targets/results/"
echo ""
echo "🔍 Next steps:"
echo "   • Review nuclei findings: cat targets/results/nuclei_$DOMAIN.txt"
echo "   • Check for sensitive files in crawled URLs"
echo "   • Manual testing on interesting endpoints"
echo "=========================================="

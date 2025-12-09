#!/bin/bash
# scan.sh - Wrapper utama

DOMAIN=$1
MODE=$2

case $MODE in
    "recon")
        echo "[*] Running reconnaissance only"
        ./scripts/passive_recon.sh $DOMAIN
        ;;
    "scan")
        echo "[*] Running full scan"
        ./scripts/full_scan.sh $DOMAIN
        ;;
    "quick")
        echo "[*] Running quick scan"
        ./scripts/quick_scan.sh $DOMAIN
        ;;
    *)
        echo "Usage: $0 <domain> [recon|scan|quick]"
        echo "Examples:"
        echo "  $0 example.com recon    # Passive recon only"
        echo "  $0 example.com scan     # Full scan"
        echo "  $0 example.com quick    # Quick assessment"
        exit 1
        ;;
esac

#!/usr/bin/env python3
"""
bug_hunter.py - Pipeline Bug Hunting Terintegrasi
Author: Security Researcher
"""

import os
import sys
import json
import yaml
import subprocess
from datetime import datetime
from pathlib import Path

class BugHunter:
    def __init__(self, domain):
        self.domain = domain
        self.base_dir = Path(".")
        self.setup_directories()
        self.load_config()
        
    def setup_directories(self):
        """Setup struktur direktori"""
        dirs = [
            "targets/recon",
            "targets/scan", 
            "targets/results",
            "logs",
            "reports",
            "backups"
        ]
        
        for dir_path in dirs:
            (self.base_dir / dir_path).mkdir(parents=True, exist_ok=True)
            
    def load_config(self):
        """Load konfigurasi dari file"""
        config_path = self.base_dir / "config.yaml"
        if config_path.exists():
            with open(config_path) as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {
                "threads": 30,
                "rate_limit": 100
            }
    
    def run_command(self, cmd, output_file=None):
        """Jalankan command dengan logging"""
        log_file = self.base_dir / f"logs/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        with open(log_file, 'a') as log:
            log.write(f"[{datetime.now()}] Command: {cmd}\n")
            
            if output_file:
                with open(output_file, 'w') as out:
                    process = subprocess.Popen(
                        cmd, shell=True, stdout=out, stderr=log, text=True
                    )
            else:
                process = subprocess.Popen(
                    cmd, shell=True, stdout=subprocess.PIPE, stderr=log, text=True
                )
                output, _ = process.communicate()
                return output
                
            process.wait()
    
    def passive_recon(self):
        """Fase reconnaissance pasif"""
        print("[*] Starting passive reconnaissance")
        
        # Assetfinder
        self.run_command(
            f"./tools/assetfinder --subs-only {self.domain}",
            self.base_dir / "targets/recon/assetfinder.txt"
        )
        
        # Subfinder
        self.run_command(
            f"./tools/subfinder -d {self.domain} -silent",
            self.base_dir / "targets/recon/subfinder.txt"
        )
        
        # Merge results
        subdomains = set()
        for file in ["assetfinder.txt", "subfinder.txt"]:
            file_path = self.base_dir / f"targets/recon/{file}"
            if file_path.exists():
                with open(file_path) as f:
                    subdomains.update(f.read().splitlines())
        
        # Save unique subdomains
        with open(self.base_dir / "targets/recon/all_subs.txt", "w") as f:
            f.write("\n".join(sorted(subdomains)))
        
        print(f"[+] Found {len(subdomains)} subdomains")
        return list(subdomains)
    
    def find_live_hosts(self, subdomains):
        """Cari host yang hidup"""
        print("[*] Finding live hosts")
        
        subs_file = self.base_dir / "targets/recon/all_subs.txt"
        live_hosts = self.base_dir / "targets/recon/live_hosts.txt"
        
        self.run_command(
            f"cat {subs_file} | ./tools/httpx -silent -threads 30 -timeout 3 "
            f"-ports 80,443,8080,8443,3000 -o {live_hosts}"
        )
        
        # Count live hosts
        if live_hosts.exists():
            with open(live_hosts) as f:
                count = len(f.read().splitlines())
                print(f"[+] Found {count} live hosts")
    
    def crawl_urls(self):
        """Crawl URLs dengan Katana"""
        print("[*] Crawling URLs")
        
        live_hosts = self.base_dir / "targets/recon/live_hosts.txt"
        katana_output = self.base_dir / "targets/scan/katana_urls.txt"
        
        if live_hosts.exists():
            self.run_command(
                f"cat {live_hosts} | ./tools/katana -d 3 -jc -kf -c 20 -o {katana_output}"
            )
    
    def run_nuclei_scan(self):
        """Scan dengan Nuclei (aman)"""
        print("[*] Running Nuclei scan")
        
        live_hosts = self.base_dir / "targets/recon/live_hosts.txt"
        nuclei_output = self.base_dir / "targets/results/nuclei_findings.txt"
        
        if live_hosts.exists():
            self.run_command(
                f"./tools/nuclei -l {live_hosts} -severity medium,high,critical "
                f"-etags intrusive,dos,brute -rate-limit 50 -c 20 -timeout 5 "
                f"-o {nuclei_output}"
            )
    
    def run_xss_scan(self):
        """Scan XSS dengan Dalfox"""
        print("[*] Running XSS scan")
        
        katana_urls = self.base_dir / "targets/scan/katana_urls.txt"
        xss_output = self.base_dir / "targets/results/xss_findings.txt"
        
        if katana_urls.exists():
            self.run_command(
                f"cat {katana_urls} | ./tools/dalfox pipe --skip-bav "
                f"--only-custom-payload --skip-grepping -o {xss_output}"
            )
    
    def generate_report(self):
        """Generate laporan akhir"""
        print("[*] Generating report")
        
        report_file = self.base_dir / f"reports/report_{self.domain}_{datetime.now().strftime('%Y%m%d')}.md"
        
        with open(report_file, 'w') as f:
            f.write(f"# Bug Hunting Report\n")
            f.write(f"## Domain: {self.domain}\n")
            f.write(f"## Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Subdomains section
            subs_file = self.base_dir / "targets/recon/all_subs.txt"
            if subs_file.exists():
                with open(subs_file) as sf:
                    subs = sf.read().splitlines()
                    f.write(f"## Subdomains Found: {len(subs)}\n")
                    for sub in subs[:50]:  # Tampilkan 50 pertama
                        f.write(f"- {sub}\n")
            
            # Nuclei findings
            nuclei_file = self.base_dir / "targets/results/nuclei_findings.txt"
            if nuclei_file.exists():
                f.write("\n## Critical Findings\n")
                with open(nuclei_file) as nf:
                    for line in nf:
                        if any(sev in line.lower() for sev in ["critical", "high"]):
                            f.write(f"- {line}")
            
            # XSS findings
            xss_file = self.base_dir / "targets/results/xss_findings.txt"
            if xss_file.exists():
                f.write("\n## XSS Findings\n")
                with open(xss_file) as xf:
                    f.write(xf.read())
        
        print(f"[+] Report saved to: {report_file}")
    
    def run(self):
        """Jalankan pipeline lengkap"""
        print(f"[*] Starting bug hunting for: {self.domain}")
        
        # Phase 1: Recon
        subdomains = self.passive_recon()
        self.find_live_hosts(subdomains)
        
        # Phase 2: Crawling
        self.crawl_urls()
        
        # Phase 3: Scanning
        self.run_nuclei_scan()
        self.run_xss_scan()
        
        # Phase 4: Reporting
        self.generate_report()
        
        print("[+] Bug hunting completed!")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python bug_hunter.py <domain>")
        sys.exit(1)
    
    hunter = BugHunter(sys.argv[1])
    hunter.run()

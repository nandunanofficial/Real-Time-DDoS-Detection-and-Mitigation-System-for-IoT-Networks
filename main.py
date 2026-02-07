#!/usr/bin/env python3
"""
Information Security Analysis and Audit Tool
Main entry point for comprehensive security assessment
"""

import os
import sys
import argparse
import json
from datetime import datetime

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from vulnerability_scanner.scanner import VulnerabilityScanner
from security_audit.auditor import SecurityAuditor
from risk_assessment.assessor import RiskAssessor
from reporting.report_generator import SecurityReportGenerator

class InformationSecurityTool:
    def __init__(self):
        self.scanner = None
        self.auditor = SecurityAuditor()
        self.assessor = RiskAssessor()
        self.report_generator = SecurityReportGenerator()
        self.results_dir = "results"
        
        # Create results directory
        os.makedirs(self.results_dir, exist_ok=True)
    
    def run_vulnerability_scan(self, target: str) -> str:
        """Run vulnerability assessment"""
        print(f"[*] Starting vulnerability scan for {target}...")
        
        self.scanner = VulnerabilityScanner(target)
        self.scanner.port_scan()
        self.scanner.ssl_certificate_check()
        self.scanner.web_vulnerability_check()
        
        # Save results
        filename = os.path.join(self.results_dir, self.scanner.save_results())
        print(f"[+] Vulnerability scan completed: {filename}")
        
        return filename
    
    def run_security_audit(self) -> str:
        """Run security audit"""
        print("[*] Starting security audit...")
        
        self.auditor.gather_system_info()
        self.auditor.check_file_permissions()
        self.auditor.check_password_policy()
        self.auditor.check_network_security()
        self.auditor.check_software_updates()
        self.auditor.generate_compliance_report()
        self.auditor.generate_recommendations()
        
        # Save results
        filename = os.path.join(self.results_dir, self.auditor.save_audit_results())
        print(f"[+] Security audit completed: {filename}")
        
        return filename
    
    def run_risk_assessment(self) -> str:
        """Run risk assessment"""
        print("[*] Starting risk assessment...")
        
        self.assessor.perform_risk_analysis()
        self.assessor.develop_mitigation_strategies()
        self.assessor.calculate_residual_risks()
        
        # Save results
        filename = os.path.join(self.results_dir, self.assessor.save_assessment_results())
        print(f"[+] Risk assessment completed: {filename}")
        
        return filename
    
    def generate_comprehensive_report(self, vuln_file: str = None, 
                                    audit_file: str = None, 
                                    risk_file: str = None) -> tuple:
        """Generate comprehensive security report"""
        print("[*] Generating comprehensive security report...")
        
        # Load scan results
        scan_data = self.report_generator.load_scan_results(vuln_file, audit_file, risk_file)
        
        # Generate report components
        self.report_generator.generate_executive_summary(scan_data)
        self.report_generator.generate_detailed_findings(scan_data)
        self.report_generator.generate_compliance_matrix(scan_data)
        self.report_generator.generate_recommendations(
            self.report_generator.report_data['detailed_findings']
        )
        
        # Generate reports
        html_file = os.path.join(self.results_dir, 
                                self.report_generator.generate_html_report())
        markdown_file = os.path.join(self.results_dir, 
                                   self.report_generator.generate_markdown_report())
        
        print(f"[+] HTML report generated: {html_file}")
        print(f"[+] Markdown report generated: {markdown_file}")
        
        return html_file, markdown_file
    
    def run_full_assessment(self, target: str = None) -> dict:
        """Run complete security assessment"""
        print("=" * 60)
        print("INFORMATION SECURITY ANALYSIS AND AUDIT")
        print("=" * 60)
        
        results = {}
        
        # Run vulnerability scan if target provided
        if target:
            results['vulnerability'] = self.run_vulnerability_scan(target)
        
        # Run security audit
        results['audit'] = self.run_security_audit()
        
        # Run risk assessment
        results['risk_assessment'] = self.run_risk_assessment()
        
        # Generate comprehensive report
        html_report, markdown_report = self.generate_comprehensive_report(
            results.get('vulnerability'),
            results['audit'],
            results['risk_assessment']
        )
        
        results['html_report'] = html_report
        results['markdown_report'] = markdown_report
        
        print("\n" + "=" * 60)
        print("ASSESSMENT COMPLETED")
        print("=" * 60)
        print("Results saved in 'results' directory:")
        for key, value in results.items():
            print(f"  - {key}: {os.path.basename(value)}")
        
        return results

def main():
    parser = argparse.ArgumentParser(
        description="Information Security Analysis and Audit Tool"
    )
    
    parser.add_argument(
        '--target', '-t',
        help='Target for vulnerability scan (IP address or domain)'
    )
    
    parser.add_argument(
        '--vulnerability', '-v',
        action='store_true',
        help='Run vulnerability scan only'
    )
    
    parser.add_argument(
        '--audit', '-a',
        action='store_true',
        help='Run security audit only'
    )
    
    parser.add_argument(
        '--risk', '-r',
        action='store_true',
        help='Run risk assessment only'
    )
    
    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate report from existing results'
    )
    
    parser.add_argument(
        '--full', '-f',
        action='store_true',
        help='Run full security assessment'
    )
    
    args = parser.parse_args()
    
    tool = InformationSecurityTool()
    
    try:
        if args.full:
            tool.run_full_assessment(args.target)
        elif args.vulnerability:
            if not args.target:
                print("Error: Target required for vulnerability scan")
                sys.exit(1)
            tool.run_vulnerability_scan(args.target)
        elif args.audit:
            tool.run_security_audit()
        elif args.risk:
            tool.run_risk_assessment()
        elif args.report:
            tool.generate_comprehensive_report()
        else:
            # Default: run full assessment
            tool.run_full_assessment(args.target)
            
    except KeyboardInterrupt:
        print("\n[!] Assessment interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error during assessment: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

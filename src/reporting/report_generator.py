#!/usr/bin/env python3
"""
Report Generator Module
Generates comprehensive security analysis and audit reports
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from jinja2 import Template

class SecurityReportGenerator:
    def __init__(self):
        self.report_data = {
            'report_metadata': {
                'generated_date': datetime.now().isoformat(),
                'report_version': '1.0',
                'organization': 'Security Analysis Team'
            },
            'executive_summary': {},
            'vulnerability_findings': [],
            'audit_results': {},
            'risk_assessment': {},
            'compliance_status': {},
            'recommendations': [],
            'appendices': {}
        }
    
    def load_scan_results(self, vulnerability_file: str = None, audit_file: str = None, 
                         risk_file: str = None) -> Dict[str, Any]:
        """Load results from various security scans"""
        loaded_data = {}
        
        if vulnerability_file and os.path.exists(vulnerability_file):
            with open(vulnerability_file, 'r') as f:
                loaded_data['vulnerability_scan'] = json.load(f)
        
        if audit_file and os.path.exists(audit_file):
            with open(audit_file, 'r') as f:
                loaded_data['security_audit'] = json.load(f)
        
        if risk_file and os.path.exists(risk_file):
            with open(risk_file, 'r') as f:
                loaded_data['risk_assessment'] = json.load(f)
        
        return loaded_data
    
    def generate_executive_summary(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of security posture"""
        summary = {
            'overall_risk_level': 'Medium',
            'critical_findings': 0,
            'high_risk_findings': 0,
            'medium_risk_findings': 0,
            'low_risk_findings': 0,
            'compliance_score': 75,
            'security_posture': 'Moderate',
            'key_metrics': {}
        }
        
        # Analyze vulnerability data
        if 'vulnerability_scan' in scan_data:
            vuln_data = scan_data['vulnerability_scan']
            web_vulns = vuln_data.get('web_vulnerabilities', [])
            
            for vuln in web_vulns:
                severity = vuln.get('severity', 'Low').lower()
                if severity == 'critical':
                    summary['critical_findings'] += 1
                elif severity == 'high':
                    summary['high_risk_findings'] += 1
                elif severity == 'medium':
                    summary['medium_risk_findings'] += 1
                else:
                    summary['low_risk_findings'] += 1
        
        # Analyze audit data
        if 'security_audit' in scan_data:
            audit_data = scan_data['security_audit']
            security_checks = audit_data.get('security_checks', {})
            
            file_perm_issues = len(security_checks.get('file_permissions', []))
            summary['key_metrics']['file_permission_issues'] = file_perm_issues
            
            firewall_status = security_checks.get('network_security', {}).get('firewall_status', 'Unknown')
            summary['key_metrics']['firewall_status'] = firewall_status
        
        # Analyze risk assessment data
        if 'risk_assessment' in scan_data:
            risk_data = scan_data['risk_assessment']
            risks = risk_data.get('risks_identified', [])
            
            critical_risks = len([r for r in risks if r.get('risk_level') == 'CRITICAL'])
            high_risks = len([r for r in risks if r.get('risk_level') == 'HIGH'])
            
            summary['key_metrics']['critical_risks'] = critical_risks
            summary['key_metrics']['high_risks'] = high_risks
        
        # Calculate overall risk level
        total_findings = (summary['critical_findings'] + summary['high_risk_findings'] + 
                         summary['medium_risk_findings'] + summary['low_risk_findings'])
        
        if summary['critical_findings'] > 0 or summary['high_risk_findings'] > 5:
            summary['overall_risk_level'] = 'Critical'
            summary['security_posture'] = 'Poor'
        elif summary['high_risk_findings'] > 2 or summary['medium_risk_findings'] > 10:
            summary['overall_risk_level'] = 'High'
            summary['security_posture'] = 'Weak'
        elif summary['medium_risk_findings'] > 5:
            summary['overall_risk_level'] = 'Medium'
            summary['security_posture'] = 'Moderate'
        else:
            summary['overall_risk_level'] = 'Low'
            summary['security_posture'] = 'Strong'
        
        self.report_data['executive_summary'] = summary
        return summary
    
    def generate_detailed_findings(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate detailed findings from all scans"""
        detailed_findings = []
        
        # Process vulnerability findings
        if 'vulnerability_scan' in scan_data:
            vuln_data = scan_data['vulnerability_scan']
            
            # Port scan findings
            open_ports = vuln_data.get('open_ports', [])
            if open_ports:
                detailed_findings.append({
                    'category': 'Network Security',
                    'finding_type': 'Open Ports',
                    'severity': 'Medium',
                    'description': f'Open ports detected: {", ".join(map(str, open_ports))}',
                    'recommendation': 'Review and close unnecessary open ports',
                    'evidence': open_ports
                })
            
            # SSL certificate findings
            ssl_info = vuln_data.get('ssl_info', {})
            if ssl_info:
                detailed_findings.append({
                    'category': 'Encryption',
                    'finding_type': 'SSL Certificate',
                    'severity': 'Low',
                    'description': 'SSL certificate information gathered',
                    'recommendation': 'Ensure SSL certificates are valid and up-to-date',
                    'evidence': ssl_info
                })
            
            # Web vulnerabilities
            web_vulns = vuln_data.get('web_vulnerabilities', [])
            for vuln in web_vulns:
                detailed_findings.append({
                    'category': 'Web Security',
                    'finding_type': vuln.get('type', 'Unknown'),
                    'severity': vuln.get('severity', 'Low'),
                    'description': vuln.get('description', ''),
                    'recommendation': 'Address web security vulnerabilities',
                    'evidence': vuln
                })
        
        # Process audit findings
        if 'security_audit' in scan_data:
            audit_data = scan_data['security_audit']
            security_checks = audit_data.get('security_checks', {})
            
            # File permission issues
            file_issues = security_checks.get('file_permissions', [])
            if file_issues:
                detailed_findings.append({
                    'category': 'Access Control',
                    'finding_type': 'File Permissions',
                    'severity': 'Medium',
                    'description': f'File permission issues detected: {len(file_issues)} issues',
                    'recommendation': 'Review and correct file permissions',
                    'evidence': file_issues
                })
            
            # Password policy issues
            password_policy = security_checks.get('password_policy', {})
            if not password_policy.get('min_length_check', False):
                detailed_findings.append({
                    'category': 'Authentication',
                    'finding_type': 'Password Policy',
                    'severity': 'Medium',
                    'description': 'Weak or missing password policy',
                    'recommendation': 'Implement strong password policies',
                    'evidence': password_policy
                })
        
        # Process risk assessment findings
        if 'risk_assessment' in scan_data:
            risk_data = scan_data['risk_assessment']
            risks = risk_data.get('risks_identified', [])
            
            # Top risks
            top_risks = sorted(risks, key=lambda x: x.get('risk_score', 0), reverse=True)[:10]
            for risk in top_risks:
                detailed_findings.append({
                    'category': 'Risk Management',
                    'finding_type': 'Security Risk',
                    'severity': risk.get('risk_level', 'Low'),
                    'description': risk.get('risk_scenario', ''),
                    'recommendation': 'Implement risk mitigation strategies',
                    'evidence': risk
                })
        
        self.report_data['detailed_findings'] = detailed_findings
        return detailed_findings
    
    def generate_compliance_matrix(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance matrix against security standards"""
        compliance_matrix = {
            'cis_controls': {
                'status': 'Partially Compliant',
                'score': 65,
                'findings': []
            },
            'nist_framework': {
                'status': 'Partially Compliant',
                'score': 70,
                'findings': []
            },
            'iso27001': {
                'status': 'Not Assessed',
                'score': 0,
                'findings': []
            },
            'gdpr': {
                'status': 'Not Assessed',
                'score': 0,
                'findings': []
            }
        }
        
        # CIS Controls assessment
        if 'security_audit' in scan_data:
            audit_data = scan_data['security_audit']
            compliance_status = audit_data.get('compliance_status', {})
            
            if 'cis_benchmarks' in compliance_status:
                cis_status = compliance_status['cis_benchmarks']
                if cis_status == 'Compliant':
                    compliance_matrix['cis_controls']['score'] = 90
                    compliance_matrix['cis_controls']['status'] = 'Compliant'
                elif cis_status == 'Partially Compliant':
                    compliance_matrix['cis_controls']['score'] = 65
                    compliance_matrix['cis_controls']['status'] = 'Partially Compliant'
                else:
                    compliance_matrix['cis_controls']['score'] = 30
                    compliance_matrix['cis_controls']['status'] = 'Non-Compliant'
        
        self.report_data['compliance_status'] = compliance_matrix
        return compliance_matrix
    
    def generate_recommendations(self, detailed_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Categorize recommendations by severity
        critical_findings = [f for f in detailed_findings if f.get('severity') == 'Critical']
        high_findings = [f for f in detailed_findings if f.get('severity') == 'High']
        medium_findings = [f for f in detailed_findings if f.get('severity') == 'Medium']
        
        # Immediate recommendations (Critical/High)
        if critical_findings or high_findings:
            recommendations.append({
                'priority': 'Immediate',
                'category': 'Critical Security Issues',
                'recommendations': [
                    'Address all critical and high-severity vulnerabilities immediately',
                    'Implement emergency security controls',
                    'Enhance monitoring and alerting',
                    'Prepare incident response procedures'
                ],
                'timeline': '0-7 days',
                'resources': 'High',
                'impact': 'Critical'
            })
        
        # Short-term recommendations (Medium)
        if medium_findings:
            recommendations.append({
                'priority': 'Short-term',
                'category': 'Security Improvements',
                'recommendations': [
                    'Implement comprehensive security policies',
                    'Enhance access controls',
                    'Conduct security awareness training',
                    'Regular vulnerability scanning'
                ],
                'timeline': '30 days',
                'resources': 'Medium',
                'impact': 'High'
            })
        
        # Long-term recommendations
        recommendations.append({
            'priority': 'Long-term',
            'category': 'Security Program Development',
            'recommendations': [
                'Develop comprehensive security governance framework',
                'Implement continuous monitoring program',
                'Regular security assessments and audits',
                'Security awareness and training program'
            ],
            'timeline': '90-180 days',
            'resources': 'Medium to High',
            'impact': 'Strategic'
        })
        
        self.report_data['recommendations'] = recommendations
        return recommendations
    
    def generate_html_report(self, output_file: str = None) -> str:
        """Generate comprehensive HTML report"""
        if output_file is None:
            output_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .summary { background-color: #f4f4f4; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #fbc02d; font-weight: bold; }
        .low { color: #388e3c; font-weight: bold; }
        .finding { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .recommendation { background-color: #e3f2fd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        .risk-critical { background-color: #ffebee; }
        .risk-high { background-color: #fff3e0; }
        .risk-medium { background-color: #fffde7; }
        .risk-low { background-color: #e8f5e8; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Analysis and Audit Report</h1>
        <p>Generated on: {{ report_metadata.generated_date }}</p>
        <p>Organization: {{ report_metadata.organization }}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Overall Risk Level:</strong> 
        <span class="{{ executive_summary.overall_risk_level.lower() }}">
        {{ executive_summary.overall_risk_level }}</span></p>
        <p><strong>Security Posture:</strong> {{ executive_summary.security_posture }}</p>
        <p><strong>Compliance Score:</strong> {{ executive_summary.compliance_score }}/100</p>
        
        <h3>Findings Summary</h3>
        <ul>
            <li>Critical Findings: <span class="critical">{{ executive_summary.critical_findings }}</span></li>
            <li>High Risk Findings: <span class="high">{{ executive_summary.high_risk_findings }}</span></li>
            <li>Medium Risk Findings: <span class="medium">{{ executive_summary.medium_risk_findings }}</span></li>
            <li>Low Risk Findings: <span class="low">{{ executive_summary.low_risk_findings }}</span></li>
        </ul>
    </div>

    <h2>Detailed Findings</h2>
    {% for finding in detailed_findings %}
    <div class="finding">
        <h3>{{ finding.finding_type }}</h3>
        <p><strong>Category:</strong> {{ finding.category }}</p>
        <p><strong>Severity:</strong> <span class="{{ finding.severity.lower() }}">{{ finding.severity }}</span></p>
        <p><strong>Description:</strong> {{ finding.description }}</p>
        <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
    </div>
    {% endfor %}

    <h2>Compliance Status</h2>
    <table>
        <tr>
            <th>Standard</th>
            <th>Status</th>
            <th>Score</th>
        </tr>
        {% for standard, data in compliance_status.items() %}
        <tr>
            <td>{{ standard.upper() }}</td>
            <td>{{ data.status }}</td>
            <td>{{ data.score }}/100</td>
        </tr>
        {% endfor %}
    </table>

    <h2>Recommendations</h2>
    {% for rec in recommendations %}
    <div class="recommendation">
        <h3>{{ rec.priority }} - {{ rec.category }}</h3>
        <p><strong>Timeline:</strong> {{ rec.timeline }}</p>
        <p><strong>Resources Required:</strong> {{ rec.resources }}</p>
        <p><strong>Expected Impact:</strong> {{ rec.impact }}</p>
        <ul>
            {% for recommendation in rec.recommendations %}
            <li>{{ recommendation }}</li>
            {% endfor %}
        </ul>
    </div>
    {% endfor %}

    <div class="footer">
        <p><em>This report was generated automatically by the Security Analysis Tool</em></p>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        html_content = template.render(**self.report_data)
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return output_file
    
    def generate_markdown_report(self, output_file: str = None) -> str:
        """Generate comprehensive Markdown report"""
        if output_file is None:
            output_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        markdown_content = f"""# Security Analysis and Audit Report

**Generated:** {self.report_data['report_metadata']['generated_date']}  
**Organization:** {self.report_data['report_metadata']['organization']}

## Executive Summary

**Overall Risk Level:** {self.report_data['executive_summary']['overall_risk_level']}  
**Security Posture:** {self.report_data['executive_summary']['security_posture']}  
**Compliance Score:** {self.report_data['executive_summary']['compliance_score']}/100

### Findings Summary
- **Critical Findings:** {self.report_data['executive_summary']['critical_findings']}
- **High Risk Findings:** {self.report_data['executive_summary']['high_risk_findings']}
- **Medium Risk Findings:** {self.report_data['executive_summary']['medium_risk_findings']}
- **Low Risk Findings:** {self.report_data['executive_summary']['low_risk_findings']}

## Detailed Findings

"""
        
        for finding in self.report_data['detailed_findings']:
            markdown_content += f"""### {finding['finding_type']}

**Category:** {finding['category']}  
**Severity:** {finding['severity']}  
**Description:** {finding['description']}  
**Recommendation:** {finding['recommendation']}

"""
        
        markdown_content += "## Compliance Status\n\n"
        markdown_content += "| Standard | Status | Score |\n"
        markdown_content += "|---------|--------|-------|\n"
        
        for standard, data in self.report_data['compliance_status'].items():
            markdown_content += f"| {standard.upper()} | {data['status']} | {data['score']}/100 |\n"
        
        markdown_content += "\n## Recommendations\n\n"
        
        for rec in self.report_data['recommendations']:
            markdown_content += f"""### {rec['priority']} - {rec['category']}

**Timeline:** {rec['timeline']}  
**Resources Required:** {rec['resources']}  
**Expected Impact:** {rec['impact']}

"""
            for recommendation in rec['recommendations']:
                markdown_content += f"- {recommendation}\n"
            markdown_content += "\n"
        
        with open(output_file, 'w') as f:
            f.write(markdown_content)
        
        return output_file

if __name__ == "__main__":
    # Example usage
    generator = SecurityReportGenerator()
    
    # Load scan results (if available)
    scan_data = generator.load_scan_results()
    
    # Generate report components
    generator.generate_executive_summary(scan_data)
    generator.generate_detailed_findings(scan_data)
    generator.generate_compliance_matrix(scan_data)
    generator.generate_recommendations(generator.report_data['detailed_findings'])
    
    # Generate reports
    html_file = generator.generate_html_report()
    markdown_file = generator.generate_markdown_report()
    
    print(f"HTML Report generated: {html_file}")
    print(f"Markdown Report generated: {markdown_file}")

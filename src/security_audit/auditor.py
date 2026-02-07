#!/usr/bin/env python3
"""
Security Audit Module
Performs comprehensive security audit of system configurations and policies
"""

import os
import json
import hashlib
import platform
import subprocess
from datetime import datetime
from typing import Dict, List, Any

class SecurityAuditor:
    def __init__(self):
        self.system_info = {}
        self.audit_results = {
            'audit_date': datetime.now().isoformat(),
            'system_info': {},
            'security_checks': {},
            'compliance_status': {},
            'recommendations': []
        }
    
    def gather_system_info(self) -> Dict[str, Any]:
        """Gather basic system information"""
        try:
            system_info = {
                'platform': platform.system(),
                'platform_release': platform.release(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'hostname': platform.node(),
                'processor': platform.processor(),
            }
            
            self.system_info = system_info
            self.audit_results['system_info'] = system_info
            return system_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def check_file_permissions(self, directory: str = None) -> Dict[str, Any]:
        """Check file permissions for security"""
        if directory is None:
            directory = os.getcwd()
        
        permission_issues = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat_info = os.stat(file_path)
                        permissions = oct(stat_info.st_mode)[-3:]
                        
                        # Check for world-writable files
                        if permissions[-1] in ['2', '6', '7']:
                            permission_issues.append({
                                'file': file_path,
                                'permissions': permissions,
                                'issue': 'World-writable'
                            })
                        
                        # Check for sensitive files with excessive permissions
                        sensitive_files = ['.env', 'config.py', 'secrets.txt', 'passwords.txt']
                        if any(sensitive in file.lower() for sensitive in sensitive_files):
                            if permissions not in ['600', '400', '644', '640']:
                                permission_issues.append({
                                    'file': file_path,
                                    'permissions': permissions,
                                    'issue': 'Sensitive file with excessive permissions'
                                })
                    except:
                        continue
                        
        except Exception as e:
            permission_issues.append({'error': str(e)})
        
        self.audit_results['security_checks']['file_permissions'] = permission_issues
        return permission_issues
    
    def check_password_policy(self) -> Dict[str, Any]:
        """Check password policy compliance"""
        password_checks = {
            'min_length_check': False,
            'complexity_check': False,
            'history_check': False,
            'lockout_policy': False
        }
        
        try:
            if platform.system() == "Linux":
                # Check Linux password policies
                try:
                    with open('/etc/pam.d/common-password', 'r') as f:
                        content = f.read()
                        if 'minlen=' in content:
                            password_checks['min_length_check'] = True
                        if 'ucredit=' in content or 'lcredit=' in content or 'dcredit=' in content:
                            password_checks['complexity_check'] = True
                except:
                    pass
                
                # Check for password history
                try:
                    with open('/etc/security/pwquality.conf', 'r') as f:
                        content = f.read()
                        if 'remember=' in content or 'difok=' in content:
                            password_checks['history_check'] = True
                except:
                    pass
                    
            elif platform.system() == "Windows":
                # Windows password policy checks would require admin privileges
                password_checks['windows_admin_required'] = True
                
        except Exception as e:
            password_checks['error'] = str(e)
        
        self.audit_results['security_checks']['password_policy'] = password_checks
        return password_checks
    
    def check_network_security(self) -> Dict[str, Any]:
        """Check network security configurations"""
        network_checks = {
            'firewall_status': 'Unknown',
            'open_services': [],
            'network_interfaces': []
        }
        
        try:
            if platform.system() == "Linux":
                # Check firewall status
                try:
                    result = subprocess.run(['sudo', 'ufw', 'status'], 
                                          capture_output=True, text=True, timeout=10)
                    if 'active' in result.stdout:
                        network_checks['firewall_status'] = 'Active'
                    else:
                        network_checks['firewall_status'] = 'Inactive'
                except:
                    network_checks['firewall_status'] = 'Unable to check'
                
                # Check listening services
                try:
                    result = subprocess.run(['netstat', '-tlnp'], 
                                          capture_output=True, text=True, timeout=10)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'LISTEN' in line:
                            network_checks['open_services'].append(line.strip())
                except:
                    pass
                    
        except Exception as e:
            network_checks['error'] = str(e)
        
        self.audit_results['security_checks']['network_security'] = network_checks
        return network_checks
    
    def check_software_updates(self) -> Dict[str, Any]:
        """Check for software updates and patches"""
        update_status = {
            'last_update': 'Unknown',
            'updates_available': False,
            'critical_updates': 0
        }
        
        try:
            if platform.system() == "Linux":
                # Check for package updates
                try:
                    result = subprocess.run(['apt', 'list', '--upgradable'], 
                                          capture_output=True, text=True, timeout=30)
                    if result.stdout and len(result.stdout.strip()) > 0:
                        update_status['updates_available'] = True
                        update_status['update_count'] = len(result.stdout.strip().split('\n')) - 1
                except:
                    pass
                    
        except Exception as e:
            update_status['error'] = str(e)
        
        self.audit_results['security_checks']['software_updates'] = update_status
        return update_status
    
    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report against security standards"""
        compliance = {
            'cis_benchmarks': 'Not Assessed',
            'nist_framework': 'Not Assessed',
            'iso27001': 'Not Assessed',
            'gdpr_compliance': 'Not Assessed'
        }
        
        # Basic compliance checks based on audit results
        security_checks = self.audit_results.get('security_checks', {})
        
        # CIS Controls assessment
        file_perm_issues = len(security_checks.get('file_permissions', []))
        if file_perm_issues == 0:
            compliance['cis_benchmarks'] = 'Compliant'
        elif file_perm_issues < 5:
            compliance['cis_benchmarks'] = 'Partially Compliant'
        else:
            compliance['cis_benchmarks'] = 'Non-Compliant'
        
        self.audit_results['compliance_status'] = compliance
        return compliance
    
    def generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on audit findings"""
        recommendations = []
        
        security_checks = self.audit_results.get('security_checks', {})
        
        # File permission recommendations
        file_issues = security_checks.get('file_permissions', [])
        if file_issues:
            recommendations.append("Review and fix file permission issues, especially world-writable files")
        
        # Password policy recommendations
        password_policy = security_checks.get('password_policy', {})
        if not password_policy.get('min_length_check', False):
            recommendations.append("Implement minimum password length policy (8+ characters)")
        if not password_policy.get('complexity_check', False):
            recommendations.append("Implement password complexity requirements")
        
        # Network security recommendations
        network_security = security_checks.get('network_security', {})
        if network_security.get('firewall_status') == 'Inactive':
            recommendations.append("Enable and configure firewall protection")
        
        # Software update recommendations
        updates = security_checks.get('software_updates', {})
        if updates.get('updates_available', False):
            recommendations.append("Apply available software updates and security patches")
        
        self.audit_results['recommendations'] = recommendations
        return recommendations
    
    def generate_audit_report(self) -> str:
        """Generate comprehensive security audit report"""
        report = f"""
# Security Audit Report
**Date:** {self.audit_results['audit_date']}
**System:** {self.system_info.get('hostname', 'Unknown')} ({self.system_info.get('platform', 'Unknown')})

## Executive Summary
- File Permission Issues: {len(self.audit_results['security_checks'].get('file_permissions', []))}
- Password Policy Status: {self.audit_results['security_checks'].get('password_policy', {}).get('status', 'Not Checked')}
- Firewall Status: {self.audit_results['security_checks'].get('network_security', {}).get('firewall_status', 'Unknown')}
- Software Updates: {'Available' if self.audit_results['security_checks'].get('software_updates', {}).get('updates_available') else 'Up to date'}

## Detailed Findings

### System Information
{json.dumps(self.system_info, indent=2)}

### Security Checks Results
{json.dumps(self.audit_results['security_checks'], indent=2)}

### Compliance Status
{json.dumps(self.audit_results['compliance_status'], indent=2)}

## Recommendations
"""
        for i, rec in enumerate(self.audit_results['recommendations'], 1):
            report += f"{i}. {rec}\n"
        
        return report
    
    def save_audit_results(self, filename: str = None) -> str:
        """Save audit results to file"""
        if filename is None:
            filename = f"security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.audit_results, f, indent=2)
        
        return filename

if __name__ == "__main__":
    # Example usage
    auditor = SecurityAuditor()
    auditor.gather_system_info()
    auditor.check_file_permissions()
    auditor.check_password_policy()
    auditor.check_network_security()
    auditor.check_software_updates()
    auditor.generate_compliance_report()
    auditor.generate_recommendations()
    
    print(auditor.generate_audit_report())
    auditor.save_audit_results()

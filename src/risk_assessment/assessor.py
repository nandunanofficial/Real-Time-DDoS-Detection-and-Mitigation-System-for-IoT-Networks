#!/usr/bin/env python3
"""
Risk Assessment Module
Performs systematic evaluation of security risks and mitigation strategies
"""

import json
import math
from datetime import datetime
from typing import Dict, List, Any, Tuple
from enum import Enum

class RiskLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

class ThreatType(Enum):
    MALICIOUS_SOFTWARE = "Malicious Software"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"
    DATA_BREACH = "Data Breach"
    DENIAL_OF_SERVICE = "Denial of Service"
    INSIDER_THREAT = "Insider Threat"
    PHYSICAL_SECURITY = "Physical Security"
    SOCIAL_ENGINEERING = "Social Engineering"

class RiskAssessor:
    def __init__(self):
        self.risk_matrix = {
            'likelihood': {
                'very_likely': 5,
                'likely': 4,
                'possible': 3,
                'unlikely': 2,
                'rare': 1
            },
            'impact': {
                'catastrophic': 5,
                'critical': 4,
                'moderate': 3,
                'minor': 2,
                'negligible': 1
            }
        }
        self.assessment_results = {
            'assessment_date': datetime.now().isoformat(),
            'risks_identified': [],
            'risk_scores': {},
            'mitigation_strategies': [],
            'residual_risks': [],
            'risk_treatment_plan': {}
        }
    
    def calculate_risk_score(self, likelihood: str, impact: str) -> Tuple[int, RiskLevel]:
        """Calculate risk score based on likelihood and impact"""
        likelihood_score = self.risk_matrix['likelihood'].get(likelihood.lower(), 3)
        impact_score = self.risk_matrix['impact'].get(impact.lower(), 3)
        
        risk_score = likelihood_score * impact_score
        
        if risk_score >= 20:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 15:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 10:
            risk_level = RiskLevel.MEDIUM
        elif risk_score >= 5:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.INFO
        
        return risk_score, risk_level
    
    def identify_threats(self) -> List[Dict[str, Any]]:
        """Identify potential security threats"""
        threats = [
            {
                'id': 'THREAT_001',
                'name': 'Malware Infection',
                'type': ThreatType.MALICIOUS_SOFTWARE.value,
                'description': 'Unauthorized malicious software installation and execution',
                'likelihood': 'likely',
                'impact': 'critical',
                'affected_assets': ['servers', 'workstations', 'network'],
                'indicators': ['unusual network traffic', 'system slowdown', 'unauthorized processes']
            },
            {
                'id': 'THREAT_002',
                'name': 'Unauthorized Access',
                'type': ThreatType.UNAUTHORIZED_ACCESS.value,
                'description': 'Unauthorized individuals gaining access to systems or data',
                'likelihood': 'possible',
                'impact': 'critical',
                'affected_assets': ['databases', 'file_servers', 'applications'],
                'indicators': ['failed login attempts', 'access from unusual locations', 'privilege escalation']
            },
            {
                'id': 'THREAT_003',
                'name': 'Data Breach',
                'type': ThreatType.DATA_BREACH.value,
                'description': 'Unauthorized access to or disclosure of sensitive information',
                'likelihood': 'unlikely',
                'impact': 'catastrophic',
                'affected_assets': ['customer_data', 'financial_records', 'intellectual_property'],
                'indicators': ['data exfiltration', 'unusual data access patterns', 'encryption of files']
            },
            {
                'id': 'THREAT_004',
                'name': 'Denial of Service',
                'type': ThreatType.DENIAL_OF_SERVICE.value,
                'description': 'Service disruption due to overwhelming traffic or resource exhaustion',
                'likelihood': 'possible',
                'impact': 'moderate',
                'affected_assets': ['web_servers', 'network_infrastructure', 'applications'],
                'indicators': ['service unavailability', 'high resource usage', 'network saturation']
            },
            {
                'id': 'THREAT_005',
                'name': 'Insider Threat',
                'type': ThreatType.INSIDER_THREAT.value,
                'description': 'Security risks from authorized users within the organization',
                'likelihood': 'unlikely',
                'impact': 'critical',
                'affected_assets': ['all_systems', 'sensitive_data', 'intellectual_property'],
                'indicators': ['unusual access patterns', 'data exfiltration', 'privilege abuse']
            }
        ]
        
        return threats
    
    def assess_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Assess system vulnerabilities"""
        vulnerabilities = [
            {
                'id': 'VULN_001',
                'name': 'Outdated Software',
                'description': 'Systems running outdated software with known vulnerabilities',
                'severity': 'high',
                'cvss_score': 7.5,
                'affected_systems': ['web_servers', 'database_servers'],
                'exploitability': 'high',
                'remediation': 'Apply security patches and updates'
            },
            {
                'id': 'VULN_002',
                'name': 'Weak Authentication',
                'description': 'Insufficient authentication mechanisms and password policies',
                'severity': 'medium',
                'cvss_score': 5.5,
                'affected_systems': ['applications', 'remote_access'],
                'exploitability': 'medium',
                'remediation': 'Implement multi-factor authentication and strong password policies'
            },
            {
                'id': 'VULN_003',
                'name': 'Missing Security Headers',
                'description': 'Web applications missing important security headers',
                'severity': 'low',
                'cvss_score': 3.5,
                'affected_systems': ['web_applications'],
                'exploitability': 'low',
                'remediation': 'Configure security headers in web server/application'
            },
            {
                'id': 'VULN_004',
                'name': 'Inadequate Access Controls',
                'description': 'Insufficient access control mechanisms and privilege management',
                'severity': 'high',
                'cvss_score': 8.0,
                'affected_systems': ['file_servers', 'databases', 'applications'],
                'exploitability': 'high',
                'remediation': 'Implement proper access controls and principle of least privilege'
            }
        ]
        
        return vulnerabilities
    
    def calculate_asset_value(self, assets: List[str]) -> Dict[str, int]:
        """Calculate the value of assets for risk assessment"""
        asset_values = {
            'customer_data': 100,
            'financial_records': 95,
            'intellectual_property': 90,
            'web_servers': 70,
            'database_servers': 85,
            'file_servers': 60,
            'network_infrastructure': 75,
            'workstations': 40,
            'applications': 65
        }
        
        return {asset: asset_values.get(asset, 50) for asset in assets}
    
    def perform_risk_analysis(self) -> List[Dict[str, Any]]:
        """Perform comprehensive risk analysis"""
        threats = self.identify_threats()
        vulnerabilities = self.assess_vulnerabilities()
        
        risks = []
        
        for threat in threats:
            for vulnerability in vulnerabilities:
                # Check if threat and vulnerability can combine
                affected_assets = set(threat['affected_assets']) & set(vulnerability['affected_systems'])
                
                if affected_assets:
                    asset_value = self.calculate_asset_value(list(affected_assets))
                    total_asset_value = sum(asset_value.values())
                    
                    # Adjust likelihood and impact based on vulnerability severity
                    adjusted_likelihood = self._adjust_likelihood(threat['likelihood'], vulnerability['severity'])
                    adjusted_impact = self._adjust_impact(threat['impact'], total_asset_value)
                    
                    risk_score, risk_level = self.calculate_risk_score(adjusted_likelihood, adjusted_impact)
                    
                    risk = {
                        'risk_id': f"RISK_{len(risks) + 1:03d}",
                        'threat_id': threat['id'],
                        'vulnerability_id': vulnerability['id'],
                        'threat_name': threat['name'],
                        'vulnerability_name': vulnerability['name'],
                        'affected_assets': list(affected_assets),
                        'total_asset_value': total_asset_value,
                        'likelihood': adjusted_likelihood,
                        'impact': adjusted_impact,
                        'risk_score': risk_score,
                        'risk_level': risk_level.name,
                        'description': f"{threat['description']} exploiting {vulnerability['description']}",
                        'risk_scenario': f"{threat['name']} + {vulnerability['name']}"
                    }
                    
                    risks.append(risk)
        
        self.assessment_results['risks_identified'] = risks
        return risks
    
    def _adjust_likelihood(self, base_likelihood: str, vulnerability_severity: str) -> str:
        """Adjust likelihood based on vulnerability severity"""
        likelihood_levels = ['rare', 'unlikely', 'possible', 'likely', 'very_likely']
        base_index = likelihood_levels.index(base_likelihood)
        
        severity_adjustment = {
            'low': 0,
            'medium': 1,
            'high': 2,
            'critical': 3
        }
        
        adjustment = severity_adjustment.get(vulnerability_severity, 0)
        new_index = min(base_index + adjustment, len(likelihood_levels) - 1)
        
        return likelihood_levels[new_index]
    
    def _adjust_impact(self, base_impact: str, asset_value: int) -> str:
        """Adjust impact based on asset value"""
        impact_levels = ['negligible', 'minor', 'moderate', 'critical', 'catastrophic']
        base_index = impact_levels.index(base_impact)
        
        # Adjust impact based on asset value
        if asset_value >= 80:
            adjustment = 1
        elif asset_value >= 60:
            adjustment = 0
        else:
            adjustment = -1
        
        new_index = max(0, min(base_index + adjustment, len(impact_levels) - 1))
        
        return impact_levels[new_index]
    
    def develop_mitigation_strategies(self) -> List[Dict[str, Any]]:
        """Develop risk mitigation strategies"""
        risks = self.assessment_results['risks_identified']
        
        strategies = []
        
        # Group risks by risk level
        critical_risks = [r for r in risks if r['risk_level'] == 'CRITICAL']
        high_risks = [r for r in risks if r['risk_level'] == 'HIGH']
        medium_risks = [r for r in risks if r['risk_level'] == 'MEDIUM']
        
        # Develop strategies for each risk level
        if critical_risks:
            strategies.append({
                'strategy_id': 'STRAT_001',
                'risk_level': 'CRITICAL',
                'approach': 'Risk Mitigation',
                'description': 'Immediate implementation of controls to reduce critical risks',
                'actions': [
                    'Apply all security patches within 24 hours',
                    'Implement emergency access controls',
                    'Enable enhanced monitoring and alerting',
                    'Prepare incident response procedures'
                ],
                'timeline': 'Immediate',
                'resources_required': 'High',
                'expected_reduction': '70-90%'
            })
        
        if high_risks:
            strategies.append({
                'strategy_id': 'STRAT_002',
                'risk_level': 'HIGH',
                'approach': 'Risk Mitigation',
                'description': 'Systematic implementation of security controls for high risks',
                'actions': [
                    'Implement multi-factor authentication',
                    'Enhance network security controls',
                    'Regular vulnerability scanning and patching',
                    'Security awareness training'
                ],
                'timeline': '30 days',
                'resources_required': 'Medium',
                'expected_reduction': '50-70%'
            })
        
        if medium_risks:
            strategies.append({
                'strategy_id': 'STRAT_003',
                'risk_level': 'MEDIUM',
                'approach': 'Risk Acceptance/Mitigation',
                'description': 'Cost-effective approach to medium risks',
                'actions': [
                    'Implement basic security controls',
                    'Regular monitoring and review',
                    'Document risk acceptance rationale',
                    'Plan for future improvements'
                ],
                'timeline': '90 days',
                'resources_required': 'Low',
                'expected_reduction': '30-50%'
            })
        
        self.assessment_results['mitigation_strategies'] = strategies
        return strategies
    
    def calculate_residual_risks(self) -> List[Dict[str, Any]]:
        """Calculate residual risks after mitigation"""
        original_risks = self.assessment_results['risks_identified']
        strategies = self.assessment_results['mitigation_strategies']
        
        residual_risks = []
        
        for risk in original_risks:
            # Apply mitigation reduction based on risk level
            reduction_percentages = {
                'CRITICAL': 0.8,
                'HIGH': 0.6,
                'MEDIUM': 0.4,
                'LOW': 0.2
            }
            
            reduction = reduction_percentages.get(risk['risk_level'], 0.0)
            residual_score = int(risk['risk_score'] * (1 - reduction))
            
            # Recalculate risk level
            if residual_score >= 20:
                residual_level = 'CRITICAL'
            elif residual_score >= 15:
                residual_level = 'HIGH'
            elif residual_score >= 10:
                residual_level = 'MEDIUM'
            elif residual_score >= 5:
                residual_level = 'LOW'
            else:
                residual_level = 'INFO'
            
            residual_risk = {
                'risk_id': risk['risk_id'],
                'original_score': risk['risk_score'],
                'original_level': risk['risk_level'],
                'residual_score': residual_score,
                'residual_level': residual_level,
                'reduction_applied': f"{int(reduction * 100)}%",
                'mitigation_status': 'Implemented' if reduction > 0 else 'No Mitigation'
            }
            
            residual_risks.append(residual_risk)
        
        self.assessment_results['residual_risks'] = residual_risks
        return residual_risks
    
    def generate_risk_register(self) -> str:
        """Generate comprehensive risk register"""
        risks = self.assessment_results['risks_identified']
        
        register = "# Risk Register\n\n"
        register += "| Risk ID | Risk Description | Risk Score | Risk Level | Affected Assets | Mitigation Strategy |\n"
        register += "|---------|------------------|------------|------------|-----------------|---------------------|\n"
        
        for risk in sorted(risks, key=lambda x: x['risk_score'], reverse=True):
            register += f"| {risk['risk_id']} | {risk['risk_scenario']} | {risk['risk_score']} | {risk['risk_level']} | {', '.join(risk['affected_assets'])} | See mitigation plan |\n"
        
        return register
    
    def generate_risk_assessment_report(self) -> str:
        """Generate comprehensive risk assessment report"""
        report = f"""
# Risk Assessment Report
**Date:** {self.assessment_results['assessment_date']}

## Executive Summary
- Total Risks Identified: {len(self.assessment_results['risks_identified'])}
- Critical Risks: {len([r for r in self.assessment_results['risks_identified'] if r['risk_level'] == 'CRITICAL'])}
- High Risks: {len([r for r in self.assessment_results['risks_identified'] if r['risk_level'] == 'HIGH'])}
- Medium Risks: {len([r for r in self.assessment_results['risks_identified'] if r['risk_level'] == 'MEDIUM'])}
- Average Risk Score: {sum(r['risk_score'] for r in self.assessment_results['risks_identified']) / len(self.assessment_results['risks_identified']):.1f}

## Risk Analysis Results

### Top 10 Risks
"""
        
        top_risks = sorted(self.assessment_results['risks_identified'], 
                          key=lambda x: x['risk_score'], reverse=True)[:10]
        
        for i, risk in enumerate(top_risks, 1):
            report += f"""
{i}. **{risk['risk_scenario']}** ({risk['risk_level']})
   - Risk Score: {risk['risk_score']}
   - Affected Assets: {', '.join(risk['affected_assets'])}
   - Description: {risk['description']}
"""
        
        report += "\n## Mitigation Strategies\n"
        for strategy in self.assessment_results['mitigation_strategies']:
            report += f"""
### {strategy['risk_level']} Risk Strategy
- **Approach:** {strategy['approach']}
- **Timeline:** {strategy['timeline']}
- **Expected Reduction:** {strategy['expected_reduction']}
- **Key Actions:**
"""
            for action in strategy['actions']:
                report += f"  - {action}\n"
        
        report += "\n## Residual Risk Assessment\n"
        report += "| Risk ID | Original Score | Residual Score | Reduction | Status |\n"
        report += "|---------|----------------|----------------|-----------|--------|\n"
        
        for residual in self.assessment_results['residual_risks']:
            report += f"| {residual['risk_id']} | {residual['original_score']} | {residual['residual_score']} | {residual['reduction_applied']} | {residual['mitigation_status']} |\n"
        
        return report
    
    def save_assessment_results(self, filename: str = None) -> str:
        """Save assessment results to file"""
        if filename is None:
            filename = f"risk_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.assessment_results, f, indent=2)
        
        return filename

if __name__ == "__main__":
    # Example usage
    assessor = RiskAssessor()
    assessor.perform_risk_analysis()
    assessor.develop_mitigation_strategies()
    assessor.calculate_residual_risks()
    
    print(assessor.generate_risk_assessment_report())
    print("\n" + assessor.generate_risk_register())
    assessor.save_assessment_results()

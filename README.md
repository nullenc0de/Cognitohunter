# CognitoHunter 🎯

A powerful AWS Cognito analysis and session hijacking toolkit designed for security researchers and penetration testers. CognitoHunter specializes in dissecting AWS Cognito implementations and performing advanced credential-to-session conversions.

![Python](https://img.shields.io/badge/python-v3.7+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
</div>

## 🚀 Features

- 🔍 **Deep Configuration Discovery**
  - Identifies AWS Cognito configurations in web apps and JS files
  - Extracts identity pools, user pools, and client IDs
  - Maps AWS authentication flows

- 🔑 **Advanced Credential Acquisition**
  - Validates identity pools across multiple regions
  - Obtains AWS credentials for unauthenticated access
  - Extracts temporary security tokens

- 🔄 **Multi-method Session Conversion**
  - SDK token exchange
  - Cognito hosted UI flow
  - AWS Web Identity federation
  - Browser SDK emulation
  - JWT token exchange
  - Direct API access

- 🎯 **Session Validation & Hijacking**
  - Tests obtained sessions against common endpoints
  - Provides browser-ready cookie commands
  - Generates authorization headers
  - Validates session permissions

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cognitohunter.git
cd cognitohunter

# Install required packages
pip3 install -r requirements.txt
```

## 📖 Quick Start

### Full Analysis Mode
```bash
python3 cognitohunter.py -u https://example.com -v --insecure
```

### Direct Credentials Mode
```bash
python3 cognitohunter.py -u https://example.com \
    --creds "ACCESS_KEY:SECRET_KEY:SESSION_TOKEN" \
    --identity "IDENTITY_ID"
```

### Command Line Options
```
🎯 CognitoHunter v1.0.0 - AWS Cognito Analysis Toolkit

optional arguments:
  -h, --help            show this help message and exit
  -u, --url URL        Target URL to analyze
  -v, --verbose        Enable verbose logging
  -o, --output FILE    Output file for results
  --insecure           Skip SSL verification
  --creds CREDS        Use existing AWS credentials
  --identity ID        Use existing Identity ID
```

## 💡 Example Output

```json
{
  "identity_pools": [
    "us-west-2:6f4d8534-3bf0-4357-9b8b-750f2f3d23d3"
  ],
  "validations": [
    {
      "type": "identity_pool",
      "id": "us-west-2:6f4d8534-3bf0-4357-9b8b-750f2f3d23d3",
      "identity_id": "us-west-2:c6d76489-2df1-cb8f-eb4b-e5fe685d350e",
      "credentials": {
        "AccessKeyId": "ASIA4NV3EREW5EFZTNHT",
        "SecretKey": "5eglHwsS0/QOF7Tz/OmO3xWRFQ1ppnnvJORERBM1",
        "SessionToken": "IQoJb3JpZ2luX2VjEJf..."
      }
    }
  ],
  "web_sessions": [
    {
      "method": "sdk_token",
      "cookies": {
        "session": "example_session_cookie"
      },
      "headers": {
        "Authorization": "Bearer example_token"
      }
    }
  ]
}
```

## 🔄 How It Works

1. **Configuration Discovery Phase**
   - Scans target website and JS files
   - Extracts AWS configurations
   - Maps authentication endpoints

2. **Credential Acquisition Phase**
   - Validates identity pools
   - Obtains AWS temporary credentials
   - Tests credential permissions

3. **Session Conversion Phase**
   - Attempts multiple conversion methods
   - Validates obtained sessions
   - Tests session permissions

4. **Result Generation Phase**
   - Provides detailed analysis
   - Generates exploitation commands
   - Validates session access

## 🛡️ Defense Recommendations

1. **Identity Pool Security**
   - Disable unauthenticated access unless required
   - Implement strict IAM roles
   - Regular audit of permissions

2. **Session Management**
   - Implement proper session timeouts
   - Use secure session storage
   - Validate session permissions

3. **General Security**
   - Hide AWS configurations
   - Implement proper CORS policies
   - Regular security audits

## ⚠️ Disclaimer

This tool is for security research purposes only. Always obtain proper authorization before testing any systems or applications.

## 👥 Authors

- Paul Seekamp (@nullenc0de)

## 🙏 Acknowledgments

- Research based on work by NotSoSecure
- Inspired by Theodo Cloud Security research
- AWS Cognito security research community

## 📚 See Also

- [AWS Cognito Documentation](https://docs.aws.amazon.com/cognito/)
- [Identity Pools Guide](https://docs.aws.amazon.com/cognito/latest/developerguide/identity-pools.html)
- [Web Identity Federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html)

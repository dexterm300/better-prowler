# AWS Security Assessment Tool

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![.NET](https://img.shields.io/badge/.NET-8.0-purple.svg)](https://dotnet.microsoft.com/download/dotnet/8.0)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)

A comprehensive Windows WPF application for automated AWS security configuration assessment across AWS Organizations. This tool performs 16 comprehensive security checks to help identify misconfigurations, compliance gaps, and security risks across all accounts in your AWS Organization.

## 🎯 Features

This tool performs **16 comprehensive security checks** across all accounts in your AWS Organization:

1. **Root Account Hygiene** - MFA, access keys, usage detection
2. **Organization Structure & SCPs** - Service Control Policies validation
3. **IAM Baseline** - Users, roles, policies, MFA enforcement
4. **Cross-Account Trust** - Role trust policy analysis
5. **CloudTrail Configuration** - Multi-region, encryption, log integrity
6. **AWS Config** - Recorder status, aggregators
7. **Security Services** - GuardDuty, Security Hub, Access Analyzer, Inspector
8. **S3 Baseline** - Public access, encryption, log buckets
9. **KMS Baseline** - Key policies, rotation
10. **Network Baseline** - VPCs, Flow Logs, endpoints
11. **Monitoring & Alerting** - CloudWatch alarms, log groups
12. **Billing & Budgets** - Budget configuration
13. **Tagging Baseline** - Resource tagging compliance
14. **Backup Policies** - Backup plans and vaults
15. **IaC Governance** - CloudFormation drift, StackSets
16. **Incident Readiness** - Runbooks, testing

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Required Permissions](#required-permissions)
- [Audit Role Setup](#audit-role-setup)
- [Output Format](#output-format)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

## 🔧 Prerequisites

- **.NET 8.0 SDK** or later ([Download](https://dotnet.microsoft.com/download/dotnet/8.0))
- **Windows OS** (required for WPF)
- **AWS IAM credentials** with appropriate permissions (see [Required Permissions](#required-permissions))
- **Audit role** configured in each member account (see [Audit Role Setup](#audit-role-setup))
- **AWS Organization** with management account access

## 📦 Installation

### Option 1: Build from Source

1. **Clone the repository:**
   ```bash
   git clone https://github.com/dexterm300/better-prowler.git
   cd better-prowler
   ```

2. **Restore NuGet packages:**
   ```bash
   dotnet restore
   ```

3. **Build the application:**
   ```bash
   dotnet build
   ```

4. **Run the application:**
   ```bash
   dotnet run
   ```

### Option 2: Use Pre-built Binary

1. Download the latest release from the [Releases](https://github.com/dexterm300/better-prowler/releases) page
2. Extract the ZIP file
3. Run `AwsSecurityAssessment.exe`

## ⚙️ Configuration

### Configuration File

Copy `config.json.example` to `config.json` and update with your settings:

```json
{
  "ManagementAccountId": "123456789012",
  "ManagementRoleName": "OrganizationAccountAccessRole",
  "AuditRoleName": "SecurityAuditRole",
  "Regions": []
}
```

**Note:** Leave `Regions` empty to check all available regions, or specify a list of regions to check.

### Application Settings

The application also supports runtime configuration through the UI:
- **Access Key ID** - Your AWS access key
- **Secret Access Key** - Your AWS secret key
- **Region** - AWS region (default: us-east-1)
- **Audit Role Name** - Name of the audit role in member accounts (default: AuditRole)

## 🚀 Usage

1. **Launch the application**
   - Run `AwsSecurityAssessment.exe` or use `dotnet run`

2. **Enter AWS Credentials:**
   - Access Key ID
   - Secret Access Key
   - Region (default: us-east-1)
   - Audit Role Name (default: AuditRole)

3. **Test Connection (Optional):**
   - Click "Test Connection" to verify credentials before running the assessment

4. **Start Assessment:**
   - Click "Start Assessment" to begin scanning all accounts in your organization
   - Progress will be displayed in real-time

5. **Review Findings:**
   - Findings are displayed in a tree view organized by account and check type
   - Use the filter options to narrow down results
   - Status indicators:
     - ✅ **PASS** - Check passed successfully
     - ⚠️ **WARN** - Warning condition detected
     - ❌ **FAIL** - Failure condition detected

6. **Export Results:**
   - **Export to JSON**: Save findings to a local JSON file
   - **Upload to S3**: Upload findings directly to an S3 bucket

## 🔐 Required Permissions

The application requires extensive AWS permissions to perform comprehensive security assessments.

### Organization Level (Management Account)

The credentials used must have:
- `organizations:ListAccounts` - List all accounts in the organization
- `organizations:ListPoliciesForTarget` - View Service Control Policies
- `organizations:ListParents` - View organizational structure
- `sts:AssumeRole` - Assume roles in member accounts

### Per Account (via Audit Role)

Each member account must have an audit role with the following read-only permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudtrail:List*",
        "config:Describe*",
        "config:Get*",
        "config:List*",
        "guardduty:Get*",
        "guardduty:List*",
        "securityhub:Get*",
        "securityhub:List*",
        "securityhub:Describe*",
        "s3:GetBucket*",
        "s3:ListBucket",
        "s3:GetObject",
        "s3control:Get*",
        "s3control:List*",
        "kms:Describe*",
        "kms:Get*",
        "kms:List*",
        "ec2:Describe*",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "logs:Describe*",
        "logs:Get*",
        "logs:List*",
        "budgets:Describe*",
        "budgets:View*",
        "tag:Get*",
        "backup:Describe*",
        "backup:Get*",
        "backup:List*",
        "cloudformation:Describe*",
        "cloudformation:Get*",
        "cloudformation:List*",
        "access-analyzer:Get*",
        "access-analyzer:List*",
        "inspector2:Get*",
        "inspector2:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

## 🔑 Audit Role Setup

Each member account must have an IAM role that can be assumed by the assessment tool. The role should have a trust policy like:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::MANAGEMENT_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "optional-external-id"
        }
      }
    }
  ]
}
```

**Best Practices:**
- Use an external ID for additional security
- Limit the trust policy to specific IAM users/roles from the management account
- Use least privilege for the audit role permissions
- Consider using AWS Organizations SCPs to enforce audit role requirements

## 📊 Output Format

Findings are exported in JSON format with the following structure:

```json
{
  "accountId": "123456789012",
  "accountName": "Production",
  "checkName": "IAM_BASELINE",
  "status": "FAIL",
  "messages": [
    "IAM user 'admin' has AdministratorAccess",
    "IAM user 'testuser' has no MFA device configured"
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Status Values

- **PASS** - Check passed successfully, no issues found
- **WARN** - Warning condition detected, review recommended
- **FAIL** - Failure condition detected, action required

## 🐛 Troubleshooting

### "Access Denied" Errors

- Verify credentials have required permissions at the organization level
- Check that audit role exists in each member account
- Verify trust relationships are configured correctly
- Ensure the audit role has the necessary permissions attached

### "No accounts found"

- Verify credentials have `organizations:ListAccounts` permission
- Check that you're using the management account credentials
- Ensure the account is part of an AWS Organization

### Role Assumption Failures

- Verify audit role name is correct (case-sensitive)
- Check trust policy allows your principal (management account)
- Verify role has necessary permissions attached
- Check for SCPs that might be blocking role assumption

### Application Crashes or Freezes

- Check Windows Event Viewer for error details
- Verify .NET 8.0 runtime is installed
- Ensure sufficient system resources (memory, disk space)
- Try running with administrator privileges

### Slow Performance

- Large organizations may take significant time to assess
- Consider running assessments during off-peak hours
- Check network connectivity to AWS endpoints
- Review AWS CloudWatch for API throttling

## 🔒 Security Considerations

- **Credentials Storage**: Credentials are stored in memory only during execution and are never persisted to disk
- **Never commit credentials** to version control - use `config.json.example` as a template
- **Use IAM roles** with least privilege principle
- **Consider using temporary credentials** or session tokens instead of long-lived access keys
- **Review findings carefully** before taking remediation actions
- **Rotate credentials regularly** and use MFA for management account access
- **Audit role permissions** should be read-only to prevent accidental modifications

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Improvement

- Additional security checks and compliance frameworks
- Performance optimizations for large organizations
- UI/UX enhancements
- Better error handling and user feedback
- Automated remediation suggestions
- Support for additional AWS services
- Export formats (CSV, PDF, etc.)
- Scheduled assessments and reporting

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit your changes (`git commit -m 'Add some amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📝 License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed to help identify security configuration issues and compliance gaps in your AWS environment. However:

- **It does not guarantee complete security coverage** - always review findings manually
- **Follow AWS security best practices** - this tool supplements, not replaces, proper security practices
- **Use as part of a comprehensive security program** - not as the sole security measure
- **Test in non-production environments first** - understand the tool's behavior before using in production
- **No warranty provided** - see LICENSE file for full disclaimer

## 📚 Additional Resources

- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [AWS Organizations Documentation](https://docs.aws.amazon.com/organizations/)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)

## 📧 Support

For issues, questions, or contributions:
- Open an issue on [GitHub Issues](https://github.com/dexterm300/better-prowler/issues)
- Review existing issues before creating new ones
- Provide detailed information when reporting bugs

---

**Made with ❤️ for the AWS security community**

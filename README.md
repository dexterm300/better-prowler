# AWS Security Assessment Tool

A comprehensive WPF application for automated AWS security configuration assessment across an AWS Organization.

## Features

This tool performs 16 comprehensive security checks across all accounts in your AWS Organization:

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

## Prerequisites

- .NET 8.0 SDK or later
- Windows OS (for WPF)
- AWS IAM credentials with appropriate permissions
- Audit role configured in each member account

## Required Permissions

The application requires extensive AWS permissions:

### Organization Level
- `organizations:ListAccounts`
- `organizations:ListPoliciesForTarget`
- `organizations:ListParents`

### Per Account (via Audit Role)
- `iam:*` (read-only)
- `cloudtrail:*` (read-only)
- `config:*` (read-only)
- `guardduty:*` (read-only)
- `securityhub:*` (read-only)
- `s3:*` (read-only)
- `s3control:*` (read-only)
- `kms:*` (read-only)
- `ec2:Describe*`
- `cloudwatch:*` (read-only)
- `cloudwatchlogs:*` (read-only)
- `budgets:*` (read-only)
- `resourcegroupstaggingapi:*` (read-only)
- `backup:*` (read-only)
- `cloudformation:*` (read-only)
- `access-analyzer:*` (read-only)
- `inspector2:*` (read-only)

## Installation

1. Clone or download this repository
2. Restore NuGet packages:
   ```bash
   dotnet restore
   ```
3. Build the application:
   ```bash
   dotnet build
   ```
4. Run the application:
   ```bash
   dotnet run
   ```

## Usage

1. **Launch the application**
2. **Enter AWS Credentials**:
   - Access Key ID
   - Secret Access Key
   - Region (default: us-east-1)
   - Audit Role Name (default: AuditRole)
3. **Click "Start Assessment"**
4. **Review findings** in the tree view
5. **Export results**:
   - Export to JSON file
   - Upload to S3 bucket

## Audit Role Setup

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

## Output Format

Findings are exported in JSON format with the following structure:

```json
{
  "accountId": "123456789012",
  "accountName": "Production",
  "checkName": "IAM_BASELINE",
  "status": "FAIL",
  "messages": [
    "IAM user 'admin' has AdministratorAccess"
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Status Values

- **PASS** - Check passed successfully
- **WARN** - Warning condition detected
- **FAIL** - Failure condition detected

## Troubleshooting

### "Access Denied" Errors
- Verify credentials have required permissions
- Check that audit role exists in each account
- Verify trust relationships are configured correctly

### "No accounts found"
- Verify credentials have `organizations:ListAccounts` permission
- Check that you're using the management account credentials

### Role Assumption Failures
- Verify audit role name is correct
- Check trust policy allows your principal
- Verify role has necessary permissions

## Security Considerations

- Credentials are stored in memory only during execution
- Never commit credentials to version control
- Use IAM roles with least privilege
- Consider using temporary credentials or session tokens
- Review findings before taking remediation actions

## Limitations

- Some checks require manual verification (e.g., incident runbooks)
- Large organizations may take significant time to assess
- Some checks may require additional permissions
- Cross-region checks are performed per-region

## Contributing

Contributions are welcome! Areas for improvement:
- Additional security checks
- Performance optimizations
- UI enhancements
- Better error handling
- Automated remediation suggestions

## License

This project is provided as-is for security assessment purposes.

## Disclaimer

This tool is designed to help identify security configuration issues. It does not guarantee complete security coverage. Always review findings manually and follow AWS security best practices. The tool should be used as part of a comprehensive security program, not as the sole security measure.

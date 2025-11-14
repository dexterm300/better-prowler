using Amazon.Organizations;
using Amazon.Organizations.Model;
using AwsSecurityAssessment.Checkers;
using AwsSecurityAssessment.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Services
{
    public class SecurityAssessmentService
    {
        public async Task<List<AccountInfo>> DiscoverAccountsAsync(AwsCredentials credentials)
        {
            var accounts = new List<AccountInfo>();
            var awsCreds = AwsClientService.CreateCredentials(credentials);
            
            using var orgClient = new AmazonOrganizationsClient(awsCreds, Amazon.RegionEndpoint.GetBySystemName(credentials.Region));

            try
            {
                var response = await orgClient.ListAccountsAsync(new ListAccountsRequest());

                // Process initial response
                ProcessAccounts(response.Accounts, accounts);

                // Handle pagination
                while (response.NextToken != null)
                {
                    response = await orgClient.ListAccountsAsync(new ListAccountsRequest
                    {
                        NextToken = response.NextToken
                    });

                    ProcessAccounts(response.Accounts, accounts);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to discover accounts: {ex.Message}", ex);
            }

            return accounts;
        }

        private static void ProcessAccounts(IEnumerable<Account> accounts, List<AccountInfo> result)
        {
            foreach (var account in accounts)
            {
                if (account.Status == AccountStatus.ACTIVE)
                {
                    result.Add(new AccountInfo
                    {
                        Id = account.Id,
                        Name = account.Name,
                        Email = account.Email,
                        Status = account.Status.Value
                    });
                }
            }
        }

        public async Task<List<SecurityFinding>> PerformAllChecksAsync(
            AccountInfo account, 
            AwsCredentials baseCredentials, 
            AssessmentConfig config)
        {
            var allFindings = new List<SecurityFinding>();

            try
            {
                // Assume audit role - extract account ID from role ARN and replace with target account ID
                var roleArn = config.AuditRoleArn;
                if (string.IsNullOrWhiteSpace(roleArn))
                {
                    throw new Exception("Audit Role ARN is required");
                }
                
                // Replace account ID in role ARN with target account ID
                var arnParts = roleArn.Split(':');
                if (arnParts.Length >= 5)
                {
                    arnParts[4] = account.Id; // Replace account ID in ARN
                    roleArn = string.Join(":", arnParts);
                }
                
                var sessionCredentials = await AwsClientService.AssumeAuditRoleAsync(
                    roleArn, 
                    baseCredentials);

                // Create checkers
                var checkers = new BaseSecurityChecker[]
                {
                    new RootAccountHygieneChecker(),
                    new OrgStructureChecker(),
                    new IamBaselineChecker(),
                    new CrossAccountTrustChecker(),
                    new CloudTrailConfigurationChecker(),
                    new AwsConfigChecker(),
                    new SecurityServicesChecker(),
                    new S3BaselineChecker(),
                    new KmsBaselineChecker(),
                    new NetworkBaselineChecker(),
                    new MonitoringAndAlertingChecker(),
                    new BillingAndBudgetsChecker(),
                    new TaggingBaselineChecker(),
                    new BackupPoliciesChecker(),
                    new IaCGovernanceChecker(),
                    new IncidentReadinessChecker()
                };

                // Perform all checks in parallel
                var checkTasks = checkers.Select(checker => 
                    checker.CheckAsync(account, sessionCredentials, baseCredentials.Region));
                
                var findings = await Task.WhenAll(checkTasks);
                allFindings.AddRange(findings);
            }
            catch (Exception ex)
            {
                var errorFinding = new SecurityFinding
                {
                    AccountId = account.Id,
                    AccountName = account.Name,
                    CheckName = "ASSESSMENT_ERROR",
                    Status = FindingStatus.FAIL
                };
                errorFinding.Fail($"Failed to assess account: {ex.Message}");
                allFindings.Add(errorFinding);
            }

            return allFindings;
        }
    }
}

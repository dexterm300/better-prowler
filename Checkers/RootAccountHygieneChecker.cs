using Amazon;
using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class RootAccountHygieneChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("ROOT_HYGIENE", account);

            try
            {
                using var iamClient = new AmazonIdentityManagementServiceClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                var summary = await iamClient.GetAccountSummaryAsync(new GetAccountSummaryRequest());
                
                // Check MFA
                if (summary.SummaryMap.TryGetValue("AccountMFAEnabled", out var mfaValue) && mfaValue == 0)
                {
                    finding.Fail("Root MFA not enabled");
                }

                // Check for root access keys (this requires special permissions, so we'll note it)
                finding.Warn("Root access key detection requires management account access - verify manually");

                // Check for recent root usage
                finding.Warn("Root account usage detection requires CloudTrail analysis - verify manually");
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking root account hygiene: {ex.Message}");
            }

            return finding;
        }
    }
}


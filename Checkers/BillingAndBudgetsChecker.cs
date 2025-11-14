using Amazon;
using Amazon.Budgets;
using Amazon.Budgets.Model;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class BillingAndBudgetsChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("BILLING", account);

            try
            {
                using var budgetsClient = new AmazonBudgetsClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                var budgets = await budgetsClient.DescribeBudgetsAsync(new DescribeBudgetsRequest
                {
                    AccountId = account.Id
                });

                if (!budgets.Budgets.Any())
                {
                    finding.Warn("No AWS Budgets configured");
                }

                // Note: Billing access check requires IAM policy analysis
                finding.Warn("Billing access permissions check - verify manually");
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking billing and budgets: {ex.Message}");
            }

            return finding;
        }
    }
}


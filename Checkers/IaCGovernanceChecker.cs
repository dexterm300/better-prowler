using Amazon;
using Amazon.CloudFormation;
using Amazon.CloudFormation.Model;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class IaCGovernanceChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("IAC_GOVERNANCE", account);

            try
            {
                using var cfClient = new AmazonCloudFormationClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                var stacks = await cfClient.DescribeStacksAsync(new DescribeStacksRequest());

                // Check drift detection (simplified - would need to check each stack)
                finding.Warn("Drift detection status - verify per stack");

                // Check for StackSets (organization-level)
                try
                {
                    var stackSets = await cfClient.ListStackSetsAsync(new ListStackSetsRequest());
                    if (!stackSets.Summaries.Any())
                    {
                        finding.Warn("No organization-wide StackSets configured");
                    }
                }
                catch (Exception ex)
                {
                    finding.Warn($"Could not check StackSets - may require organization-level permissions: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking IaC governance: {ex.Message}");
            }

            return finding;
        }
    }
}


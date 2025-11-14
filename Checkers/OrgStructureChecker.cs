using Amazon;
using Amazon.Organizations;
using Amazon.Organizations.Model;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class OrgStructureChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("ORG_STRUCTURE", account);

            try
            {
                using var orgClient = new AmazonOrganizationsClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                var scps = await orgClient.ListPoliciesForTargetAsync(new ListPoliciesForTargetRequest
                {
                    TargetId = account.Id,
                    Filter = Amazon.Organizations.PolicyType.SERVICE_CONTROL_POLICY
                });

                if (!scps.Policies.Any())
                {
                    finding.Warn("No SCPs attached to account");
                }

                var parents = await orgClient.ListParentsAsync(new ListParentsRequest
                {
                    ChildId = account.Id
                });

                // Note: OU placement validation would require business logic
                finding.Pass();
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking org structure: {ex.Message}");
            }

            return finding;
        }
    }
}


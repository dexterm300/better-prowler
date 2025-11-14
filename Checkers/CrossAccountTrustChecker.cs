using Amazon;
using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class CrossAccountTrustChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("CROSS_ACCOUNT_TRUST", account);

            try
            {
                using var iamClient = new AmazonIdentityManagementServiceClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                // Get all roles with pagination
                var allRoles = new List<Role>();
                var rolesResponse = await iamClient.ListRolesAsync(new ListRolesRequest());
                allRoles.AddRange(rolesResponse.Roles);
                while (rolesResponse.IsTruncated)
                {
                    rolesResponse = await iamClient.ListRolesAsync(new ListRolesRequest
                    {
                        Marker = rolesResponse.Marker
                    });
                    allRoles.AddRange(rolesResponse.Roles);
                }

                foreach (var role in allRoles)
                {
                    var rolePolicy = await iamClient.GetRoleAsync(new GetRoleRequest
                    {
                        RoleName = role.RoleName
                    });

                    var trustPolicy = rolePolicy.Role.AssumeRolePolicyDocument;
                    
                    if (trustPolicy.Contains("\"AWS\":\"*\"") || trustPolicy.Contains("\"Principal\":{\"AWS\":\"*\""))
                    {
                        finding.Fail($"Role '{role.RoleName}' trust allows any AWS account");
                    }

                    // Check for external trust without conditions
                    if (trustPolicy.Contains("arn:aws:iam::") && !trustPolicy.Contains("Condition"))
                    {
                        finding.Warn($"Role '{role.RoleName}' has external trust with no conditions");
                    }
                }
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking cross-account trust: {ex.Message}");
            }

            return finding;
        }
    }
}


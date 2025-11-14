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
    public class IamBaselineChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("IAM_BASELINE", account);

            try
            {
                using var iamClient = new AmazonIdentityManagementServiceClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                // Get all users with pagination
                var allUsers = new List<User>();
                var usersResponse = await iamClient.ListUsersAsync(new ListUsersRequest());
                allUsers.AddRange(usersResponse.Users);
                while (usersResponse.IsTruncated)
                {
                    usersResponse = await iamClient.ListUsersAsync(new ListUsersRequest
                    {
                        Marker = usersResponse.Marker
                    });
                    allUsers.AddRange(usersResponse.Users);
                }

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

                // Get all policies with pagination
                var allPolicies = new List<ManagedPolicy>();
                var policiesResponse = await iamClient.ListPoliciesAsync(new ListPoliciesRequest { Scope = PolicyScopeType.Local });
                allPolicies.AddRange(policiesResponse.Policies);
                while (policiesResponse.IsTruncated)
                {
                    policiesResponse = await iamClient.ListPoliciesAsync(new ListPoliciesRequest 
                    { 
                        Scope = PolicyScopeType.Local,
                        Marker = policiesResponse.Marker
                    });
                    allPolicies.AddRange(policiesResponse.Policies);
                }

                // Check users
                foreach (var user in allUsers)
                {
                    // Get attached policies with pagination
                    var attachedPoliciesResponse = await iamClient.ListAttachedUserPoliciesAsync(new ListAttachedUserPoliciesRequest
                    {
                        UserName = user.UserName
                    });
                    var attachedPolicies = new List<AttachedPolicyType>(attachedPoliciesResponse.AttachedPolicies);
                    while (attachedPoliciesResponse.IsTruncated)
                    {
                        attachedPoliciesResponse = await iamClient.ListAttachedUserPoliciesAsync(new ListAttachedUserPoliciesRequest
                        {
                            UserName = user.UserName,
                            Marker = attachedPoliciesResponse.Marker
                        });
                        attachedPolicies.AddRange(attachedPoliciesResponse.AttachedPolicies);
                    }

                    foreach (var policy in attachedPolicies)
                    {
                        if (policy.PolicyName == "AdministratorAccess")
                        {
                            finding.Fail($"IAM user '{user.UserName}' has AdministratorAccess");
                        }
                    }

                    // Check access keys with pagination
                    var accessKeysResponse = await iamClient.ListAccessKeysAsync(new ListAccessKeysRequest
                    {
                        UserName = user.UserName
                    });
                    var accessKeys = new List<AccessKeyMetadata>(accessKeysResponse.AccessKeyMetadata);
                    while (accessKeysResponse.IsTruncated)
                    {
                        accessKeysResponse = await iamClient.ListAccessKeysAsync(new ListAccessKeysRequest
                        {
                            UserName = user.UserName,
                            Marker = accessKeysResponse.Marker
                        });
                        accessKeys.AddRange(accessKeysResponse.AccessKeyMetadata);
                    }

                    foreach (var key in accessKeys)
                    {
                        if (key.CreateDate < DateTime.UtcNow.AddDays(-90))
                        {
                            finding.Warn($"IAM key for user '{user.UserName}' older than 90 days");
                        }
                    }

                    // Check MFA
                    var mfaDevices = await iamClient.ListMFADevicesAsync(new ListMFADevicesRequest
                    {
                        UserName = user.UserName
                    });

                    try
                    {
                        var loginProfile = await iamClient.GetLoginProfileAsync(new GetLoginProfileRequest
                        {
                            UserName = user.UserName
                        });

                        if (loginProfile.LoginProfile != null && !mfaDevices.MFADevices.Any())
                        {
                            finding.Warn($"User '{user.UserName}' missing MFA");
                        }
                    }
                    catch (NoSuchEntityException)
                    {
                        // User has no console access, skip
                    }
                }

                // Check policies for wildcards
                foreach (var policy in allPolicies)
                {
                    var policyVersion = await iamClient.GetPolicyVersionAsync(new GetPolicyVersionRequest
                    {
                        PolicyArn = policy.Arn,
                        VersionId = policy.DefaultVersionId
                    });

                    var policyDoc = policyVersion.PolicyVersion.Document;
                    if (policyDoc.Contains("\"Action\":\"*\"") || policyDoc.Contains("\"Resource\":\"*\""))
                    {
                        finding.Fail($"Overly permissive IAM policy: {policy.PolicyName}");
                    }
                }
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking IAM baseline: {ex.Message}");
            }

            return finding;
        }
    }
}


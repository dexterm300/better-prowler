using Amazon;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class KmsBaselineChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("KMS_BASELINE", account);

            try
            {
                using var kmsClient = new AmazonKeyManagementServiceClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                // Get all keys with pagination
                var allKeys = new List<KeyListEntry>();
                var keysResponse = await kmsClient.ListKeysAsync(new ListKeysRequest());
                allKeys.AddRange(keysResponse.Keys);
                while (!string.IsNullOrEmpty(keysResponse.NextMarker))
                {
                    keysResponse = await kmsClient.ListKeysAsync(new ListKeysRequest
                    {
                        Marker = keysResponse.NextMarker
                    });
                    allKeys.AddRange(keysResponse.Keys);
                }

                foreach (var key in allKeys)
                {
                    var keyMetadata = await kmsClient.DescribeKeyAsync(new DescribeKeyRequest
                    {
                        KeyId = key.KeyId
                    });

                    // Check key policy
                    var policy = await kmsClient.GetKeyPolicyAsync(new GetKeyPolicyRequest
                    {
                        KeyId = key.KeyId,
                        PolicyName = "default"
                    });

                    if (policy.Policy.Contains("\"Action\":\"*\"") || policy.Policy.Contains("\"Effect\":\"Allow\"") && policy.Policy.Contains("\"Principal\":\"*\""))
                    {
                        finding.Fail($"KMS key has overly broad permissions: {key.KeyId}");
                    }

                    // Check rotation
                    try
                    {
                        var rotationStatus = await kmsClient.GetKeyRotationStatusAsync(new GetKeyRotationStatusRequest
                        {
                            KeyId = key.KeyId
                        });

                        if (!rotationStatus.KeyRotationEnabled)
                        {
                            finding.Warn($"KMS key rotation disabled: {key.KeyId}");
                        }
                    }
                    catch (Exception ex)
                    {
                        // Some key types don't support rotation
                        finding.Warn($"Could not check rotation status for key {key.KeyId}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking KMS baseline: {ex.Message}");
            }

            return finding;
        }
    }
}


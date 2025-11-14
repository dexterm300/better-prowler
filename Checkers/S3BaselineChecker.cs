using Amazon;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3Control;
using Amazon.S3Control.Model;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class S3BaselineChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("S3_BASELINE", account);

            try
            {
                // Check account-level Block Public Access
                try
                {
                    using var s3ControlClient = new AmazonS3ControlClient(credentials, RegionEndpoint.GetBySystemName(region));
                    var accountBlock = await s3ControlClient.GetPublicAccessBlockAsync(new Amazon.S3Control.Model.GetPublicAccessBlockRequest
                    {
                        AccountId = account.Id
                    });

                    if (!accountBlock.PublicAccessBlockConfiguration.BlockPublicAcls ||
                        !accountBlock.PublicAccessBlockConfiguration.BlockPublicPolicy ||
                        !accountBlock.PublicAccessBlockConfiguration.IgnorePublicAcls ||
                        !accountBlock.PublicAccessBlockConfiguration.RestrictPublicBuckets)
                    {
                        finding.Fail("Account-level S3 Block Public Access disabled");
                    }
                }
                catch (AmazonS3ControlException ex) when (ex.ErrorCode == "NoSuchPublicAccessBlockConfiguration" || ex.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    finding.Fail("Account-level S3 Block Public Access not configured");
                }
                catch (Exception ex)
                {
                    finding.Warn($"Account-level S3 Block Public Access check failed: {ex.Message}");
                }

                // Check buckets
                using var s3Client = new AmazonS3Client(credentials, RegionEndpoint.GetBySystemName(region));
                var buckets = await s3Client.ListBucketsAsync(new ListBucketsRequest());

                foreach (var bucket in buckets.Buckets)
                {
                    try
                    {
                        // Check bucket public access
                        var publicAccess = await s3Client.GetPublicAccessBlockAsync(new Amazon.S3.Model.GetPublicAccessBlockRequest
                        {
                            BucketName = bucket.BucketName
                        });

                        if (!publicAccess.PublicAccessBlockConfiguration.BlockPublicAcls ||
                            !publicAccess.PublicAccessBlockConfiguration.BlockPublicPolicy)
                        {
                            finding.Fail($"Public bucket detected: {bucket.BucketName}");
                        }
                    }
                    catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound || ex.ErrorCode == "NoSuchPublicAccessBlockConfiguration")
                    {
                        finding.Fail($"Bucket '{bucket.BucketName}' does not have public access block configured");
                    }
                    catch (Exception ex)
                    {
                        finding.Warn($"Bucket '{bucket.BucketName}' public access check failed: {ex.Message}");
                    }

                    // Check encryption
                    try
                    {
                        var encryption = await s3Client.GetBucketEncryptionAsync(new GetBucketEncryptionRequest
                        {
                            BucketName = bucket.BucketName
                        });

                        if (encryption.ServerSideEncryptionConfiguration == null ||
                            !encryption.ServerSideEncryptionConfiguration.ServerSideEncryptionRules.Any())
                        {
                            finding.Warn($"Bucket unencrypted: {bucket.BucketName}");
                        }
                    }
                    catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound || ex.ErrorCode == "NoSuchBucket")
                    {
                        finding.Warn($"Bucket '{bucket.BucketName}' not found or not accessible");
                    }
                    catch (Exception ex)
                    {
                        finding.Warn($"Bucket '{bucket.BucketName}' encryption check failed: {ex.Message}");
                    }

                    // Check if log bucket (simplified check)
                    if (bucket.BucketName.Contains("log") || bucket.BucketName.Contains("trail"))
                    {
                        // Note: Detailed permission check would require GetBucketPolicy
                        finding.Warn($"Log bucket '{bucket.BucketName}' - verify write-only permissions");
                    }
                }
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking S3 baseline: {ex.Message}");
            }

            return finding;
        }
    }
}


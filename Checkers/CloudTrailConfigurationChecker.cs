using Amazon;
using Amazon.CloudTrail;
using Amazon.CloudTrail.Model;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using AwsSecurityAssessment.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class CloudTrailConfigurationChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("CLOUDTRAIL", account);

            try
            {
                using var cloudTrailClient = new AmazonCloudTrailClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                var trails = await cloudTrailClient.DescribeTrailsAsync(new DescribeTrailsRequest());

                if (!trails.TrailList.Any())
                {
                    finding.Fail("No CloudTrail configured");
                    return finding;
                }

                using var s3Client = new AmazonS3Client(credentials, RegionEndpoint.GetBySystemName(region));

                foreach (var trail in trails.TrailList)
                {
                    if (!trail.IsMultiRegionTrail)
                    {
                        finding.Warn($"CloudTrail '{trail.Name}' not multi-region");
                    }

                    if (!trail.IncludeGlobalServiceEvents)
                    {
                        finding.Warn($"CloudTrail '{trail.Name}' global events not included");
                    }

                    if (!trail.LogFileValidationEnabled)
                    {
                        finding.Warn($"CloudTrail '{trail.Name}' log integrity not enabled");
                    }

                    // Check S3 bucket encryption and public access
                    if (!string.IsNullOrEmpty(trail.S3BucketName))
                    {
                        try
                        {
                            var bucketEncryption = await s3Client.GetBucketEncryptionAsync(new GetBucketEncryptionRequest
                            {
                                BucketName = trail.S3BucketName
                            });

                            // Encryption check passed
                        }
                        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound || ex.ErrorCode == "NoSuchBucket")
                        {
                            finding.Warn($"Trail S3 bucket '{trail.S3BucketName}' not found or not accessible");
                        }
                        catch (Exception ex)
                        {
                            finding.Warn($"Trail S3 bucket '{trail.S3BucketName}' encryption check failed: {ex.Message}");
                        }

                        // Check public access
                        try
                        {
                            var publicAccess = await s3Client.GetPublicAccessBlockAsync(new GetPublicAccessBlockRequest
                            {
                                BucketName = trail.S3BucketName
                            });
                            
                            if (!publicAccess.PublicAccessBlockConfiguration.BlockPublicAcls ||
                                !publicAccess.PublicAccessBlockConfiguration.BlockPublicPolicy ||
                                !publicAccess.PublicAccessBlockConfiguration.IgnorePublicAcls ||
                                !publicAccess.PublicAccessBlockConfiguration.RestrictPublicBuckets)
                            {
                                finding.Warn($"Trail S3 bucket '{trail.S3BucketName}' has public access settings enabled");
                            }
                        }
                        catch (AmazonS3Exception ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound || ex.ErrorCode == "NoSuchPublicAccessBlockConfiguration")
                        {
                            finding.Fail($"Trail S3 bucket '{trail.S3BucketName}' does not have public access block configured");
                        }
                        catch (Exception ex)
                        {
                            finding.Warn($"Trail S3 bucket '{trail.S3BucketName}' public access check failed: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking CloudTrail configuration: {ex.Message}");
            }

            return finding;
        }
    }
}


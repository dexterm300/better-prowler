using Amazon;
using Amazon.Runtime;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using AwsSecurityAssessment.Models;
using System;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Services
{
    public class AwsClientService
    {
        public static AWSCredentials CreateCredentials(AwsCredentials creds)
        {
            return new BasicAWSCredentials(creds.AccessKeyId, creds.SecretAccessKey);
        }

        public static async Task<AWSCredentials> AssumeAuditRoleAsync(
            string roleArn, 
            AwsCredentials baseCredentials)
        {
            var credentials = CreateCredentials(baseCredentials);
            using var stsClient = new AmazonSecurityTokenServiceClient(credentials, RegionEndpoint.GetBySystemName(baseCredentials.Region));
            
            var assumeRoleRequest = new AssumeRoleRequest
            {
                RoleArn = roleArn,
                RoleSessionName = $"SecurityAssessment-{Guid.NewGuid()}",
                DurationSeconds = 3600
            };

            try
            {
                var assumeRoleResponse = await stsClient.AssumeRoleAsync(assumeRoleRequest);
                return new SessionAWSCredentials(
                    assumeRoleResponse.Credentials.AccessKeyId,
                    assumeRoleResponse.Credentials.SecretAccessKey,
                    assumeRoleResponse.Credentials.SessionToken
                );
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to assume role {roleArn}: {ex.Message}", ex);
            }
        }

        public static async Task<bool> TestConnectionAsync(AwsCredentials credentials)
        {
            try
            {
                var awsCreds = CreateCredentials(credentials);
                using var stsClient = new AmazonSecurityTokenServiceClient(awsCreds, RegionEndpoint.GetBySystemName(credentials.Region));
                
                var callerIdentity = await stsClient.GetCallerIdentityAsync(new GetCallerIdentityRequest());
                return callerIdentity != null;
            }
            catch
            {
                return false;
            }
        }
    }
}


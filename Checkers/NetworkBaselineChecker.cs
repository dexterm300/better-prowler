using Amazon;
using Amazon.EC2;
using Amazon.EC2.Model;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class NetworkBaselineChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("NETWORK_BASELINE", account);

            try
            {
                using var ec2Client = new AmazonEC2Client(credentials, RegionEndpoint.GetBySystemName(region));
                
                var vpcs = await ec2Client.DescribeVpcsAsync(new DescribeVpcsRequest());
                var flowLogs = await ec2Client.DescribeFlowLogsAsync(new DescribeFlowLogsRequest());
                var endpoints = await ec2Client.DescribeVpcEndpointsAsync(new DescribeVpcEndpointsRequest());

                // Check for default VPC
                foreach (var vpc in vpcs.Vpcs)
                {
                    if (vpc.IsDefault)
                    {
                        finding.Warn("Default VPC exists in account");
                    }
                }

                if (!flowLogs.FlowLogs.Any())
                {
                    finding.Warn("VPC Flow Logs not enabled");
                }

                // Check for recommended endpoints
                var endpointServices = endpoints.VpcEndpoints.Select(e => e.ServiceName).ToList();
                if (!endpointServices.Any(s => s.Contains("s3")))
                {
                    finding.Warn("Recommended VPC endpoint for S3 missing");
                }
                if (!endpointServices.Any(s => s.Contains("ssm")))
                {
                    finding.Warn("Recommended VPC endpoint for SSM missing");
                }
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking network baseline: {ex.Message}");
            }

            return finding;
        }
    }
}


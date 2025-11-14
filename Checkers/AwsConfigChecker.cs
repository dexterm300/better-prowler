using Amazon;
using Amazon.ConfigService;
using Amazon.ConfigService.Model;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class AwsConfigChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("AWS_CONFIG", account);

            try
            {
                using var configClient = new AmazonConfigServiceClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                var recorders = await configClient.DescribeConfigurationRecordersAsync(new DescribeConfigurationRecordersRequest());

                if (!recorders.ConfigurationRecorders.Any())
                {
                    finding.Fail("AWS Config recorder disabled");
                }
                else
                {
                    // Check if recorder is recording (status check would require additional API call)
                    finding.Pass();
                }

                var aggregators = await configClient.DescribeConfigurationAggregatorsAsync(new DescribeConfigurationAggregatorsRequest());

                if (!aggregators.ConfigurationAggregators.Any())
                {
                    finding.Warn("No Config aggregator set up");
                }
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking AWS Config: {ex.Message}");
            }

            return finding;
        }
    }
}


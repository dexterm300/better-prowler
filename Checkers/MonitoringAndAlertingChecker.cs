using Amazon;
using Amazon.CloudWatch;
using Amazon.CloudWatch.Model;
using Amazon.CloudWatchLogs;
using Amazon.CloudWatchLogs.Model;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class MonitoringAndAlertingChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("MONITORING", account);

            try
            {
                using var cloudWatchClient = new AmazonCloudWatchClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                // Get all alarms with pagination
                var allAlarms = new List<MetricAlarm>();
                var alarmsResponse = await cloudWatchClient.DescribeAlarmsAsync(new DescribeAlarmsRequest());
                allAlarms.AddRange(alarmsResponse.MetricAlarms);

                while (!string.IsNullOrEmpty(alarmsResponse.NextToken))
                {
                    alarmsResponse = await cloudWatchClient.DescribeAlarmsAsync(new DescribeAlarmsRequest
                    {
                        NextToken = alarmsResponse.NextToken
                    });
                    allAlarms.AddRange(alarmsResponse.MetricAlarms);
                }

                var alarmNames = allAlarms.Select(a => a.AlarmName.ToLower()).ToList();
                
                var requiredAlarms = new[] { "unauthorized", "root", "guardduty" };
                foreach (var required in requiredAlarms)
                {
                    if (!alarmNames.Any(name => name.Contains(required)))
                    {
                        finding.Warn($"Missing recommended alarm pattern: {required}");
                    }
                }

                using var logsClient = new AmazonCloudWatchLogsClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                // Get all log groups with pagination
                var allLogGroups = new List<LogGroup>();
                var logGroupsResponse = await logsClient.DescribeLogGroupsAsync(new DescribeLogGroupsRequest());
                allLogGroups.AddRange(logGroupsResponse.LogGroups);

                while (!string.IsNullOrEmpty(logGroupsResponse.NextToken))
                {
                    logGroupsResponse = await logsClient.DescribeLogGroupsAsync(new DescribeLogGroupsRequest
                    {
                        NextToken = logGroupsResponse.NextToken
                    });
                    allLogGroups.AddRange(logGroupsResponse.LogGroups);
                }

                if (!allLogGroups.Any())
                {
                    finding.Warn("No CloudWatch LogGroups found");
                }
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking monitoring and alerting: {ex.Message}");
            }

            return finding;
        }
    }
}


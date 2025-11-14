using Amazon.GuardDuty;
using Amazon.GuardDuty.Model;
using Amazon.SecurityHub;
using Amazon.SecurityHub.Model;
using Amazon.AccessAnalyzer;
using Amazon.AccessAnalyzer.Model;
using Amazon.Inspector2;
using Amazon.Inspector2.Model;
using Amazon;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class SecurityServicesChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("SECURITY_SERVICES", account);

            try
            {
                // Check GuardDuty
                try
                {
                    using var guardDutyClient = new AmazonGuardDutyClient(credentials, RegionEndpoint.GetBySystemName(region));
                    var detectors = await guardDutyClient.ListDetectorsAsync(new ListDetectorsRequest());
                    if (!detectors.DetectorIds.Any())
                    {
                        finding.Warn("GuardDuty not enabled");
                    }
                }
                catch (Exception ex)
                {
                    finding.Warn($"GuardDuty check failed: {ex.Message}");
                }

                // Check Security Hub
                try
                {
                    using var securityHubClient = new AmazonSecurityHubClient(credentials, RegionEndpoint.GetBySystemName(region));
                    var hub = await securityHubClient.DescribeHubAsync(new DescribeHubRequest());
                }
                catch (InvalidAccessException)
                {
                    finding.Warn("Security Hub not enabled");
                }
                catch (Exception ex)
                {
                    finding.Warn($"Security Hub check failed: {ex.Message}");
                }

                // Check Access Analyzer
                try
                {
                    using var analyzerClient = new AmazonAccessAnalyzerClient(credentials, RegionEndpoint.GetBySystemName(region));
                    var analyzersResponse = await analyzerClient.ListAnalyzersAsync(new ListAnalyzersRequest());
                    var allAnalyzers = new List<AnalyzerSummary>(analyzersResponse.Analyzers);
                    
                    // Handle pagination
                    while (!string.IsNullOrEmpty(analyzersResponse.NextToken))
                    {
                        analyzersResponse = await analyzerClient.ListAnalyzersAsync(new ListAnalyzersRequest
                        {
                            NextToken = analyzersResponse.NextToken
                        });
                        allAnalyzers.AddRange(analyzersResponse.Analyzers);
                    }
                    
                    if (!allAnalyzers.Any(a => a.Status == AnalyzerStatus.ACTIVE))
                    {
                        finding.Warn("IAM Access Analyzer not enabled");
                    }
                }
                catch (Exception ex)
                {
                    finding.Warn($"IAM Access Analyzer check failed: {ex.Message}");
                }

                // Check Inspector
                try
                {
                    using var inspectorClient = new AmazonInspector2Client(credentials, RegionEndpoint.GetBySystemName(region));
                    var status = await inspectorClient.GetDelegatedAdminAccountAsync(new GetDelegatedAdminAccountRequest());
                    // Note: Inspector status check is more complex
                    finding.Warn("Inspector status check - verify manually");
                }
                catch (Exception ex)
                {
                    finding.Warn($"Inspector check failed: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking security services: {ex.Message}");
            }

            return finding;
        }
    }
}


using Amazon;
using Amazon.ResourceGroupsTaggingAPI;
using Amazon.ResourceGroupsTaggingAPI.Model;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class TaggingBaselineChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("TAGGING", account);

            try
            {
                using var taggingClient = new AmazonResourceGroupsTaggingAPIClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                // Get all resources with pagination
                var allResources = new List<ResourceTagMapping>();
                var resourcesResponse = await taggingClient.GetResourcesAsync(new GetResourcesRequest
                {
                    ResourcesPerPage = 100
                });
                allResources.AddRange(resourcesResponse.ResourceTagMappingList);

                while (!string.IsNullOrEmpty(resourcesResponse.PaginationToken))
                {
                    resourcesResponse = await taggingClient.GetResourcesAsync(new GetResourcesRequest
                    {
                        ResourcesPerPage = 100,
                        PaginationToken = resourcesResponse.PaginationToken
                    });
                    allResources.AddRange(resourcesResponse.ResourceTagMappingList);
                }

                var requiredTags = new[] { "Environment", "Owner", "Project" };
                int missingTagCount = 0;

                foreach (var resource in allResources)
                {
                    var tagKeys = resource.Tags.Select(t => t.Key).ToList();
                    var missingTags = requiredTags.Where(rt => !tagKeys.Contains(rt)).ToList();
                    
                    if (missingTags.Any())
                    {
                        missingTagCount++;
                    }
                }

                if (missingTagCount > 0)
                {
                    finding.Warn($"{missingTagCount} resources missing mandatory tags");
                }
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking tagging baseline: {ex.Message}");
            }

            return finding;
        }
    }
}


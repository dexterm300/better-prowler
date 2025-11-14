using System;

namespace AwsSecurityAssessment.Models
{
    public class FindingTableRow
    {
        public string FindingTitle { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public string RecommendedFix { get; set; } = string.Empty;
        public FindingStatus Status { get; set; }
        public string AccountId { get; set; } = string.Empty;
        public string AccountName { get; set; } = string.Empty;
    }
}


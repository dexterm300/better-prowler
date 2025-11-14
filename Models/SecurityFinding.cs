using System;
using System.Collections.Generic;

namespace AwsSecurityAssessment.Models
{
    public enum FindingStatus
    {
        PASS,
        WARN,
        FAIL
    }

    public class SecurityFinding
    {
        public string AccountId { get; set; } = string.Empty;
        public string AccountName { get; set; } = string.Empty;
        public string CheckName { get; set; } = string.Empty;
        public FindingStatus Status { get; set; } = FindingStatus.PASS;
        public List<string> Messages { get; set; } = new List<string>();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        public void Fail(string message)
        {
            Status = FindingStatus.FAIL;
            Messages.Add(message);
        }

        public void Warn(string message)
        {
            if (Status != FindingStatus.FAIL)
            {
                Status = FindingStatus.WARN;
            }
            Messages.Add(message);
        }

        public void Pass()
        {
            // Ensure status is PASS and add message if none exists
            Status = FindingStatus.PASS;
            if (Messages.Count == 0)
            {
                Messages.Add("Check passed");
            }
        }
    }
}

namespace AwsSecurityAssessment.Models
{
    public class AwsCredentials
    {
        public string AccessKeyId { get; set; } = string.Empty;
        public string SecretAccessKey { get; set; } = string.Empty;
        public string Region { get; set; } = "us-east-1";
    }
}


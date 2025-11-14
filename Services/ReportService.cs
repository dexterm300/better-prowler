using Amazon;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using AwsSecurityAssessment.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Services
{
    public class ReportService
    {
        public void ExportToJson(List<SecurityFinding> findings, string filePath)
        {
            var json = JsonConvert.SerializeObject(findings, Formatting.Indented);
            File.WriteAllText(filePath, json);
        }

        public void ExportToCsv(ObservableCollection<FindingTableRow> tableRows, string filePath)
        {
            var csv = new StringBuilder();
            
            // Add header row
            csv.AppendLine("Finding Title,Details,Recommended Fix,Status,Account ID,Account Name");
            
            // Add data rows
            foreach (var row in tableRows)
            {
                // Escape commas and quotes in CSV values
                var title = EscapeCsvValue(row.FindingTitle);
                var details = EscapeCsvValue(row.Details);
                var recommendedFix = EscapeCsvValue(row.RecommendedFix);
                var status = EscapeCsvValue(row.Status.ToString());
                var accountId = EscapeCsvValue(row.AccountId);
                var accountName = EscapeCsvValue(row.AccountName);
                
                csv.AppendLine($"{title},{details},{recommendedFix},{status},{accountId},{accountName}");
            }
            
            File.WriteAllText(filePath, csv.ToString(), Encoding.UTF8);
        }

        private string EscapeCsvValue(string value)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;
            
            // If value contains comma, quote, or newline, wrap in quotes and escape internal quotes
            if (value.Contains(",") || value.Contains("\"") || value.Contains("\n") || value.Contains("\r"))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }
            
            return value;
        }

        public async Task UploadToS3Async(
            List<SecurityFinding> findings, 
            string bucketName, 
            string keyPrefix,
            AWSCredentials? credentials = null,
            string region = "us-east-1")
        {
            var json = JsonConvert.SerializeObject(findings, Formatting.Indented);
            var key = $"{keyPrefix}aws_security_assessment_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json";

            using var s3Client = credentials != null
                ? new AmazonS3Client(credentials, RegionEndpoint.GetBySystemName(region))
                : new AmazonS3Client(RegionEndpoint.GetBySystemName(region));
            
            var request = new PutObjectRequest
            {
                BucketName = bucketName,
                Key = key,
                ContentBody = json,
                ContentType = "application/json"
            };

            await s3Client.PutObjectAsync(request);
        }
    }
}

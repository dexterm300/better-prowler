using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public abstract class BaseSecurityChecker
    {
        protected SecurityFinding CreateFinding(string checkName, AccountInfo account)
        {
            return new SecurityFinding
            {
                AccountId = account.Id,
                AccountName = account.Name,
                CheckName = checkName
            };
        }

        public abstract Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region);
    }
}

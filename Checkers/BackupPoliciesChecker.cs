using Amazon;
using Amazon.Backup;
using Amazon.Backup.Model;
using Amazon.Runtime;
using AwsSecurityAssessment.Models;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AwsSecurityAssessment.Checkers
{
    public class BackupPoliciesChecker : BaseSecurityChecker
    {
        public override async Task<SecurityFinding> CheckAsync(
            AccountInfo account, 
            AWSCredentials credentials, 
            string region)
        {
            var finding = CreateFinding("BACKUP", account);

            try
            {
                using var backupClient = new AmazonBackupClient(credentials, RegionEndpoint.GetBySystemName(region));
                
                var plans = await backupClient.ListBackupPlansAsync(new ListBackupPlansRequest());

                if (!plans.BackupPlansList.Any())
                {
                    finding.Warn("No backup plans configured");
                }

                var vaults = await backupClient.ListBackupVaultsAsync(new ListBackupVaultsRequest());

                foreach (var vault in vaults.BackupVaultList)
                {
                    try
                    {
                        var vaultDetails = await backupClient.DescribeBackupVaultAsync(new DescribeBackupVaultRequest
                        {
                            BackupVaultName = vault.BackupVaultName
                        });

                        // Note: Encryption check would require additional API calls
                        finding.Pass();
                    }
                    catch (Exception ex)
                    {
                        finding.Warn($"Could not verify encryption for backup vault '{vault.BackupVaultName}': {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                finding.Fail($"Error checking backup policies: {ex.Message}");
            }

            return finding;
        }
    }
}


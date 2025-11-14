using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using AwsSecurityAssessment.Models;
using AwsSecurityAssessment.Services;
using AwsSecurityAssessment.ViewModels;
using Microsoft.Win32;

namespace AwsSecurityAssessment
{
    public partial class MainWindow : Window
    {
        private readonly AssessmentViewModel _viewModel;
        private readonly SecurityAssessmentService _assessmentService;
        private List<SecurityFinding> _allFindings = new List<SecurityFinding>();
        private ObservableCollection<FindingTableRow> _tableRows = new ObservableCollection<FindingTableRow>();

        public MainWindow()
        {
            InitializeComponent();
            _viewModel = new AssessmentViewModel();
            DataContext = _viewModel;
            _assessmentService = new SecurityAssessmentService();
            ResultsDataGrid.ItemsSource = _tableRows;
            
            // Add validation for Access Key ID
            AccessKeyIdTextBox.TextChanged += AccessKeyIdTextBox_TextChanged;
            
            // Add validation for Secret Access Key
            SecretAccessKeyPasswordBox.PasswordChanged += SecretAccessKeyPasswordBox_PasswordChanged;
        }

        private void SecretAccessKeyPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            var passwordBox = sender as PasswordBox;
            if (passwordBox == null) return;

            var secretKey = passwordBox.Password;
            
            // Limit to 40 characters
            if (secretKey.Length > 40)
            {
                var cursorPosition = secretKey.Length;
                passwordBox.Password = secretKey.Substring(0, 40);
                return; // Exit early to avoid re-triggering the event
            }
            
            // Clear previous error styling
            passwordBox.BorderBrush = null;
            passwordBox.ToolTip = null;

            if (string.IsNullOrEmpty(secretKey))
            {
                return; // Allow empty for now, will validate on button click
            }

            // Validate length
            if (!IsValidSecretAccessKey(secretKey))
            {
                passwordBox.BorderBrush = Brushes.Red;
                passwordBox.ToolTip = "Secret Access Key must be exactly 40 characters.";
            }
        }

        private bool IsValidSecretAccessKey(string secretKey)
        {
            if (string.IsNullOrWhiteSpace(secretKey))
                return false;

            // Must be exactly 40 characters
            return secretKey.Length == 40;
        }

        private void AccessKeyIdTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null) return;

            var accessKeyId = textBox.Text;
            
            // Convert to uppercase and remove invalid characters
            var cursorPosition = textBox.CaretIndex;
            var upperCaseKey = accessKeyId.ToUpperInvariant();
            var filteredKey = new string(upperCaseKey.Where(c => char.IsLetterOrDigit(c)).ToArray());
            
            // Limit to 20 characters
            if (filteredKey.Length > 20)
            {
                filteredKey = filteredKey.Substring(0, 20);
            }

            // Only update if the text actually changed
            if (filteredKey != accessKeyId)
            {
                textBox.Text = filteredKey;
                textBox.CaretIndex = Math.Min(cursorPosition, filteredKey.Length);
                return; // Exit early to avoid re-triggering the event
            }

            var trimmedKey = filteredKey.Trim();
            
            // Clear previous error styling
            textBox.BorderBrush = null;
            textBox.ToolTip = null;

            if (string.IsNullOrEmpty(trimmedKey))
            {
                return; // Allow empty for now, will validate on button click
            }

            // Validate format
            if (!IsValidAccessKeyId(trimmedKey))
            {
                textBox.BorderBrush = Brushes.Red;
                textBox.ToolTip = "Access Key ID must be 20 characters, start with 'AKIA', and contain only uppercase letters and numbers (A-Z, 0-9)";
            }
        }

        private bool IsValidAccessKeyId(string accessKeyId)
        {
            if (string.IsNullOrWhiteSpace(accessKeyId))
                return false;

            // Must be exactly 20 characters
            if (accessKeyId.Length != 20)
                return false;

            // Must start with "AKIA"
            if (!accessKeyId.StartsWith("AKIA", StringComparison.Ordinal))
                return false;

            // Must contain only uppercase letters and numbers [A-Z0-9]
            var regex = new Regex(@"^[A-Z0-9]{20}$");
            return regex.IsMatch(accessKeyId);
        }

        private async void StartAssessmentButton_Click(object sender, RoutedEventArgs e)
        {
            // Validate credentials
            if (string.IsNullOrWhiteSpace(_viewModel.AccessKeyId))
            {
                MessageBox.Show("Access Key ID is required.", "Validation Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
                AccessKeyIdTextBox.Focus();
                return;
            }

            if (!IsValidAccessKeyId(_viewModel.AccessKeyId))
            {
                MessageBox.Show("Access Key ID format is invalid. It must be:\n" +
                    "• Exactly 20 characters\n" +
                    "• Start with 'AKIA'\n" +
                    "• Contain only uppercase letters and numbers (A-Z, 0-9)", 
                    "Validation Error", MessageBoxButton.OK, MessageBoxImage.Error);
                AccessKeyIdTextBox.Focus();
                AccessKeyIdTextBox.SelectAll();
                return;
            }

            if (string.IsNullOrWhiteSpace(SecretAccessKeyPasswordBox.Password))
            {
                MessageBox.Show("Secret Access Key is required.", "Validation Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
                SecretAccessKeyPasswordBox.Focus();
                return;
            }

            if (!IsValidSecretAccessKey(SecretAccessKeyPasswordBox.Password))
            {
                MessageBox.Show("Secret Access Key must be exactly 40 characters.", 
                    "Validation Error", MessageBoxButton.OK, MessageBoxImage.Error);
                SecretAccessKeyPasswordBox.Focus();
                SecretAccessKeyPasswordBox.SelectAll();
                return;
            }

            try
            {
                StartAssessmentButton.IsEnabled = false;
                TestConnectionButton.IsEnabled = false;
                ProgressBar.Visibility = Visibility.Visible;
                ProgressBar.IsIndeterminate = true;
                StatusTextBlock.Text = "Starting assessment...";
                _tableRows.Clear();
                _allFindings.Clear();

                var credentials = new AwsCredentials
                {
                    AccessKeyId = _viewModel.AccessKeyId,
                    SecretAccessKey = SecretAccessKeyPasswordBox.Password,
                    Region = !string.IsNullOrWhiteSpace(RegionTextBox.Text) ? RegionTextBox.Text.Trim() : "us-east-1"
                };

                var config = new AssessmentConfig
                {
                    AuditRoleArn = !string.IsNullOrWhiteSpace(AuditRoleTextBox.Text) ? AuditRoleTextBox.Text.Trim() : string.Empty
                };

                await RunAssessmentAsync(credentials, config);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error during assessment: {ex.Message}\n\n{ex.StackTrace}", 
                    "Assessment Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                StartAssessmentButton.IsEnabled = true;
                TestConnectionButton.IsEnabled = true;
                ProgressBar.Visibility = Visibility.Collapsed;
                ProgressBar.IsIndeterminate = false;
                ExportButtonJson.IsEnabled = _allFindings.Any();
                ExportButtonCSV.IsEnabled = _allFindings.Any();
            }
        }

        private async void TestConnectionButton_Click(object sender, RoutedEventArgs e)
        {
            // Validate credentials
            if (string.IsNullOrWhiteSpace(_viewModel.AccessKeyId))
            {
                MessageBox.Show("Access Key ID is required.", "Validation Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
                AccessKeyIdTextBox.Focus();
                return;
            }

            if (!IsValidAccessKeyId(_viewModel.AccessKeyId))
            {
                MessageBox.Show("Access Key ID format is invalid. It must be:\n" +
                    "• Exactly 20 characters\n" +
                    "• Start with 'AKIA'\n" +
                    "• Contain only uppercase letters and numbers (A-Z, 0-9)", 
                    "Validation Error", MessageBoxButton.OK, MessageBoxImage.Error);
                AccessKeyIdTextBox.Focus();
                AccessKeyIdTextBox.SelectAll();
                return;
            }

            if (string.IsNullOrWhiteSpace(SecretAccessKeyPasswordBox.Password))
            {
                MessageBox.Show("Secret Access Key is required.", "Validation Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
                SecretAccessKeyPasswordBox.Focus();
                return;
            }

            if (!IsValidSecretAccessKey(SecretAccessKeyPasswordBox.Password))
            {
                MessageBox.Show("Secret Access Key must be exactly 40 characters.", 
                    "Validation Error", MessageBoxButton.OK, MessageBoxImage.Error);
                SecretAccessKeyPasswordBox.Focus();
                SecretAccessKeyPasswordBox.SelectAll();
                return;
            }

            try
            {
                TestConnectionButton.IsEnabled = false;
                StatusTextBlock.Text = "Testing connection...";

                var credentials = new AwsCredentials
                {
                    AccessKeyId = _viewModel.AccessKeyId,
                    SecretAccessKey = SecretAccessKeyPasswordBox.Password,
                    Region = !string.IsNullOrWhiteSpace(RegionTextBox.Text) ? RegionTextBox.Text.Trim() : "us-east-1"
                };

                var isConnected = await AwsClientService.TestConnectionAsync(credentials);

                if (isConnected)
                {
                    MessageBox.Show("Connection test successful! Credentials are valid.", 
                        "Connection Test", MessageBoxButton.OK, MessageBoxImage.Information);
                    StatusTextBlock.Text = "Connection test successful.";
                }
                else
                {
                    MessageBox.Show("Connection test failed. Please verify your credentials.", 
                        "Connection Test Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                    StatusTextBlock.Text = "Connection test failed.";
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error testing connection: {ex.Message}", 
                    "Connection Test Error", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusTextBlock.Text = $"Connection test error: {ex.Message}";
            }
            finally
            {
                TestConnectionButton.IsEnabled = true;
            }
        }

        private async Task RunAssessmentAsync(AwsCredentials credentials, AssessmentConfig config)
        {
            try
            {
                // Discover accounts
                StatusTextBlock.Text = "Discovering AWS Organization accounts...";
                var accounts = await _assessmentService.DiscoverAccountsAsync(credentials);
                AccountCountTextBlock.Text = $"Accounts: {accounts.Count}";

                int accountIndex = 0;
                foreach (var account in accounts)
                {
                    accountIndex++;
                    StatusTextBlock.Text = $"Assessing account {accountIndex}/{accounts.Count}: {account.Name} ({account.Id})";

                    // Perform all 16 security checks
                    var checkResults = await _assessmentService.PerformAllChecksAsync(account, credentials, config);
                    _allFindings.AddRange(checkResults);

                    // Add findings to table
                    foreach (var finding in checkResults)
                    {
                        var tableRow = CreateTableRow(finding);
                        _tableRows.Add(tableRow);
                    }

                    // Update counts
                    FindingsCountTextBlock.Text = $"Findings: {_allFindings.Count}";
                }

                StatusTextBlock.Text = $"Assessment complete. Found {_allFindings.Count} findings across {accounts.Count} accounts.";
            }
            catch (Exception ex)
            {
                var errorRow = new FindingTableRow
                {
                    FindingTitle = "ASSESSMENT_ERROR",
                    Details = $"Error: {ex.Message}",
                    RecommendedFix = "Please verify your credentials and permissions, then try again.",
                    Status = FindingStatus.FAIL,
                    AccountId = "N/A",
                    AccountName = "N/A"
                };
                _tableRows.Add(errorRow);
                StatusTextBlock.Text = $"Assessment failed: {ex.Message}";
            }
        }

        private FindingTableRow CreateTableRow(SecurityFinding finding)
        {
            var title = $"[{finding.Status}] {finding.CheckName} - {finding.AccountName} ({finding.AccountId})";
            var details = string.Join("; ", finding.Messages);
            var recommendedFix = GetRecommendedFix(finding);

            return new FindingTableRow
            {
                FindingTitle = title,
                Details = details,
                RecommendedFix = recommendedFix,
                Status = finding.Status,
                AccountId = finding.AccountId,
                AccountName = finding.AccountName
            };
        }

        private string GetRecommendedFix(SecurityFinding finding)
        {
            if (finding.Status == FindingStatus.PASS)
            {
                return "No action required - check passed.";
            }

            // Generate recommendations based on check name
            return finding.CheckName switch
            {
                "ROOT_HYGIENE" => "Enable MFA for root account. Remove root access keys if present. Monitor CloudTrail for root account usage.",
                "IAM_BASELINE" => "Review IAM policies and remove overly permissive access. Enable MFA for all users. Rotate access keys regularly. Remove AdministratorAccess from IAM users.",
                "CROSS_ACCOUNT_TRUST" => "Review and restrict cross-account trust policies. Add conditions to external trust relationships. Remove wildcard principals.",
                "CLOUDTRAIL" => "Enable multi-region CloudTrail. Enable log file validation. Ensure CloudTrail captures all regions and global services.",
                "AWS_CONFIG" => "Enable AWS Config recorder. Set up Config aggregator for organization-wide visibility.",
                "SECURITY_SERVICES" => "Enable GuardDuty, Security Hub, Access Analyzer, and Inspector for comprehensive security monitoring.",
                "S3_BASELINE" => "Enable account-level S3 Block Public Access. Encrypt all S3 buckets. Review bucket policies and ACLs.",
                "KMS_BASELINE" => "Review KMS key policies for overly permissive access. Enable automatic key rotation where supported.",
                "NETWORK_BASELINE" => "Remove default VPCs. Enable VPC Flow Logs. Configure VPC endpoints for S3 and SSM.",
                "MONITORING" => "Set up CloudWatch alarms for unauthorized API calls, root account usage, and GuardDuty findings.",
                "BILLING" => "Configure AWS Budgets with alerts. Review and restrict billing access permissions.",
                "TAGGING" => "Implement mandatory tagging policy. Tag all resources with Environment, Owner, and Project tags.",
                "BACKUP" => "Configure backup plans for critical resources. Enable encryption for backup vaults.",
                "IAC_GOVERNANCE" => "Use CloudFormation StackSets for organization-wide deployments. Enable drift detection.",
                "INCIDENT_READINESS" => "Document incident response runbooks. Conduct regular incident response testing. Establish incident response team.",
                "ORG_STRUCTURE" => "Attach Service Control Policies (SCPs) to accounts. Organize accounts into OUs with appropriate policies.",
                _ => "Review the finding details and consult AWS security best practices documentation."
            };
        }

        private void ExportButtonJson_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "JSON files (*.json)|*.json",
                    FileName = $"aws_security_assessment_{DateTime.Now:yyyyMMdd_HHmmss}.json"
                };

                if (dialog.ShowDialog() == true)
                {
                    var reportService = new ReportService();
                    reportService.ExportToJson(_allFindings, dialog.FileName);
                    MessageBox.Show($"Report exported successfully to {dialog.FileName}", 
                        "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error exporting report: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportButtonCSV_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dialog = new SaveFileDialog
                {
                    Filter = "CSV files (*.csv)|*.csv",
                    FileName = $"aws_security_assessment_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
                };

                if (dialog.ShowDialog() == true)
                {
                    var reportService = new ReportService();
                    reportService.ExportToCsv(_tableRows, dialog.FileName);
                    MessageBox.Show($"Report exported successfully to {dialog.FileName}", 
                        "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error exporting report: {ex.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RegionTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {

        }
    }
}

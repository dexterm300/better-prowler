using System.Windows;

namespace AwsSecurityAssessment
{
    public partial class S3UploadDialog : Window
    {
        public string BucketName { get; private set; } = string.Empty;
        public string KeyPrefix { get; private set; } = string.Empty;

        public S3UploadDialog()
        {
            InitializeComponent();
        }

        private void UploadButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(BucketNameTextBox.Text))
            {
                MessageBox.Show("Please enter a bucket name.", "Validation Error", 
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            BucketName = BucketNameTextBox.Text.Trim();
            KeyPrefix = KeyPrefixTextBox.Text.Trim();
            if (!string.IsNullOrEmpty(KeyPrefix) && !KeyPrefix.EndsWith("/"))
            {
                KeyPrefix += "/";
            }

            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}


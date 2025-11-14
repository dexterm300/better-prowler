using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace AwsSecurityAssessment.ViewModels
{
    public class AssessmentViewModel : INotifyPropertyChanged
    {
        private string _accessKeyId = string.Empty;

        public string AccessKeyId
        {
            get => _accessKeyId;
            set { _accessKeyId = value; OnPropertyChanged(); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}

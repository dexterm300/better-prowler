# Contributing to AWS Security Assessment Tool

Thank you for your interest in contributing to the AWS Security Assessment Tool! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Bugs

Before creating a bug report:
1. Check if the issue has already been reported in [GitHub Issues](https://github.com/dexterm300/better-prowler/issues)
2. Verify you're using the latest version
3. Gather relevant information (error messages, logs, steps to reproduce)

When creating a bug report, please include:
- **Description**: Clear description of the bug
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Environment**: OS version, .NET version, AWS region
- **Screenshots/Logs**: If applicable

### Suggesting Enhancements

Enhancement suggestions are welcome! When suggesting an enhancement:
1. Check if it's already been suggested
2. Provide a clear description of the enhancement
3. Explain the use case and benefits
4. Consider implementation complexity

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**:
   - Follow the coding standards (see below)
   - Add tests if applicable
   - Update documentation as needed
   - Ensure code compiles without warnings
4. **Test your changes**:
   - Test in a non-production AWS environment
   - Verify all existing functionality still works
   - Test edge cases and error conditions
5. **Commit your changes**:
   ```bash
   git commit -m "Add: Description of your changes"
   ```
   Use clear, descriptive commit messages following conventional commits format:
   - `Add:` for new features
   - `Fix:` for bug fixes
   - `Update:` for updates to existing features
   - `Refactor:` for code refactoring
   - `Docs:` for documentation changes
6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Create a Pull Request**:
   - Provide a clear title and description
   - Reference any related issues
   - Request review from maintainers

## Development Setup

### Prerequisites

- .NET 8.0 SDK
- Windows OS (for WPF development)
- Visual Studio 2022 or Visual Studio Code
- AWS account for testing (non-production recommended)

### Building the Project

```bash
# Clone your fork
git clone https://github.com/dexterm300/better-prowler.git
cd better-prowler

# Restore dependencies
dotnet restore

# Build the project
dotnet build

# Run the application
dotnet run
```

### Project Structure

```
better-prowler/
├── Checkers/          # Security check implementations
├── Models/            # Data models
├── Services/          # Business logic and AWS client services
├── ViewModels/        # MVVM view models
├── MainWindow.xaml    # Main UI
└── App.xaml           # Application definition
```

## Coding Standards

### C# Style Guidelines

- Follow [Microsoft C# Coding Conventions](https://docs.microsoft.com/en-us/dotnet/csharp/fundamentals/coding-style/coding-conventions)
- Use meaningful variable and method names
- Add XML documentation comments for public methods and classes
- Use `async`/`await` for asynchronous operations
- Handle exceptions appropriately with try-catch blocks
- Use nullable reference types where applicable

### Code Formatting

- Use 4 spaces for indentation (not tabs)
- Use `PascalCase` for public members
- Use `camelCase` for private fields and local variables
- Use `_camelCase` for private instance fields
- Add braces for all control structures, even single-line

### Example

```csharp
/// <summary>
/// Performs security check on IAM configuration.
/// </summary>
/// <param name="accountId">The AWS account ID to check</param>
/// <param name="credentials">AWS credentials for the account</param>
/// <returns>A security finding with the check results</returns>
public async Task<SecurityFinding> CheckIamBaselineAsync(
    string accountId, 
    AWSCredentials credentials)
{
    var finding = new SecurityFinding
    {
        CheckName = "IAM_BASELINE",
        AccountId = accountId
    };

    try
    {
        // Implementation here
    }
    catch (Exception ex)
    {
        finding.Warn($"Error during IAM check: {ex.Message}");
    }

    return finding;
}
```

### Error Handling

- Always handle exceptions appropriately
- Provide meaningful error messages
- Log errors for debugging (when logging is implemented)
- Don't swallow exceptions silently
- Use specific exception types when possible

### AWS API Calls

- Always use async methods for AWS SDK calls
- Implement proper pagination for list operations
- Handle AWS-specific exceptions (e.g., `AccessDeniedException`, `NoSuchEntityException`)
- Consider rate limiting and throttling
- Use appropriate retry logic for transient failures

## Adding New Security Checks

To add a new security check:

1. **Create a new checker class** in the `Checkers/` directory:
   ```csharp
   public class MyNewChecker : BaseSecurityChecker
   {
       public override string CheckName => "MY_NEW_CHECK";
       
       public override async Task<SecurityFinding> CheckAsync(
           string accountId, 
           AWSCredentials credentials)
       {
           var finding = InitializeFinding(accountId);
           // Implementation
           return finding;
       }
   }
   ```

2. **Register the checker** in `SecurityAssessmentService.cs`:
   ```csharp
   private readonly List<BaseSecurityChecker> _checkers = new()
   {
       // ... existing checkers
       new MyNewChecker()
   };
   ```

3. **Update documentation**:
   - Add to README.md features list
   - Document required permissions
   - Add any configuration requirements

## Testing

### Manual Testing

Before submitting a PR, test:
- ✅ Code compiles without warnings
- ✅ Application runs without crashes
- ✅ New features work as expected
- ✅ Existing features still work
- ✅ Error handling works correctly
- ✅ Edge cases are handled

### Testing Checklist

- [ ] Tested in a non-production AWS environment
- [ ] Verified with multiple AWS accounts
- [ ] Tested error scenarios (invalid credentials, missing permissions, etc.)
- [ ] Tested with different AWS regions
- [ ] Verified UI updates correctly
- [ ] Checked for memory leaks or performance issues

## Documentation

When adding features or making changes:

- Update README.md if user-facing functionality changes
- Add XML documentation comments to public APIs
- Update this CONTRIBUTING.md if contributing process changes
- Update code comments for complex logic

## Review Process

1. **Automated Checks**: PRs must pass all automated checks
2. **Code Review**: At least one maintainer must approve
3. **Testing**: Changes must be tested and verified
4. **Documentation**: Documentation must be updated if needed

## Questions?

If you have questions about contributing:
- Open a discussion in [GitHub Discussions](https://github.com/dexterm300/better-prowler/discussions)
- Check existing issues and PRs
- Review the codebase for examples

## License

By contributing, you agree that your contributions will be licensed under the GNU General Public License v3.0.

Thank you for contributing! 🎉


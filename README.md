# GitGuard

GitGuard is a web-based secret scanning tool that analyzes GitHub repositories and their commit history for accidentally exposed credentials and sensitive information.

The project combines regex-based detection with Shannon entropy analysis to identify both known secret formats and suspicious high-randomness strings.

## Features

- Scan public GitHub repositories
- Traverse commit history, not just the latest version
- Detect common secret types:
  - AWS Access Keys
  - GitHub Personal Access Tokens
  - Google API Keys
  - Stripe Secret Keys
  - JWT Tokens
  - Database Connection Strings
  - Private Key Headers
  - SendGrid API Keys
- Shannon entropy analysis for unknown secrets
- Context-aware detection using security-related keywords
- Severity classification (Critical, High, Medium, Low)
- False-positive filtering
- Swagger API documentation

## Technologies Used

### Backend
- ASP.NET Core Web API
- C#
- HttpClient
- GitHub REST API

### Frontend
- React

## How It Works

1. User submits a GitHub repository URL.
2. GitGuard retrieves repository commit history through the GitHub API.
3. Modified files are extracted from each commit.
4. Added lines are scanned using:
   - Regex-based detection
   - Entropy-based detection
5. Findings are classified and returned to the user.

## Project Structure

```text
Controllers/
 └── ScanController

Services/
 ├── GitHubClientService
 ├── ScanOrchestrator
 └── SecretDetectionEngine

Program.cs
appsettings.json
```

## Running the Project

### Backend

1. Open the solution in Visual Studio.
2. Configure your GitHub Personal Access Token in `appsettings.json`.
3. Run the project.
4. Open Swagger:

```text
https://localhost:<port>/swagger
```

### API Endpoint

```http
POST /api/scan/scan
```

Example request:

```json
{
  "repositoryUrl": "https://github.com/owner/repository",
  "maxCommits": 100
}
```

## Limitations

- Currently supports GitHub repositories only.
- Does not store scan history.
- Entropy analysis may occasionally generate low-severity false positives.

## Future Improvements

- GitLab and Bitbucket support
- Scan history persistence
- CI/CD integration
- Improved false-positive reduction
- AI-assisted finding explanations

## Author

**Khaled Hassan**

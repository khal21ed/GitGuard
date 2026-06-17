using System.Text.Json;
using SecureVault.Backend.Models;

namespace SecureVault.Backend.Services
{
    public class ScanOrchestrator
    {

        private readonly GitHubClientService _gitHub;
        private readonly SecretDetectionEngine _engine;

        public ScanOrchestrator(GitHubClientService gitHubClientService, SecretDetectionEngine engine)
        {
            _gitHub = gitHubClientService;
            _engine = engine;
        }
        private string ExtractAddedLines(string patch)
        {
            return string.Join("\n",
                patch.Split('\n')
                    .Where(line => line.StartsWith("+") && !line.StartsWith("+++"))
                    .Select(line => line[1..])); // strip the leading +
        }

        /// <summary>
        /// Scans a GitHub repository for potential secrets and returns an aggregated ScanResultDto.
        /// </summary>
        /// <param name="repositoryUrl">Any valid GitHub repository URL (ssh/https) that ParseRepositoryUrl can handle.</param>
        /// <param name="maxCommits">Maximum number of commits to traverse. Default is 100.</param>
        public async Task<ScanResultDto> ScanRepositoryAsync(string repositoryUrl, int maxCommits = 100)
        {
            var result = new ScanResultDto { RepositoryUrl = repositoryUrl };

            var (owner, repo) = _gitHub.ParseRepositoryUrl(repositoryUrl);
            var scannedBlobs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);


            var commits = await _gitHub.FetchCommitsAsync(owner, repo,maxCommits);
            Console.WriteLine($"[Orchestrator] Fetched {commits.Count} commits from {owner}/{repo}");

            if (commits == null || commits.Count == 0)
            {
                return result;
            }

            int traversed = 0;

            foreach (var commitElem in commits)
            {
                if (traversed >= maxCommits)  break;

                string sha = string.Empty;
                if (commitElem.TryGetProperty("sha", out var shaProp) && shaProp.ValueKind == JsonValueKind.String)
                {
                    sha = shaProp.GetString() ?? string.Empty;
                }

                // If we couldn't extract a SHA, skip this entry
                if (string.IsNullOrEmpty(sha)) {
                    Console.WriteLine($"[Orchestrator] Skipping commit entry — no SHA found");
                    continue;
                }
                ;

                traversed++;
                result.TotalCommitsTraversed = traversed;

                JsonElement commitDetails;
                try
                {
                    commitDetails = await _gitHub.FetchCommitDetailsAsync(owner, repo, sha);

                }
                catch
                {
                    // If fetching commit details fails, skip to next commit
                    continue;
                }

                if (!commitDetails.TryGetProperty("files", out var filesElem) || filesElem.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                Console.WriteLine($"[Orchestrator] Commit {sha} has {filesElem.GetArrayLength()} file(s)");
                foreach (var fileElem in filesElem.EnumerateArray())
                {

                    if (!fileElem.TryGetProperty("filename", out var filenameProp) || filenameProp.ValueKind != JsonValueKind.String)
                        continue;

                    var filename = filenameProp.GetString() ?? string.Empty;

                    if (_engine.IsBinaryFile(filename))
                    {
                        Console.WriteLine($"[Orchestrator] Skipping binary file: {filename}");

                        continue;
                    }
                    string blobSha = string.Empty;
                    if (fileElem.TryGetProperty("sha", out var blobShaProp) && blobShaProp.ValueKind == JsonValueKind.String)
                    {
                        blobSha = blobShaProp.GetString() ?? string.Empty;
                    }
                    if (!string.IsNullOrEmpty(blobSha) && !scannedBlobs.Add(blobSha))
                    {
                        Console.WriteLine($"[Orchestrator] Skipping already scanned blob: {filename} ({blobSha})");
                        continue;
                    }
                    string patchString = string.Empty;

                    // Prefer the 'patch' (diff) when available - it contains additions in the commit
                    if (fileElem.TryGetProperty("patch", out var patchProp) && patchProp.ValueKind == JsonValueKind.String)
                    {
                        patchString = patchProp.GetString() ?? string.Empty;
                    }
                    else if (fileElem.TryGetProperty("raw_url", out var rawUrlProp) && rawUrlProp.ValueKind == JsonValueKind.String)
                    {
                        var rawUrl = rawUrlProp.GetString();
                        if (!string.IsNullOrEmpty(rawUrl))
                        {
                            try
                            {
                                patchString = await _gitHub.FetchRawContentAsync(rawUrl);
                                result.TotalBlobsCached++;
                            }
                            catch
                            {
                                // ignore failures to fetch raw content
                                continue;
                            }
                        }
                    }

                    if (string.IsNullOrEmpty(patchString))
                    {
                        Console.WriteLine($"[Orchestrator] No content to scan for file: {filename} in commit {sha}");

                        continue;
                    }
                    Console.WriteLine($"[DEBUG] File: {filename} | ContentLength: {patchString.Length}");

                  string contentToScan=  ExtractAddedLines(patchString);
                    var findings = _engine.ScanText(contentToScan, filename, sha);

                    if (findings != null && findings.Count > 0)
                    {
                        result.Findings.AddRange(findings);
                        Console.WriteLine($"[Orchestrator] {findings.Count} finding(s) in {filename} @ {sha}");

                    }
                }
            }
            result.TotalBlobsCached = scannedBlobs.Count;
            return result;
        }
    }

}

using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Configuration; // Ensure this is imported

namespace SecureVault.Backend.Services
{
    public class GitHubClientService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;

        public GitHubClientService(HttpClient httpClient, IConfiguration configuration)
        {
            _httpClient = httpClient;
            _configuration = configuration;
            ApplyAuthentication();
        }

        private void ApplyAuthentication()
        {
            var token = _configuration["GitHub:Token"];
            if (!string.IsNullOrWhiteSpace(token))
            {
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
        }

        public async Task<List<JsonElement>> FetchCommitsAsync(string owner, string repo, int maxCommits = 1000)
        {

            var allCommits = new List<JsonElement>();
            int page = 1;
            bool keepFetching = true;

            while (keepFetching && allCommits.Count < maxCommits)
            {
                Console.WriteLine($"[GitHub] Fetching page {page} for {owner}/{repo} (fetched so far: {allCommits.Count})");

                // Calculate how many more commits we are allowed to fetch to avoid over-fetching
                int remainingToFetch = maxCommits - allCommits.Count;

                // GitHub limits per_page to a maximum of 100 items
                int pageSize = Math.Min(remainingToFetch, 100);

                // Build the URL containing both the maximum page size and the current page index
                string url = $"repos/{owner}/{repo}/commits?per_page={pageSize}&page={page}";

                JsonElement root = await SendRequestWithRateLimitCheckAsync(url);

                if (root.ValueKind == JsonValueKind.Array)
                {
                    var array = root.EnumerateArray();

                    // If the page is empty, we have reached the end of the commit history
                    if (!array.Any())
                    {
                        Console.WriteLine($"[GitHub] Empty page received — end of commit history");

                        keepFetching = false;
                        break;
                    }

                    foreach (var commit in array)
                    {
                        allCommits.Add(commit);

                        // Guard check to immediately drop out if we hit the limit mid-array
                        if (allCommits.Count >= maxCommits)
                        {
                            keepFetching = false;
                            break;
                        }
                    }

                    // Increment to request the next block of commits on the next iteration
                    page++;
                }
                else
                {
                    // If root is an object, it means GitHub returned an error payload (e.g., 404, Bad Request)
                    keepFetching = false;
                }
            }

            return allCommits;
        }

        public async Task<JsonElement> FetchCommitDetailsAsync(string owner, string repo, string sha)
        {
            Console.WriteLine($"[GitHub] Fetching details for commit {sha}");
            string url = $"repos/{owner}/{repo}/commits/{sha}";
            return await SendRequestWithRateLimitCheckAsync(url);
        }

        public async Task<string> FetchRawContentAsync(string rawUrl)
        {
            Console.WriteLine($"[GitHub] Fetching raw content from: {rawUrl}");
 
            return await _httpClient.GetStringAsync(rawUrl);
        }

        private async Task<JsonElement> SendRequestWithRateLimitCheckAsync(string relativeUrl)
        {
            HttpResponseMessage response = await _httpClient.GetAsync(relativeUrl);

            if (response.Headers.Contains("X-RateLimit-Remaining"))
            {
                var remainingStr = response.Headers.GetValues("X-RateLimit-Remaining").FirstOrDefault();
                var resetStr = response.Headers.GetValues("X-RateLimit-Reset").FirstOrDefault();

                if (int.TryParse(remainingStr, out int remaining) && remaining < 10)
                {
                    if (long.TryParse(resetStr, out long resetUnixTime))
                    {
                        var resetTime = DateTimeOffset.FromUnixTimeSeconds(resetUnixTime).ToLocalTime();
                        int delayMilliseconds = (int)(resetTime - DateTime.Now).TotalMilliseconds;
                        Console.WriteLine($"[GitHub] Rate limit low ({remaining} remaining) — sleeping until {resetTime}");

                        if (delayMilliseconds > 0)
                        {
                            await Task.Delay(delayMilliseconds + 1000);
                        }
                    }
                }
                Console.WriteLine($"[GitHub] Rate limit ({remaining} remaining)");

            }

            string jsonString = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(jsonString);
            return doc.RootElement.Clone();
        }

        public (string Owner, string Repo) ParseRepositoryUrl(string url)
        {
            var cleanedUrl = url.Trim().TrimEnd('/');

            if (cleanedUrl.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
            {
                cleanedUrl = cleanedUrl.Substring(0, cleanedUrl.Length - 4);
            }

            var uri = new Uri(cleanedUrl);
            var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length < 2)
            {
                throw new ArgumentException("Invalid GitHub repository URL structure.");
            }
            return (segments[0], segments[1]);
        }
    }
}
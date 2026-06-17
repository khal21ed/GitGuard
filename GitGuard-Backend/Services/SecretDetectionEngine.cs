using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using SecureVault.Backend.Models;

namespace SecureVault.Backend.Services
{
    public class SecretDetectionEngine
    {
        // Tier 1: Well-defined cryptographic signature mappings paired with severe classifications
        // Added RegexOptions.Compiled directly within initialization logic for enhanced throughput
        private readonly List<(string RuleName, Regex RegexPattern, string Severity)> _regexRules = new()
        {
            ( "AWS Access Key ID", new Regex(@"AKIA[A-Z0-9]{16}", RegexOptions.Compiled, RegexTimeout), "CRITICAL" ),
            ( "GitHub Personal Access Token", new Regex(@"ghp_[a-zA-Z0-9]{36}", RegexOptions.Compiled, RegexTimeout), "CRITICAL" ),
            ( "Slack Incoming Webhook", new Regex(@"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}", RegexOptions.Compiled, RegexTimeout), "HIGH" ),
            ( "Generic Connection String", new Regex(@"(?i)(mongodb\+srv|postgres|mysql):\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.-]+", RegexOptions.Compiled, RegexTimeout), "HIGH" ),
            ( "Hardcoded Password Assignment", new Regex(@"(?i)password\s*=\s*[""'](?!your|my|sample|example|placeholder)[^""']{4,}[""']", RegexOptions.Compiled, RegexTimeout), "HIGH" ),
( "Generic API Key Assignment", new Regex(@"(?i)(api_key|apikey|api-key)\s*[=:]\s*['""]?[a-zA-Z0-9_\-]{16,}['""]?", RegexOptions.Compiled, RegexTimeout), "HIGH" ),
( "Private Key Header", new Regex(@"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", RegexOptions.Compiled, RegexTimeout), "CRITICAL" ),
( "Google API Key", new Regex(@"AIza[0-9A-Za-z\-_]{35}", RegexOptions.Compiled, RegexTimeout), "CRITICAL" ),
( "Stripe Secret Key", new Regex(@"sk_(live|test)_[0-9a-zA-Z]{24,}", RegexOptions.Compiled,RegexTimeout), "CRITICAL" ),
( "JWT Token", new Regex(@"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", RegexOptions.Compiled,RegexTimeout), "HIGH" ),
( "SendGrid API Key", new Regex(@"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", RegexOptions.Compiled,RegexTimeout), "CRITICAL" ),
        };

        // Tier 2: Extract text inside quotes to analyze for un-prefixed passwords or asymmetric keys
        private static readonly Regex StringLiteralRegex = new(@"['""]([a-zA-Z0-9_\-\+=\/]{12,})['""]", RegexOptions.Compiled);

        // Pre-filtering Keywords: Scan around string assignments to contextualize candidate text strings
        private static readonly string[] HighSignalKeywords = { "secret", "password", "passwd", "key", "token", "connectionstring", "credential", "private" };

        private readonly HashSet<string> _binaryExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".exe", ".dll", ".zip", ".tar", ".gz", ".woff", ".ico"
        };

        // Path exclusion filters to drop massive false-positive noise generating assets (Lockfiles / Minified libraries)
        private readonly string[] _excludedPathSegments = {
    "/node_modules/", "/obj/", "/bin/",
    "package-lock.json", ".pnpm-lock.yaml", "yarn.lock"
};

        private readonly HashSet<string> _placeholderValues = new(StringComparer.OrdinalIgnoreCase)
{
    "your_api_key", "my_api_key", "api_key_here", "insert_key_here",
    "placeholder", "example", "changeme", "xxxxxxxx", "00000000",
    "your_token", "my_token", "your_secret", "my_secret"
};
        private readonly HashSet<string> _excludedFileNames = new(StringComparer.OrdinalIgnoreCase)
{
    ".gitignore",
    ".gitattributes",
    ".editorconfig"
};

        private readonly HashSet<string> _excludedExtensions = new(StringComparer.OrdinalIgnoreCase)
{
    ".csproj", ".vbproj", ".fsproj",  // project files
    ".sln", ".slnx",                   // solution files
    ".props", ".targets"               // MSBuild files
};
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1.5);

        public List<FindingDto> ScanText(string text, string filePath, string commitSha)
        {
            Console.WriteLine($"[Engine] Scanning file: {filePath} | Content length: {text.Length}");

            var findings = new List<FindingDto>();
            if (string.IsNullOrEmpty(text)) return findings;

            // False positive mitigation: Early exit if file lives in standard package-lock or transient build directories
            // Existing path segment check
            if (_excludedPathSegments.Any(segment => filePath.Contains(segment, StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine($"[Engine] Skipped (path filter): {filePath}");
                return findings;
            }

            // New: exact filename check
            string fileName = Path.GetFileName(filePath);
            if (_excludedFileNames.Contains(fileName))
            {
                Console.WriteLine($"[Engine] Skipped (excluded filename): {fileName}");
                return findings;


            }
            // New: extension check
            string ext = Path.GetExtension(filePath);
            if (_excludedExtensions.Contains(ext))
            {
                Console.WriteLine($"[Engine] Skipped (excluded extension): {ext} — {filePath}");
                return findings;


            }

            // Architecture Fix: Track the unmasked raw tokens captured to accurately prevent double-reporting findings
            var trackedRawSecrets = new HashSet<string>();

            // 1. Run Signature-Based Rules (Regex Matchers)
            foreach (var rule in _regexRules)
            {
                try
                {
                    var matches = rule.RegexPattern.Matches(text);

                    foreach (Match match in matches)
                    {
                        Console.WriteLine($"[Engine] Rule '{rule.RuleName}' matched in {filePath}");

                        string rawSecret = match.Value;
                        trackedRawSecrets.Add(rawSecret);

                        // Inside the regex loop, before adding a finding
                        if (_placeholderValues.Any(p => rawSecret.Contains(p, StringComparison.OrdinalIgnoreCase)))
                            continue;

                        findings.Add(new FindingDto
                        {
                            RuleName = rule.RuleName,
                            FilePath = filePath,
                            CommitSha = commitSha,
                            MatchedText = MaskSecret(rawSecret),
                            Severity = rule.Severity,
                            EntropyScore = Math.Round(CalculateShannonEntropy(rawSecret), 2)
                        });
                    }
                }
                catch (RegexMatchTimeoutException)
                {
                    // Gracefully log or handle timeout bounds while keeping the broader orchestrator scanner alive
                    Console.WriteLine($"[Timeout] Regex rule '{rule.RuleName}' timed out scanning file: {filePath}");
                }
            }

            // 2. Run Context & Entropy-Based Rules on Raw String Content
            try
            {
                var literals = StringLiteralRegex.Matches(text);
                foreach (Match literal in literals)
                {
                    string extractedValue = literal.Groups[1].Value;

                    // Mitigation Fix: Compare against raw unmasked values directly to solve the masking deduplication bug
                    if (trackedRawSecrets.Any(secret => extractedValue.Contains(secret)))
                    {
                        continue;
                    }

                    // Check context around the match inside the text block to verify if it is near high-signal structural variables
                    bool isNearKeyword = false;
                    int startWindow = Math.Max(0, literal.Index - 40);
                    int endWindow = Math.Min(text.Length, literal.Index + literal.Length + 40);
                    string neighborhoodContext = text[startWindow..endWindow];

                    if (HighSignalKeywords.Any(kw => neighborhoodContext.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                    {
                        isNearKeyword = true;
                    }

                    double entropy = CalculateShannonEntropy(extractedValue);

                   
                    // Lower requirement to 3.5 if explicitly bound next to key/password context variables.
                    // Otherwise maintain strict baseline threshold of 4.5 to avoid false flags.
                    double requiredThreshold = isNearKeyword ? 3.5 : 4.5;

                    if (entropy > requiredThreshold)
                    {
                        
                        if (_placeholderValues.Any(p => extractedValue.Contains(p, StringComparison.OrdinalIgnoreCase)))
                            continue;
                        findings.Add(new FindingDto
                        {
                            RuleName = isNearKeyword ? "High-Signal Entropy Assignment" : "High Entropy String Literal",
                            FilePath = filePath,
                            CommitSha = commitSha,
                            MatchedText = MaskSecret(extractedValue),
                            Severity = entropy >= 5.5 ? "HIGH" :entropy>=4.0?"MEDUIM": "LOW",
                            EntropyScore = Math.Round(entropy, 2) 
                        });
                    }
                }
            }
            catch (RegexMatchTimeoutException)
            {
                Console.WriteLine($"[Timeout] High Entropy scanning loop timed out on file: {filePath}");
            }

            return findings;
        }

        public bool IsBinaryFile(string filename)
        {
            string ext = Path.GetExtension(filename);
            return _binaryExtensions.Contains(ext);
        }

       
        public double CalculateShannonEntropy(string secret)
        {
            if (string.IsNullOrEmpty(secret)) return 0;

            var frequencies = secret.GroupBy(c => c)
                                    .ToDictionary(g => g.Key, g => (double)g.Count() / secret.Length);

            double entropy = 0;
            foreach (var frequency in frequencies.Values)
            {
                entropy -= frequency * Math.Log2(frequency);
            }

            return entropy;
        }

        /// <summary>
        /// Mask secrets so sensitive strings don't leak into memory logs or UI views unencrypted.
        /// </summary>
        private string MaskSecret(string secret)
        {
            if (string.IsNullOrEmpty(secret)) return string.Empty;
            if (secret.Length <= 8) return new string('*', secret.Length);
            return secret[..4] + new string('*', secret.Length - 8) + secret[^4..];
        }
    }
}
namespace SecureVault.Backend.Models
{
    
        public class FindingDto
        {
            public string RuleName { get; set; } = string.Empty;
            public string FilePath { get; set; } = string.Empty;
            public string CommitSha { get; set; } = string.Empty;
            public string MatchedText { get; set; } = string.Empty;
            public string Severity { get; set; } = "LOW"; // LOW, MEDIUM, HIGH, CRITICAL
            public double EntropyScore { get; set; }
        }
    

    public class ScanResultDto
    {
        public string RepositoryUrl { get; set; } = string.Empty;
        public int TotalCommitsTraversed { get; set; }
        public int TotalBlobsCached { get; set; }
        public List<FindingDto> Findings { get; set; } = new List<FindingDto>();
    }
}
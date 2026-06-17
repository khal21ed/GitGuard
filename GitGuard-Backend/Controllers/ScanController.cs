using Microsoft.AspNetCore.Mvc;
using SecureVault.Backend.Models;
using SecureVault.Backend.Services;

namespace SecureVault.Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ScanController : ControllerBase
    {
        private readonly ScanOrchestrator _orchestrator;

        public ScanController(ScanOrchestrator orchestrator)
        {
            _orchestrator = orchestrator;
        }

        [HttpPost("scan")]
        public async Task<ActionResult<ScanResultDto>> ScanRepository([FromBody] ScanRequest request)
        {
            Console.WriteLine($"[Controller] Scan requested for: {request.RepositoryUrl} | MaxCommits: {request.MaxCommits}");

            if (request == null || string.IsNullOrWhiteSpace(request.RepositoryUrl))
            {
                return BadRequest("RepositoryUrl is required in the request body.");
            }

            if (!Uri.TryCreate(request.RepositoryUrl, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                return BadRequest("Invalid repository URL. Must be an absolute http(s) URL.");
            }

            if (!uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) &&
                !uri.Host.EndsWith(".github.com", StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest("Repository URL must be a GitHub URL (github.com).");
            }

            try
            {
                var result = await _orchestrator.ScanRepositoryAsync(request.RepositoryUrl, request.MaxCommits ?? 100);
                Console.WriteLine($"[Controller] Scan complete — {result.TotalCommitsTraversed} commits, {result.Findings.Count} findings");

                return Ok(result);
            }
            catch (ArgumentException aex)
            {
                return BadRequest(aex.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Scan failed: {ex.Message}");
            }
        }
    }

    public class ScanRequest
    {
        public string RepositoryUrl { get; set; } = string.Empty;
        public int? MaxCommits { get; set; }
    }
}

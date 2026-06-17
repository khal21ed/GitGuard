using SecureVault.Backend.Services;
using System.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var allowedOrigins = new[]
{
    "http://localhost:5173",
    "http://127.0.0.1:5173"
};

builder.Services.AddCors(options =>
{
    options.AddPolicy("GitGuardFrontend", policy =>
    {
        policy
            .WithOrigins(allowedOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

// Configure the Typed HttpClient for GitHubClientService
builder.Services.AddHttpClient<GitHubClientService>(client =>
{
    client.BaseAddress = new Uri("https://api.github.com/");
    client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("SecureVault-Scanner-API", "1.0"));
    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
});

// Register scanning services
builder.Services.AddSingleton<SecretDetectionEngine>();
builder.Services.AddScoped<ScanOrchestrator>();

var app = builder.Build();

// Enable Swagger UI always
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.RoutePrefix = "swagger"; // serve at /swagger
});
app.UseCors("GitGuardFrontend");

app.UseAuthorization();
app.MapControllers();
app.Run();
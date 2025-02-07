using DotNetEnv;
using MongoDB.Driver;
using project_backend.Data;
using project_backend.Services;

var builder = WebApplication.CreateBuilder(args);

// Load environment variables from .env file
Env.Load();

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddSingleton<MongoDbContext>();

// Register IMongoDatabase with a scoped lifetime
builder.Services.AddScoped<IMongoDatabase>(sp =>
{
    var dbContext = sp.GetRequiredService<MongoDbContext>();
    return dbContext.Users.Database; // Returns the IMongoDatabase instance
});

builder.Services.AddScoped<AuthService>();
builder.Services.AddSingleton<JwtService>();
builder.Services.AddSingleton<UserService>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins", policy =>
    {
        policy.AllowAnyOrigin() // Allow requests from any origin
            .AllowAnyHeader() // Allow any headers
            .AllowAnyMethod(); // Allow any HTTP methods
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseCors("AllowAllOrigins");

app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();


app.Run();

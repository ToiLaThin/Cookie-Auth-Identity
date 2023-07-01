using CookieAuthMinimalApiWithIdentity.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

var connStr = builder.Configuration.GetConnectionString("MyConnStr");
builder.Services.AddDbContext<UserIdentityContext>(option =>
{
    option.UseSqlServer(connStr, action => action.MigrationsHistoryTable("_MigrationsHistory", "Identity"));
});
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
                .AddRoleManager<RoleManager<IdentityRole>>()//co the dependency injection dc
                .AddEntityFrameworkStores<UserIdentityContext>();
builder.Services.Configure<IdentityOptions>(config =>
{
    config.Password.RequireNonAlphanumeric = false;
    config.Password.RequireDigit = false;
    config.Password.RequireLowercase = false;
    config.Password.RequireUppercase = false;
    config.Password.RequiredLength = 3;

    config.User.RequireUniqueEmail = false;

    config.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromSeconds(10);
    config.Lockout.MaxFailedAccessAttempts = 3;
});
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var app = builder.Build();
app.MapGet("/init", (HttpContext ctx,RoleManager<IdentityRole> roleManager) => {
    IdentityRole role = new IdentityRole("user");
    var result = roleManager.CreateAsync(role);
    if(result.Result.Succeeded) {
        return Task.CompletedTask;
    }
    return Task.FromException(new Exception(result.Result.Errors.ToString()));

});

app.MapPost("/register",async (HttpContext ctx,
                          [FromBody] RegisterInfoDTO registerInfo,
                          UserManager<IdentityUser> userManager) =>  
{
    if (registerInfo != null)
    {
        if(registerInfo.Password.Equals(registerInfo.PasswordConfirmed))
        {
            IdentityUser newUser = new IdentityUser(registerInfo.UserName);
            newUser.Email = registerInfo.Email;
            var result = await userManager.CreateAsync(newUser, registerInfo.Password);
            if(result.Succeeded)
            {
                var claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.Name, registerInfo.UserName));
                claims.Add(new Claim(ClaimTypes.Email, registerInfo.Email));
                await userManager.AddClaimsAsync(newUser, claims);
                var result2 = await userManager.AddToRoleAsync(user: newUser, role: "user");
                if(result2.Succeeded)
                    return "ok";
            }
        }
    }
    return "not-ok";
});

app.MapPost("/login", (HttpContext ctx,
                       [FromBody] LoginInfoDTO loginInfo,
                       SignInManager<IdentityUser> signInManager,
                       UserManager<IdentityUser> userManager) =>
{
    if(loginInfo != null)
    {
        var result = signInManager.PasswordSignInAsync(loginInfo.Username, loginInfo.Password, false, false);
        if(result.Result.Succeeded)
        {
            var claims = userManager.GetClaimsAsync(new IdentityUser(loginInfo.Username));
        }
    }
});
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.Run("https://localhost:6200");


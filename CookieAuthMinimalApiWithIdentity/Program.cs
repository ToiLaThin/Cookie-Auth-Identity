using CookieAuthMinimalApiWithIdentity.Data;
using CookieAuthMinimalApiWithIdentity.Helpers;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
#region Configure Service in Dependency container
var connStr = builder.Configuration.GetConnectionString("MyConnStr");
builder.Services.AddDbContext<UserIdentityContext>(option =>
{
    option.UseSqlServer(connStr, action => action.MigrationsHistoryTable("_MigrationsHistory", "Identity"));
});
builder.Services.AddScoped<SessionService>();
builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
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
#endregion
var app = builder.Build();

#region Custom Middleware To Extract data from cookie
app.Use((ctx, next) =>
{
    var idp = ctx.RequestServices.GetRequiredService<IDataProtectionProvider>();
    var protector = idp.CreateProtector("auth-cookie");
    var authDataWithName = ctx.Request.Headers.Cookie.FirstOrDefault(c => c.StartsWith("auth"));
    if (authDataWithName != null) //check cookie if not valid => user not authenticated
    {
        var authData = authDataWithName.Split("=").Last();
        var payloadDecrypted = protector.Unprotect(authData);
        string[] datas = payloadDecrypted.Split("+"); //datas is keyvalue string[] formatlike key:value

        var claims = new List<Claim>(); //convert datas into list of claims including session
        foreach (string data in datas)
        {
            string[] parts = data.Split(":");
            string type = parts[0];
            string value = parts[1];
            Claim newClaim = new Claim(type, value);
            claims.Add(newClaim);
        }

        Claim? sessionClaim = claims.Find(c => c.Type == "sessionId");
        string sessionId = sessionClaim.Value;
        SessionService sessionService = ctx.RequestServices.GetRequiredService<SessionService>();
        if (sessionService.GetData<bool>(sessionId) == true)
        { //neu co session id trong cache => user da authenticated => tao claim principle va set identity.isAuthenticated = true
            ClaimsIdentity identity = new ClaimsIdentity(claims);
            ctx.User = new ClaimsPrincipal(identity); //authenticated mean have session id claim
        }
        else
        {
            //if session id expires and the cookie still store in browser => delete it
            ctx.Response.Cookies.Delete("auth");
        }
    }
    return next();
});
#endregion

#region Endpoints
app.MapGet("/init", (HttpContext ctx,RoleManager<IdentityRole> roleManager) => { //tao role user
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

app.MapPost("/login",async (HttpContext ctx,
                       [FromBody] LoginInfoDTO loginInfo,
                       SignInManager<IdentityUser> signInManager,
                       UserManager<IdentityUser> userManager,
                       SessionService sessionService,
                       IDataProtectionProvider idp,
                       IHttpContextAccessor accessor) =>
{
    Claim? sessionClaim = ctx.User?.Claims.FirstOrDefault(c => c.Type == "sessionId");
    if (sessionClaim != null)
    {
        return "already logged in";
    }
    if(loginInfo != null) //not logged in
    {
        var result = signInManager.PasswordSignInAsync(loginInfo.Username, loginInfo.Password, false, false);
        if(result.Result.Succeeded)
        {
            var signedInUser = await userManager.FindByNameAsync(loginInfo.Username);
            Guid sessionId = sessionService.GenerateSessionId();
            var protector = idp.CreateProtector("auth-cookie");
            var claims = (await userManager.GetClaimsAsync(signedInUser)).ToList(); //var claims = ctx.User.Claims.ToList();

            //got claims and session id now save it to cache and set cookie
            sessionService.SetData(sessionId.ToString(), true , DateTime.Now.AddMinutes(1));
            string userData = String.Empty;
            foreach(var claim in claims) {
                int lastIdxOfChar = claim.Type.LastIndexOf("/");
                userData += $"{claim.Type.Substring(lastIdxOfChar + 1)}:{claim.Value}+";
            }
            string finalDataToProtect = $"{userData}sessionId:{sessionId}";
            accessor.HttpContext.Response.Headers["set-cookie"] = $"auth={protector.Protect(finalDataToProtect)}";
            return "ok";
        }
    }
    return "not ok";
});

app.MapGet("/logout", (HttpContext ctx,
                       SessionService sessionService) =>
{
    Claim? sessionClaim = ctx.User?.Claims.FirstOrDefault(c => c.Type == "sessionId");
    if (sessionClaim != null)
    {
        string sessionId = sessionClaim.Value;
        sessionService.RemoveData(sessionId);
        ctx.Response.Cookies.Delete("auth");
        return "logged out";

    }
    return "login required";

});

app.MapGet("/getCurrentUserInfo", (HttpContext ctx, SessionService sessionService) =>
{
    Claim? sessionClaim = ctx.User?.Claims.FirstOrDefault(c => c.Type == "sessionId");
    if (sessionClaim != null)
    {
        string result = String.Empty;
        foreach(var claim in ctx.User.Claims)
        {
            result += $"{claim.Type}:{claim.Value}\n";
        }
        return result;
    }
    return "login required"; //in the middleware the cookie will be set to delete already
});
#endregion

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.Run("https://localhost:6200");


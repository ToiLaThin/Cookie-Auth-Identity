using CookieAuthMinimalApiWithIdentity.Data;
using CookieAuthMinimalApiWithIdentity.Helpers;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

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

app.MapPost("/login",async (HttpContext ctx,
                       [FromBody] LoginInfoDTO loginInfo,
                       SignInManager<IdentityUser> signInManager,
                       UserManager<IdentityUser> userManager,
                       SessionService sessionService,
                       IDataProtectionProvider idp,
                       IHttpContextAccessor accessor) =>
{
    if(loginInfo != null)
    {
        var result = signInManager.PasswordSignInAsync(loginInfo.Username, loginInfo.Password, false, false);
        if(result.Result.Succeeded)
        {
            var signedInUser = await userManager.FindByNameAsync(loginInfo.Username);
            Guid sessionId = sessionService.GenerateSessionId();
            var protector = idp.CreateProtector("auth-cookie");
            var claims = (await userManager.GetClaimsAsync(signedInUser)).ToList(); //var claims = ctx.User.Claims.ToList();

            //got claims and session id now save it to cache and set cookie
            sessionService.SetData(sessionId.ToString(), true , DateTime.Now.AddMinutes(5));
            string userData = String.Empty;
            foreach(var claim in claims) {
                userData += $"{claim.Type}:{claim.Value}+";
            }
            string finalDataToProtect = $"{userData}sessionId:{sessionId}";
            accessor.HttpContext.Response.Headers["set-cookie"] = $"auth={protector.Protect(finalDataToProtect)}";
            return "ok";
        }
    }
    return "not ok";
});

app.MapGet("/logout", (HttpContext ctx,
                       IDataProtectionProvider idp,
                       SessionService sessionService) =>
{
    var protector = idp.CreateProtector("auth-cookie");
    var authDataWithName = ctx.Request.Headers.Cookie.FirstOrDefault(c => c.StartsWith("auth"));
    if (authDataWithName != null) //check cookie if not valid => login required
    {
        var authData = authDataWithName.Split("=").Last();
        var payloadDecrypted = protector.Unprotect(authData);
        //string[] datas = payloadDecrypted.Split("+");
        //List<string> types = new List<string>();
        //List<string> values = new List<string>();

        //foreach(string data in datas)
        //{
        //    string[] parts = data.Split(":");
        //    string type = parts[0];
        //    string value = parts[1];
        //    types.Add(type); 
        //    types.Add(value);
        //}

        //get session only and check if it's in cache
        string sessionIdData = payloadDecrypted.Substring(payloadDecrypted.IndexOf("sessionId"));
        string sessionId = sessionIdData.Split(":").Last();
        if(sessionService.GetData<bool>(sessionId) == true)
        {
            sessionService.RemoveData(sessionId);
        }
        ctx.Response.Cookies.Delete("auth");
        return "logged out";
    }
    return "login required";

});

app.MapGet("/getCurrentUserInfo", (HttpContext ctx,
                       IDataProtectionProvider idp,
                       SessionService sessionService) =>
{
    var protector = idp.CreateProtector("auth-cookie");
    var authDataWithName = ctx.Request.Headers.Cookie.FirstOrDefault(c => c.StartsWith("auth")); //phan code trung lap => chuyen sang dung middleware
    if (authDataWithName != null) //check cookie if not valid => login required
    {
        
        var authData = authDataWithName.Split("=").Last();
        var payloadDecrypted = protector.Unprotect(authData);

        //get session only and check if it's in cache
        string sessionIdData = payloadDecrypted.Substring(payloadDecrypted.IndexOf("sessionId"));
        string sessionId = sessionIdData.Split(":").Last();
        if (sessionService.GetData<bool>(sessionId) == true) //which mean user is logged in
        {
            string[] datas = payloadDecrypted.Split("+");
            List<string> types = new List<string>();
            List<string> values = new List<string>();

            foreach (string data in datas)
            {
                string[] parts = data.Split(":");
                string type = parts[0];
                string value = parts[1];
                types.Add(type);
                values.Add(value);
            }
            return types.ToString() + values.ToString();
        }
        else //session id expirered => delete cookie and login required
            ctx.Response.Cookies.Delete("auth");
    }
    return "login required";

});
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.Run("https://localhost:6200");


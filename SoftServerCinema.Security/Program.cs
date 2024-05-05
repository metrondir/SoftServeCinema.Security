using SoftServerCinema.Security.DataAccess;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

using System.Text;
using SoftServerCinema.Security.Interfaces;
using SoftServerCinema.Security.Services;
using SoftServerCinema.Security.Validators;
using SoftServerCinema.Security.Entities;
using FluentValidation;

using SoftServerCinema.Security.Services.Authentication;
using SoftServerCinema.Security.ErrorFilter;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddControllers(options =>
{
    options.Filters.Add(typeof(GlobalExceptionFilter));
});


builder.Services.AddValidatorsFromAssemblyContaining<UserRegisterDTOValidator>();
builder.Services.AddValidatorsFromAssemblyContaining<UserLoginDTOValidator>();
builder.Services.AddValidatorsFromAssemblyContaining<EmailDTOValidator>();
builder.Services.AddValidatorsFromAssemblyContaining<ResetCodeDTOValidator>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();



builder.Services.AddDbContext<SecurityContext>(options =>
{
    options.UseMySQL(builder.Configuration.GetConnectionString("db"));
});


builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddTransient<ITokenGenerator, TokenGenerator>();

builder.Services.AddIdentity<UserEntity, IdentityRole<Guid>>()
    .AddEntityFrameworkStores<SecurityContext>()
    .AddDefaultTokenProviders();


builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowMyOrigins", policy =>
    {
        policy
        .AllowAnyOrigin()
        .AllowAnyMethod()
        .AllowAnyHeader();
    });
});

var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(builder.Configuration["JWT:SecretKey"]));
var tokenValidationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = builder.Configuration["JWT:Issuer"],

    ValidateAudience = true,
    ValidAudience = builder.Configuration["JWT:Audience"],

    ValidateLifetime = true,

    ValidateIssuerSigningKey = true,
    ClockSkew = TimeSpan.Zero,
    IssuerSigningKey = key

};

var authConfig = new AuthSettings();
builder.Configuration.GetSection("JWT").Bind(authConfig);
builder.Services.AddSingleton(authConfig);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddCookie()
    .AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
    {
        options.ClientId = builder.Configuration.GetSection("Autorization:ClientId").Value;
        options.ClientSecret = builder.Configuration.GetSection("Autorization:ClientSecret").Value;
    })
    .AddJwtBearer(options =>
    {   options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = tokenValidationParameters;
    });

var app = builder.Build();



if(app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseStaticFiles();


app.UseRouting();
app.UseCors("AllowMyOrigins");
app.UseHttpsRedirection();


app.UseAuthentication();
app.UseAuthorization();


app.MapControllers();

using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();

    var roles = new[] { "Admin", "User","SuperAdmin" };
    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole<Guid>(role));
    }
}

app.Run();


using System.Text;
using System.Text.Json.Serialization;
using API.Configurations;
using API.Data;
using API.Entity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers().AddJsonOptions(x=>x.JsonSerializerOptions.ReferenceHandler=ReferenceHandler.IgnoreCycles);

builder.Services.AddDbContext<StoreContext>(options => 
{options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.Configure<JwtConfig>(builder.Configuration.GetSection("JwtConfig"));
var key = Encoding.ASCII.GetBytes(builder.Configuration.GetSection("JwtConfig:Secret").Value);
var tokenValidationParams=new TokenValidationParameters()
      {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false,
        RequireExpirationTime = false,
        ValidateLifetime = true
      };

builder.Services.AddAuthentication(options => 
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
   .AddJwtBearer(jwt => 
   {
      

      jwt.SaveToken = true;
      jwt.TokenValidationParameters=tokenValidationParams ;
   });
builder.Services.AddSingleton(tokenValidationParams);

// builder.Services.AddDefaultIdentity<AppUser,AppRole>(options => options.SignIn.RequireConfirmedAccount = false)
//          .AddEntityFrameworkStores<StoreContext>();

builder.Services.AddIdentity<AppUser,AppRole>(x=>
{
    x.Password.RequireLowercase = false;
}).AddEntityFrameworkStores<StoreContext>();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swa
builder.Services.AddCors(c =>  
{  
    c.AddPolicy("AllowOrigin", options => options.AllowAnyOrigin());  
});

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("oauth2" , new OpenApiSecurityScheme
    {
        Description = "Standard Authorization header using the Bearer scheme (\"bearer {token}\")",
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey

    });
    options.OperationFilter<SecurityRequirementsOperationFilter>();
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors(options => options.AllowAnyOrigin()); 

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();



using var scope = app.Services.CreateScope();
var services = scope.ServiceProvider;
var loggerFactory = services.GetRequiredService<ILoggerFactory>();
try
{
    var context = services.GetRequiredService<StoreContext>();
    await context.Database.MigrateAsync();

}
catch (Exception ex)
{
    var logger = loggerFactory.CreateLogger<Program>();
    logger.LogError(ex, "An error occured during migration");
}



app.Run();

using System.Text;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

// --- CORS ---
builder.Services.AddCors(options =>
{
    options.AddPolicy(
        "AllowAll",
        policy =>
        {
            policy
                .AllowAnyOrigin() //para pruebas, permite todas las apps
                .AllowAnyHeader()
                .AllowAnyMethod();
        }
    );
});

//API
builder.Services.AddControllers(); //Controladores para API
var config = builder.Configuration; //leer configuracion
var secretKey = config["TokenAuthentication:SecretKey"];
var issuer = config["TokenAuthentication:Issuer"];
var audience = config["TokenAuthentication:Audience"];
var keyBytes = Encoding.ASCII.GetBytes(secretKey);

// Autenticación con cookies
builder
    .Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Home/Login"; // Redirigir para login
        options.LogoutPath = "/Home/Logout"; // Redirigir para logout
        options.AccessDeniedPath = "/Home/Index"; // Redirigir para acceso denegado
    })
    .AddJwtBearer(options => // Autenticación con JWT API
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(2),
        };
    });

//Autenticación con JWT (para la app móvil)

// Autorización con política de administrador
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Administrador", policy => policy.RequireClaim("Rol", "ADMINISTRADOR"));
});

//Logger
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

var app = builder.Build();

app.UseCors("AllowAll"); // <- importante que esté antes de UseAuthorization()

// Redirigir HTTP a HTTPS
app.UseHttpsRedirection();

// Servir archivos estáticos
app.UseStaticFiles();
app.UseRouting();

// Middleware de autenticación y autorización
app.UseAuthentication();
app.UseAuthorization();

// Mapeo de rutas
app.MapControllerRoute(name: "default", pattern: "{controller=Usuario}/{action=Loguin}/{id?}");

app.MapControllerRoute(
    name: "usuarios",
    pattern: "usuarios/{action=Index}/{id?}",
    defaults: new { controller = "Usuario" }
);

app.MapControllers(); // nuevo para endpoints de API

app.Run();

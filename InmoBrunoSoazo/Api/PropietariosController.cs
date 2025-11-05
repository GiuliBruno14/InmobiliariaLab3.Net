using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using PROYECTO_BRUNO_SOAZO.Models;

namespace PROYECTO_BRUNO_SOAZO.Api
{
    [ApiController]
    [Route("api/[controller]")] //api/propietarios
    public class PropietariosController : ControllerBase
    {
        private readonly IConfiguration config;
        private readonly ILogger<PropietariosController> _logger;

        public PropietariosController(IConfiguration config, ILogger<PropietariosController> logger)
        {
            this.config = config;
            _logger = logger;
        }

        [HttpPost("login")] //api/propietarios/login
        public async Task<IActionResult> Login([FromForm] LoginRequest login)
        {
            try
            {
                RepositorioPropietario repoP = new RepositorioPropietario();
                RepositorioUsuario repoU = new RepositorioUsuario();
                var usuario = repoU.ObtenerPorEmail(login.Email);
                var hashedPassword = HashPassword(login.Password);
                if (usuario == null || usuario.Clave != hashedPassword)
                {
                    return BadRequest("Credenciales incorrectas");
                }
                else if (usuario.Datos == null || usuario.Datos.rol == null)
                {
                    return BadRequest("NO HAY DATOS DEL ROL");
                }
                else if (usuario.Datos.rol != "PROPIETARIO")
                {
                    return BadRequest("El usuario no es propietario");
                }
                else
                {
                    string rol = usuario.Datos.rol ?? "";
                    int? numero = usuario.Datos.Numero;
                    if (rol != "PROPIETARIO" || numero != 3)
                        return BadRequest("Solo propietarios pueden iniciar sesión");
                    var token = GenerarToken(usuario);
                    return Ok(token);
                }
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message + "hola ");
            }
        }

        private string HashPassword(string password)
        {
            string hashed = Convert.ToBase64String(
                KeyDerivation.Pbkdf2(
                    password: password,
                    salt: System.Text.Encoding.ASCII.GetBytes(config["Salt"]),
                    prf: KeyDerivationPrf.HMACSHA1,
                    iterationCount: 1000,
                    numBytesRequested: 256 / 8
                )
            );
            return hashed;
        }

        private Propietario? ObtenerPropietario()
        {
            _logger.LogInformation("Obteniendo el perfil del propietario");
            var usuarioIdClaim = User.FindFirst("Id")?.Value; //Obtener el id del usuario mediante el token
            _logger.LogInformation("El id claim del usuario es: " + usuarioIdClaim);
            if (string.IsNullOrEmpty(usuarioIdClaim))
            {
                return null;
            }
            int usuarioId = int.Parse(usuarioIdClaim);
            _logger.LogInformation("El id del usuario es: " + usuarioId);
            RepositorioPropietario repoP = new RepositorioPropietario();
            var propietario = repoP.getPropietarioIdUsuario(usuarioId);
            _logger.LogInformation("El propietario es: " + propietario);
            return propietario;
        }

        [HttpGet("perfil")] //api/propietarios/perfil
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)] //Requiere estar logueado
        public async Task<IActionResult> GetPerfil()
        {
            try
            {
                var propietario = ObtenerPropietario();
                if (propietario == null)
                {
                    return NotFound("Propietario no encontrado");
                }
                var resultado = new
                {
                    Id = propietario.Id,
                    Nombre = propietario.Nombre,
                    Apellido = propietario.Apellido,
                    Dni = propietario.Dni,
                    Email = propietario.Email,
                    Telefono = propietario.Telefono,
                    Domicilio = propietario.Domicilio,
                    Ciudad = propietario.Ciudad,
                };

                return Ok(resultado);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Ocurrió un error al obtener el perfil");
            }
        }

        [HttpPut("actualizar")] //api/propietarios/actualizar
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)] //Requiere estar logueado
        public async Task<IActionResult> ActualizarPropietario(
            [FromBody] Propietario propietarioActualizado
        )
        {
            try
            {
                var propietario = ObtenerPropietario();
                if (propietario == null)
                {
                    return NotFound("Propietario no encontrado");
                }
                propietario.Nombre = propietarioActualizado.Nombre;
                propietario.Apellido = propietarioActualizado.Apellido;
                propietario.Dni = propietarioActualizado.Dni;
                propietario.Email = propietarioActualizado.Email;
                propietario.Telefono = propietarioActualizado.Telefono;
                RepositorioPropietario rp = new RepositorioPropietario();
                RepositorioUsuario ru = new RepositorioUsuario();
                _logger.LogInformation("El propietario se va a actualizar: " + propietario.Nombre);
                rp.ModificarPropietarioApp(propietario);
                _logger.LogInformation("El propietario se actualizo: " + propietario.Nombre);

                return Ok("Propietario actualizado");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Ocurrio un error al actualizar el propietario");
            }
        }

        [HttpPost("email")] //api/propietarios/email
        public async Task<IActionResult> OlvidoPassword([FromForm] string email)
        {
            try
            {
                if (string.IsNullOrEmpty(email))
                {
                    return BadRequest("El email es requerido");
                }
                RepositorioUsuario ru = new RepositorioUsuario();
                _logger.LogInformation("Mail del propietario " + email);
                var usuario = ru.ObtenerPorEmail(email);
                _logger.LogInformation("El usuario es: " + usuario);
                if (usuario == null)
                {
                    return NotFound("El usuario no existe");
                }
                string nuevaPassword = GenerarPassword();
                string hashedPassword = HashPassword(nuevaPassword);
                ru.ActualizarClave(email, hashedPassword);
                await EnviarEmail(
                    email,
                    "Reestableciemiento de contraseña",
                    $"Hola {usuario.Nombre}, tu nueva contraseña es: {nuevaPassword}"
                );
                return Ok("Se ha enviado un correo con la nueva contraseña");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Ocurrio un error al actualizar el propietario");
            }
        }

        [HttpPut("cambiarPassword")] //api/propietarios/cambiarPassword
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)] //Requiere estar logueado
        public async Task<IActionResult> CambiarPassword(
            [FromForm] string passwordActual,
            [FromForm] string passwordNueva
        )
        {
            try
            {
                if (string.IsNullOrEmpty(passwordActual) || string.IsNullOrEmpty(passwordNueva))
                    return BadRequest("Ambos campos son obligatorios");
                var propietario = ObtenerPropietario();
                if (propietario == null)
                {
                    return NotFound("Propietario no encontrado");
                }
                RepositorioUsuario ru = new RepositorioUsuario();
                var u = ru.ObtenerPorEmail(propietario.Email);
                if (u == null)
                {
                    return NotFound("Propietario no encontrado");
                }

                var hashedPasswordActual = HashPassword(passwordActual);
                if (hashedPasswordActual != u.Clave)
                {
                    return BadRequest("La contraseña actual es incorrecta");
                }
                string hashedPasswordNueva = HashPassword(passwordNueva);
                u.Clave = hashedPasswordNueva;
                ru.ActualizarClave(u.Correo, hashedPasswordNueva);

                return Ok("Contraseña cambiada");
            }
            catch
            {
                return StatusCode(500, "Ocurrio un error al cambiar la contraseña");
            }
        }

        private string GenerarToken(Usuario usuario)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, usuario.Correo ?? ""),
                new Claim("FullName", (usuario.Nombre ?? "") + " " + (usuario.Apellido ?? "")),
                new Claim("Rol", usuario.Datos.rol ?? ""),
                new Claim("Id", usuario.Id.ToString()),
            };

            var secreto = config["TokenAuthentication:SecretKey"];
            if (string.IsNullOrEmpty(secreto))
                throw new Exception("Falta configurar TokenAuthentication:Secret");
            var key = new SymmetricSecurityKey(System.Text.Encoding.ASCII.GetBytes(secreto));
            var credenciales = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: config["TokenAuthentication:Issuer"],
                audience: config["TokenAuthentication:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(60),
                signingCredentials: credenciales
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerarPassword()
        {
            string caracteres = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            return new string(
                Enumerable.Repeat(caracteres, 8).Select(s => s[random.Next(s.Length)]).ToArray()
            );
        }

        private async Task EnviarEmail(string destinatario, string asunto, string cuerpo)
        {
            using (var mensaje = new MailMessage())
            {
                mensaje.To.Add(destinatario);
                mensaje.Subject = asunto;
                mensaje.Body = cuerpo;
                mensaje.IsBodyHtml = false;
                mensaje.From = new MailAddress("giulietta133@gmail.com", "TPInmobiliaria");
                using (var smtp = new SmtpClient("smtp.gmail.com"))
                {
                    smtp.Port = 587;
                    smtp.Credentials = new NetworkCredential(
                        "giulietta133@gmail.com",
                        "anmb yyip ksrj hmlj"
                    );
                    smtp.EnableSsl = true;
                    await smtp.SendMailAsync(mensaje);
                }
            }
        }
    }
}

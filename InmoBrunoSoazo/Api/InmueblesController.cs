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
using Newtonsoft.Json;
using PROYECTO_BRUNO_SOAZO.Models;

namespace PROYECTO_BRUNO_SOAZO.Api
{
    [ApiController]
    [Route("api/[controller]")] //api/inmuebles
    public class InmueblesController : ControllerBase
    {
        private readonly IConfiguration config;
        private readonly ILogger<InmueblesController> _logger;

        public InmueblesController(IConfiguration config, ILogger<InmueblesController> logger)
        {
            this.config = config;
            _logger = logger;
        }

        [HttpGet("")] //api/inmuebles/
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)] //Requiere estar logueado
        public async Task<IActionResult> GetInmuebles()
        {
            try
            {
                RepositorioInmueble ri = new RepositorioInmueble();
                var propietario = ObtenerPropietario();
                if (propietario == null)
                {
                    return NotFound("Propietario no encontrado");
                }
                var inmuebles = ri.ObtenerInmueblesPropietario(propietario.Id);
                if (inmuebles == null || !inmuebles.Any())
                {
                    return NotFound("No se encontraron inmuebles para este propietario");
                }
                _logger.LogInformation("Se encontraron " + inmuebles.Count() + " inmuebles");
                return Ok(inmuebles);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Ocurrio un error al obtener los inmuebles");
            }
        }

        [HttpPut("actualizar")] //api/inmuebles/actualizar
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)] //Requiere estar logueado
        public async Task<IActionResult> ActualizarInmueble([FromBody] Inmueble inmuebleActualizado)
        {
            try
            {
                RepositorioInmueble ri = new RepositorioInmueble();
                RepositorioPropietario rp = new RepositorioPropietario();
                //Controlar que sea el propietario del inmueble
                var propietario = ObtenerPropietario();
                var inmueble = ri.GetInmueble(inmuebleActualizado.Id);
                if (inmueble == null)
                {
                    return NotFound("Inmueble no encontrado");
                }
                if (propietario == null)
                {
                    return NotFound("Propietario no encontrado");
                }
                if (propietario.Id != inmueble.PropietarioId)
                {
                    return Unauthorized("No tiene permisos para actualizar este inmueble");
                }
                inmueble.Disponible = inmuebleActualizado.Disponible;

                ri.ModificarInmueble(inmueble);

                return Ok("Inmueble actualizado");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Ocurrio un error al actualizar el inmueble");
            }
        }

        [HttpPost("cargar")] //api/inmuebles/cargar
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)] //Requiere estar logueado
        public async Task<IActionResult> CargarInmueble(
            [FromForm] IFormFile imagen,
            [FromForm] string inmueble
        )
        {
            try
            {
                if (imagen == null || imagen.Length == 0)
                    return BadRequest("Debe subir una imagen válida.");

                if (string.IsNullOrEmpty(inmueble))
                    return BadRequest("Los datos del inmueble son requeridos.");

                // Deserializar el JSON recibido como string
                var inmuebleObj = JsonConvert.DeserializeObject<Inmueble>(inmueble);
                if (inmuebleObj == null)
                    return BadRequest("Formato de inmueble inválido.");

                // Obtener propietario autenticado
                var propietario = ObtenerPropietario();
                if (propietario == null)
                    return Unauthorized("Propietario no encontrado.");

                inmuebleObj.PropietarioId = propietario.Id;
                _logger.LogInformation($"Propietario del inmueble: {inmuebleObj.PropietarioId}");

                // Crear carpeta si no existe
                var uploads = Path.Combine(
                    Directory.GetCurrentDirectory(),
                    "wwwroot",
                    "ImgSubidas",
                    "ImgInmuebles"
                );
                Directory.CreateDirectory(uploads);

                // Guardar archivo con nombre único
                var fileName = $"{Guid.NewGuid()}{Path.GetExtension(imagen.FileName)}";
                var filePath = Path.Combine(uploads, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await imagen.CopyToAsync(stream);
                }

                // Guardar ruta relativa (para acceder desde el front)
                inmuebleObj.Imagen = Path.Combine("ImgSubidas", "ImgInmuebles", fileName)
                    .Replace("\\", "/");

                // Guardar en base de datos
                var repo = new RepositorioInmueble();
                repo.AltaInmueble(inmuebleObj);

                _logger.LogInformation("Inmueble creado correctamente.");
                return Ok(inmuebleObj);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al crear inmueble");
                return StatusCode(500, $"Ocurrió un error al crear el inmueble: {ex.Message}");
            }
        }

        [HttpGet("tipos")] //api/inmuebles/tipos
        public IActionResult GetTipos()
        {
            try
            {
                var repo = new RepositorioTipoInmueble();
                var tipos = repo.ObtenerTipos(); // Devuelve List<Tipo>
                _logger.LogInformation("Tipos obtenidos correctamente");
                return Ok(tipos);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error al obtener tipos");
            }
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

        [HttpGet("contratos-vigentes")] //api/inmuebles/contratosVigentes
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)] //Requiere estar logueado
        public async Task<IActionResult> GetInmueblesContratosVigentes()
        {
            try
            {
                var propietario = ObtenerPropietario();
                if (propietario == null)
                    return NotFound("Propietario no encontrado");

                RepositorioInmueble ri = new RepositorioInmueble();
                _logger.LogInformation("Obteniendo los contratos vigentes");
                var inmuebles = ri.ObtenerInmueblesConContratoVigente(propietario.Id);
                _logger.LogInformation("Contratos obtenidos");

                if (inmuebles == null || !inmuebles.Any())
                    return NotFound("No se encontraron inmuebles con contrato vigente");

                return Ok(inmuebles);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Ocurrio un error al obtener los contratos");
            }
        }
    }
}

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
using Microsoft.AspNetCore.OutputCaching;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using PROYECTO_BRUNO_SOAZO.Models;

namespace PROYECTO_BRUNO_SOAZO.Api
{
    [ApiController]
    [Route("api/[controller]")] //api/contratos
    public class ContratosController : ControllerBase
    {
        private readonly IConfiguration config;
        private readonly ILogger<ContratosController> _logger;

        public ContratosController(IConfiguration config, ILogger<ContratosController> logger)
        {
            this.config = config;
            _logger = logger;
        }

        [HttpGet("inmueble/{id}")] //api/contratos/inmueble/{id}
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public IActionResult GetContratoInmueble(int id)
        {
            try
            {
                var propietario = ObtenerPropietario();
                if (propietario == null)
                {
                    return NotFound("Propietario no encontrado");
                }
                //Controlar que sea el propietario del inmueble
                var repoInm = new RepositorioInmueble();
                var inmueble = repoInm.GetInmueble(id);
                if (inmueble == null)
                {
                    return NotFound("Inmueble no encontrado");
                }
                if (propietario.Id != inmueble.PropietarioId)
                {
                    return Unauthorized(
                        "No tiene permisos para ver los contratos de este inmueble"
                    );
                }
                var repoC = new RepositorioContrato();
                var contrato = repoC.ObtenerContratoPorInmueble(id);
                if (contrato == null)
                {
                    return NotFound("No hay contrato vigente para este inmueble.");
                }
                _logger.LogInformation("Contrato obtenidos correctamente");
                return Ok(contrato);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error al obtener contratos");
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

        [HttpGet("pagos/{id}")] //api/contratos/pagos/{id}
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public IActionResult GetPagosContrato(int id)
        {
            try
            {
                var propietario = ObtenerPropietario();
                _logger.LogInformation("ID Contrato: " + id);
                if (propietario == null)
                {
                    return NotFound("Propietario no encontrado");
                }
                var repoC = new RepositorioContrato();
                var contrato = repoC.GetContrato(id);
                _logger.LogInformation("Contrato" + contrato.IdInmueble);
                if (contrato == null)
                {
                    return NotFound("Contrato no encontrado");
                }
                var repoInm = new RepositorioInmueble();
                var inmueble = repoInm.GetInmueble(contrato.IdInmueble);
                if (inmueble == null)
                {
                    return NotFound("Inmueble no encontrado");
                }
                if (propietario.Id != inmueble.PropietarioId)
                {
                    return Unauthorized(
                        "No tiene permisos para ver los contratos de este inmueble"
                    );
                }
                var repoP = new RepositorioPago();
                var pagos = repoP.ObtenerPagosPorContrato(id);
                if (pagos == null)
                {
                    return NotFound("No hay pagos para este contrato.");
                }
                _logger.LogInformation("Pagos obtenidos correctamente");
                return Ok(pagos);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error al obtener pagos");
            }
        }
    }
}

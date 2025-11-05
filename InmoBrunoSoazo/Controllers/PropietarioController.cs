using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PROYECTO_BRUNO_SOAZO;
using PROYECTO_BRUNO_SOAZO.Controllers;
using PROYECTO_BRUNO_SOAZO.Models;

namespace PROYECTO_BRUNO_SOAZOControllers;

public class PropietarioController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public PropietarioController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    [Authorize]
    public IActionResult Index()
    {
        RepositorioPropietario rp = new RepositorioPropietario();
        IList<Propietario> lista = new List<Propietario>();
        var userRole = User.Claims.FirstOrDefault(c => c.Type == "Rol")?.Value;
        ViewBag.UserRole = userRole;
        try
        {
            lista = rp.GetPropietarios();

            if (TempData.ContainsKey("Mensaje"))
            {
                ViewBag.Mensaje = TempData["Mensaje"];
            }
            else if (TempData.ContainsKey("Error"))
            {
                ViewBag.Error = TempData["Error"];
            }
            return View(lista);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al obtener la lista de propietarios");
            TempData["Error"] = "Ocurrio un error al obtener la lista de propietarios";
            ViewBag.Error = TempData["Error"];
            return View(lista);
        }
    }

    [Authorize]
    public IActionResult Editar(int id)
    {
        if (id > 0)
        {
            RepositorioPropietario rp = new RepositorioPropietario();
            var propietario = rp.getPropietario(id);
            return View(propietario);
        }
        else
        {
            return View();
        }
    }

    [Authorize]
    public IActionResult Guardar(Propietario propietario)
    {
        try
        {
            propietario.Nombre = propietario.Nombre.ToUpper();
            propietario.Apellido = propietario.Apellido.ToUpper();
            propietario.Email = propietario.Email.ToUpper();
            propietario.Domicilio = propietario.Domicilio.ToUpper();
            propietario.Ciudad = propietario.Ciudad.ToUpper();
            RepositorioPropietario rp = new RepositorioPropietario();

            if (propietario.Id > 0)
            {
                rp.ModificarPropietario(propietario);
                TempData["Mensaje"] = "El propietario ha sido modificado";
            }
            else
            {
                rp.AltaPropietario(propietario);
                TempData["Mensaje"] = "El propietario ha sido guardado";
            }
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex)
        {
            TempData["Mensaje"] = "Ocurrió un error al guardar el propietario";
            return RedirectToAction(nameof(Index));
        }
    }

    [Authorize(Policy = "Administrador")]
    public IActionResult Eliminar(int id)
    {
        try
        {
            RepositorioPropietario rp = new RepositorioPropietario();
            rp.EliminarPropietario(id);
            TempData["Mensaje"] = "El propietario ha sido eliminado";
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex)
        {
            TempData["Mensaje"] = "Ocurrio un error al eliminar el propietario";
            return RedirectToAction(nameof(Index));
        }
    }

    [Authorize]
    public IActionResult Detalles(int id)
    {
        RepositorioPropietario rp = new RepositorioPropietario();
        var propietario = rp.getPropietario(id);
        return View(propietario);
    }

    // GET: Propietario/Busqueda
    public IActionResult Busqueda()
    {
        try
        {
            return View();
        }
        catch (Exception ex)
        { //poner breakpoints para detectar errores
            throw;
        }
    }

    //[Route("[controller]/Buscar/{q}", Name = "Buscar")]
    [Authorize]
    public IActionResult BuscarPropietario(string buscar)
    {
        try
        {
            RepositorioPropietario rp = new RepositorioPropietario();
            IList<Propietario> p = rp.BuscarPorNombre(buscar);
            return View("Index", p);
        }
        catch (Exception ex)
        {
            TempData["Error"] = "Ocurrio un error al buscar el propietario";
            return RedirectToAction(nameof(Index));
        }
    }
}

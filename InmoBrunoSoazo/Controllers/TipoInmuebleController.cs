using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PROYECTO_BRUNO_SOAZO;
using PROYECTO_BRUNO_SOAZO.Controllers;
using PROYECTO_BRUNO_SOAZO.Models;


namespace PROYECTO_BRUNO_SOAZOControllers;

public class TipoInmuebleController : Controller
{
    private readonly ILogger<HomeController> _logger;


    public TipoInmuebleController(ILogger<HomeController> logger)
    {

        _logger = logger;
    }
    [Authorize]
    public IActionResult Index()
    {
        RepositorioTipoInmueble rp = new RepositorioTipoInmueble();
        IList<TipoInmueble> lista = new List<TipoInmueble>();
        var userRole = User.Claims.FirstOrDefault(c => c.Type == "Rol")?.Value;
        ViewBag.UserRole = userRole;
        try
        {
            lista = rp.ObtenerTipos();
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
            _logger.LogError(ex, "Error al obtener la lista de tipos de inmueble");
            TempData["Error"] = "Ocurrio un error al obtener la lista de tipos de inmueble";
            ViewBag.Error = TempData["Error"];
            return View(lista);
        }
    }
    [Authorize]
    public IActionResult Editar(int id)
    {
        if (id > 0)
        {
            RepositorioTipoInmueble rp = new RepositorioTipoInmueble();
            var propietario = rp.getTipoInmueble(id);
            return View(propietario);
        }
        else
        {
            return View();
        }
    }
    [Authorize]
    public IActionResult Guardar(TipoInmueble propietario)
    {
        try
        {
            propietario.Tipo = propietario.Tipo.ToUpper();
            RepositorioTipoInmueble rp = new RepositorioTipoInmueble();

            if (propietario.Id > 0)
            {
                rp.ModificarTipoInmueble(propietario);
                TempData["Mensaje"] = "El propietario ha sido modificado";

            }
            else
            {
                rp.AltaTipoInmueble(propietario);
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
    [Authorize(Policy ="Administrador")]
    public IActionResult Eliminar(int id)
    {
        try
        {
            RepositorioTipoInmueble rp = new RepositorioTipoInmueble();
            rp.EliminarTipoInmueble(id);
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
        RepositorioTipoInmueble rp = new RepositorioTipoInmueble();
        var propietario = rp.getTipoInmueble(id);
        return View(propietario);
    }

    // GET: TipoInmueble/Busqueda
    public IActionResult Busqueda()
    {
        try
        {
            return View();
        }
        catch (Exception ex)
        {//poner breakpoints para detectar errores
            throw;
        }
    }

  public IActionResult BuscarPorTipo(string buscar)
    {
        try
        {   buscar = buscar.ToUpper();
            RepositorioTipoInmueble rp = new RepositorioTipoInmueble();
            IList<TipoInmueble> p = rp.BuscarPorTipo(buscar);
            return View("Index",p );
        }
        catch (Exception ex)
        {
            TempData["Error"] = "Ocurrio un error al buscar el tipo de inmueble";
            return RedirectToAction(nameof(Index));
        }
    }
}
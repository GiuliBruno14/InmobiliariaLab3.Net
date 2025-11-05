using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PROYECTO_BRUNO_SOAZO.Models;


namespace PROYECTO_BRUNO_SOAZO.Controllers;

public class PagoController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public PagoController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }
    [Authorize]
    public IActionResult Index()
    {
        RepositorioPago rp = new RepositorioPago();
        IList<Pago> lista = new List<Pago>();
        var userRole = User.Claims.FirstOrDefault(c => c.Type == "Rol")?.Value;
        ViewBag.UserRole = userRole;
        try
        {
            lista = rp.GetPagos();

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
            _logger.LogError(ex, "Error al obtener la lista de pagos");
            TempData["Error"] = "Ocurrio un error al obtener la lista de pagos";
            ViewBag.Error = TempData["Error"];
            return View(lista);
        }
    }
    [Authorize]
    public IActionResult Editar(int? id, int? idContrato)
    {   List<string> Referencia = new List<string>{ "COMISION","CUOTA", "MULTA"};
        ViewBag.Referencia = Referencia;
    
        RepositorioContrato repoContrato = new RepositorioContrato();
        var lista = repoContrato.GetContratos();
        lista = lista.Where(x =>
                x.FechaTerm > DateTime.Now &&  // Contratos cuya fecha de término es mayor a la fecha actual
                x.Anulado == false             // Contratos que NO están anulados
            ).ToList();

        ViewBag.Contratos = lista;

        var pago = new Pago();

        if (id.HasValue && id.Value > 0)
        {
            RepositorioPago rp = new RepositorioPago();
            pago = rp.GetPago(id.Value) ?? new Pago();
        }

        if (idContrato.HasValue)
        {
            pago.IdContrato = idContrato.Value;
        }

        return View(pago);
    }

    [Authorize]
    public IActionResult AgregarPago(int? id)
    {
        RepositorioContrato repoContrato = new RepositorioContrato();
        var lista = repoContrato.GetContratos();
        lista = lista.Where(x =>
                x.FechaTerm > DateTime.Now &&  // Contratos cuya fecha de término es mayor a la fecha actual
                x.Anulado == false             // Contratos que NO están anulados
            ).ToList();
        List<string> Referencia = new List<string>{"COMISION","CUOTA", "MULTA"};
        ViewBag.Referencia = Referencia;    

        ViewBag.Contratos = lista;
        var pago = new Pago();

        if (id.HasValue)
        {
            pago.IdContrato = id.Value;
        }

        return View(pago);
    }
    [Authorize]
    public IActionResult Guardar(Pago pago, int? idContrato)
    {
        if (idContrato.HasValue)
        {
            pago.IdContrato = idContrato.Value;
        }
        RepositorioUsuario ru = new RepositorioUsuario();
        var usuario = ru.ObtenerPorEmail(User.Identity.Name);
        try
        {
            RepositorioPago rp = new RepositorioPago();

            if (pago.Id > 0)
            {
                rp.ModificarPago(pago);
                   return RedirectToAction(nameof(Index));
            }
            else
            {
                pago.IdUsuarioComenzo = usuario.Id;
                pago.IdUsuarioTermino = null;
                rp.AltaPago(pago);
                return RedirectToAction("PagosContrato", pago.Id);
            }
        }
        catch (System.Exception)
        {
            TempData["Error"] = "No se pudo completar la operación.";
            return RedirectToAction(nameof(Index));

        }
    }
    [Authorize(Policy = "Administrador")]
    public IActionResult Eliminar(int id) //Es un anulado logico
    {
        try
        {
            RepositorioPago rp = new RepositorioPago();
            RepositorioUsuario ru = new RepositorioUsuario();
            var usuario = ru.ObtenerPorEmail(User.Identity.Name);
            rp.EliminarPago(id, usuario.Id);
            TempData["Mensaje"] = "El pago ha sido anulado correctamente.";
            return RedirectToAction(nameof(Index));
        }
        catch
        {
            TempData["Error"] = "No se pudo completar la operación.";
            return RedirectToAction(nameof(Index));
        }
    }
    [Authorize]
    public IActionResult Detalles(int id)
    {
        RepositorioPago rp = new RepositorioPago();
        RepositorioUsuario ru = new RepositorioUsuario();
        var userRole = User.Claims.FirstOrDefault(c => c.Type == "Rol")?.Value;
        ViewBag.UserRole = userRole;
        var p = rp.GetPago(id);
        var usuarioC = ru.getUsuario(p.IdUsuarioComenzo);
        ViewBag.UsuarioC = usuarioC;
        if (p.IdUsuarioTermino.HasValue)
        {
            var usuarioT = ru.getUsuario(p.IdUsuarioTermino.Value);
            ViewBag.UsuarioT = usuarioT;
        }
        return View(p);
    }
    [Authorize]
    public IActionResult PagosContrato(int id)
    {
        RepositorioPago rp = new RepositorioPago();
        IList<Pago> lista = new List<Pago>();
        var userRole = User.Claims.FirstOrDefault(c => c.Type == "Rol")?.Value;
        ViewBag.UserRole = userRole;
        try
        {
            lista = rp.GetPagos();
            lista = lista.Where(x => x.IdContrato == id).ToList();
            return View("Index", lista);
        }
        catch (Exception ex)
        {
            TempData["Error"] = "Ocurrio un error al obtener la lista de pagos";
               return RedirectToAction(nameof(Index));
        }
    }


}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.WebSockets;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json.Serialization;
using PROYECTO_BRUNO_SOAZO.Controllers;
using PROYECTO_BRUNO_SOAZO.Models;

namespace PROYECTO_BRUNO_SOAZO;

public class UsuarioController : Controller
{
    private readonly IConfiguration configuration;
    private readonly IWebHostEnvironment environment;

    private readonly ILogger<HomeController> _logger;

    public UsuarioController(
        ILogger<HomeController> logger,
        IConfiguration configuration,
        IWebHostEnvironment environment
    )
    {
        _logger = logger;
        this.configuration = configuration;
        this.environment = environment;
    }

    [Authorize(Policy = "Administrador")]
    public IActionResult Index()
    {
        RepositorioUsuario repositorio = new RepositorioUsuario();
        IList<Usuario> lista = new List<Usuario>();
        var userRole = User.Claims.FirstOrDefault(c => c.Type == "Rol")?.Value;
        ViewBag.UserRole = userRole;
        try
        {
            lista = repositorio.GetUsuarios();
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
            //_logger.LogError(ex, "Error al obtener la lista de usuarios");
            TempData["Error"] = "Ocurrio un error al obtener la lista de usuarios";
            ViewBag.Error = TempData["Error"];
            return View(lista);
        }
    }

    [Authorize(Policy = "Administrador")]
    public IActionResult Crear()
    {
        RepositorioRol repoRol = new RepositorioRol();
        ViewBag.Roles = repoRol.ObtenerRoles();
        return View();
    }

    [Authorize(Policy = "Administrador")]
    [HttpPost]
    public IActionResult Guardar(Usuario usuario)
    {
        RepositorioUsuario repositorio = new RepositorioUsuario();
        if (!ModelState.IsValid) //valida que el formulario coincida con el modelo
            return View();
        try
        {
            string hashedPassword = HashPassword(usuario.Clave);
            usuario.Clave = hashedPassword;
            usuario.Rol = usuario.Rol;
            usuario.Nombre = usuario.Nombre.ToUpper();
            usuario.Apellido = usuario.Apellido.ToUpper();
            int res = repositorio.AltaUsuario(usuario);
            if (usuario.AvatarFile != null && usuario.Id > 0)
            {
                GuardarAvatar(usuario); // Método separado para manejo de archivos
            }
            else
            {
                usuario.AvatarURL = Path.Combine("/ImgSubidas", "anonimo.jpg");
                repositorio.ModificarUsuario(usuario);
            }
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex)
        {
            TempData["Mensaje"] = "Ocurrió un error al guardar el usuario";
            return RedirectToAction(nameof(Index));
        }
    }

    private string HashPassword(string password)
    {
        string hashed = Convert.ToBase64String(
            KeyDerivation.Pbkdf2(
                password: password,
                salt: System.Text.Encoding.ASCII.GetBytes(configuration["Salt"]),
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 1000,
                numBytesRequested: 256 / 8
            )
        );
        return hashed;
    }

    private void GuardarAvatar(Usuario usuario)
    {
        try
        {
            string wwwPath = environment.WebRootPath;
            string path = Path.Combine(wwwPath, "ImgSubidas");
            // Crear el directorio si no existe
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
            // Crear un nombre de archivo único con el ID del usuario
            Random random = new Random();
            // Generar un número entero aleatorio entre 0 (inclusive) y 10 (exclusivo)
            int aleacion = random.Next(10);
            string fileName =
                aleacion + "av_" + usuario.Id + Path.GetExtension(usuario.AvatarFile.FileName);
            string fullPath = Path.Combine(path, fileName);
            // Guardar la imagen en el servidor
            using (FileStream stream = new FileStream(fullPath, FileMode.Create))
            {
                usuario.AvatarFile.CopyTo(stream);
            }
            eliminaArchivoAnterior(usuario);

            usuario.AvatarURL = Path.Combine("/ImgSubidas", fileName);
            // Actualizar el usuario en la base de datos
            RepositorioUsuario repositorio = new RepositorioUsuario();
            repositorio.EditarAvatar(usuario);
        }
        catch (Exception ex)
        {
            TempData["Error"] = "Ocurrio un error al guardar el avatar";
        }
    }

    public void eliminaArchivoAnterior(Usuario usuario)
    {
        if (usuario.AvatarURL != null && !usuario.AvatarURL.EndsWith("anonimo.jpg"))
        {
            string fullPath = Path.Combine(
                environment.WebRootPath,
                usuario.AvatarURL.TrimStart('/')
            );
            if (System.IO.File.Exists(fullPath))
            {
                System.IO.File.Delete(fullPath);
            }
        }
    }

    [Authorize]
    [HttpGet]
    public IActionResult Editar(int id)
    {
        try
        {
            if (id > 0)
            {
                // Obtener el usuario actual logueado
                RepositorioUsuario ru = new RepositorioUsuario();
                var usuarioActual = ru.ObtenerPorEmail(User.Identity.Name);
                var userRole = User.Claims.FirstOrDefault(c => c.Type == "Rol")?.Value;

                // Verificar si el usuario actual puede editar al usuario con el ID dado
                if (
                    userRole == "ADMINISTRADOR"
                    || (usuarioActual != null && usuarioActual.Id == id)
                )
                {
                    RepositorioRol repoRol = new RepositorioRol();
                    ViewBag.Roles = repoRol.ObtenerRoles();

                    RepositorioUsuario repositorio = new RepositorioUsuario();
                    var usuario = repositorio.getUsuario(id);
                    return View(usuario);
                }
                else
                {
                    // Si no tiene permisos para editar, redirigir con un mensaje de error
                    TempData["Error"] = "No tiene permisos para editar este usuario.";
                    return RedirectToAction(nameof(Index));
                }
            }
            else
            {
                return View();
            }
        }
        catch (Exception ex)
        {
            TempData["Error"] = "Ocurrio un error al obtener los datos del usuario";
            return RedirectToAction(nameof(Index));
        }
    }

    [Authorize]
    [HttpPost]
    public IActionResult Editar(int id, Usuario u)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                return View(u); // Retorna con errores de validación
            }

            RepositorioUsuario ru = new RepositorioUsuario();
            var usuarioActual = ru.ObtenerPorEmail(User.Identity.Name);
            var userRole = User.Claims.FirstOrDefault(c => c.Type == "Rol")?.Value;

            // Verificar si el usuario actual tiene permisos para editar
            if (userRole == "ADMINISTRADOR" || (usuarioActual != null && usuarioActual.Id == id))
            {
                var usuarioExistente = ru.getUsuario(id);

                if (usuarioExistente != null)
                {
                    usuarioExistente.Nombre = u.Nombre.ToUpper();
                    usuarioExistente.Apellido = u.Apellido.ToUpper();
                    usuarioExistente.Correo = u.Correo;
                    if (u.AvatarFile != null)
                    {
                        usuarioExistente.AvatarFile = u.AvatarFile;
                        GuardarAvatar(usuarioExistente);
                    }
                    ru.EditarDatos(usuarioExistente);
                    ViewBag.Mensaje = "Datos del usuario actualizados correctamente";
                    return View("Editar", usuarioExistente);
                }
                else
                {
                    TempData["Error"] = "Usuario no encontrado";
                    return RedirectToAction(nameof(Index));
                }
            }
            else
            {
                TempData["Error"] = "No tiene permisos para editar este usuario.";
                return RedirectToAction(nameof(Index));
            }
        }
        catch (Exception ex)
        {
            TempData["Error"] = "Ocurrio un error al actualizar los datos del usuario";
            return RedirectToAction(nameof(Index));
        }
    }

    [Authorize]
    [HttpPost]
    public IActionResult CambiarContraseña(int id, Usuario u)
    {
        try
        {
            RepositorioUsuario ru = new RepositorioUsuario();
            var usuarioActual = ru.ObtenerPorEmail(User.Identity.Name);
            var user = ru.getUsuario(id);
            var userRole = User.Claims.FirstOrDefault(c => c.Type == "Rol")?.Value;

            // Verificar si el usuario actual es el mismo que va a cambiar la contraseña o es un administrador
            if (
                user != null
                && usuarioActual != null
                && (usuarioActual.Id == id || userRole == "ADMINISTRADOR")
            )
            {
                user.Clave = HashPassword(u.Clave);
                ru.EditarClave(user);
                ViewBag.Mensaje = "Clave editada correctamente";
                return View("Editar", user);
            }
            else
            {
                ViewBag.Error = "No tiene permisos para cambiar la contraseña de este usuario.";
                return RedirectToAction(nameof(Index));
            }
        }
        catch (Exception ex)
        {
            TempData["Error"] = "Ocurrio un error al actualizar los datos del usuario";
            return RedirectToAction(nameof(Index));
        }
    }

    [Authorize(Policy = "Administrador")]
    public IActionResult Eliminar(int id)
    {
        try
        {
            RepositorioUsuario repositorio = new RepositorioUsuario();
            repositorio.EliminarUsuario(id);
            TempData["Mensaje"] = "El usuario ha sido eliminado";
            return RedirectToAction(nameof(Index));
        }
        catch (Exception ex)
        {
            TempData["Mensaje"] = "Ocurrio un error al eliminar el usuario";
            return RedirectToAction(nameof(Index));
        }
    }

    [Authorize]
    public IActionResult EliminarAvatar(int id, Usuario usuario)
    {
        try
        {
            RepositorioUsuario ru = new RepositorioUsuario();
            var usuarioActual = ru.ObtenerPorEmail(User.Identity.Name);
            var usuarioExistente = ru.getUsuario(id);
            var userRole = User.Claims.FirstOrDefault(c => c.Type == "Rol")?.Value;

            if (usuarioExistente != null)
            {
                // Verificar si el usuario actual es el mismo que va a eliminar el avatar o es un administrador
                if (
                    usuarioActual != null
                    && (usuarioActual.Id == id || userRole == "ADMINISTRADOR")
                )
                {
                    if (usuarioExistente.AvatarURL != Path.Combine("/ImgSubidas", "anonimo.jpg"))
                    {
                        eliminaArchivoAnterior(usuarioExistente);
                        usuarioExistente.AvatarURL = Path.Combine("/ImgSubidas", "anonimo.jpg");
                        ru.EditarAvatar(usuarioExistente);
                        ViewBag.Mensaje = "La imagen se eliminó correctamente.";
                        return View("Editar", usuarioExistente);
                    }
                }
                else
                {
                    TempData["Error"] =
                        "No tiene permisos para eliminar el avatar de este usuario.";
                }
            }

            return RedirectToAction(nameof(Index));
        }
        catch (System.Exception)
        {
            TempData["Error"] = "Ocurrió un error al eliminar el avatar";
            return RedirectToAction(nameof(Index));
        }
    }

    [Authorize]
    public IActionResult Detalles(int id)
    {
        RepositorioUsuario repositorio = new RepositorioUsuario();
        var usuarioActual = repositorio.ObtenerPorEmail(User.Identity.Name);
        var userRole = User.Claims.FirstOrDefault(c => c.Type == "Rol")?.Value;
        if (usuarioActual != null && (usuarioActual.Id == id || userRole == "ADMINISTRADOR"))
        {
            var usuario = repositorio.getUsuario(id);
            return View(usuario);
        }
        else
        {
            TempData["Error"] = "No tiene permisos para ver detalles de este usuario.";
            return RedirectToAction(nameof(Index));
        }
    }

    [HttpPost]
    public async Task<IActionResult> Loguin(Log login)
    {
        var returnUrl = String.IsNullOrEmpty(TempData["returnUrl"] as string)
            ? "/Home"
            : TempData["returnUrl"].ToString();
        if (ModelState.IsValid)
        {
            string comprobarHash = HashPassword(login.Clave);
            RepositorioUsuario repositorio = new RepositorioUsuario();
            var e = repositorio.ObtenerPorEmail(login.Usuario);
            if (e == null || e.Clave != comprobarHash)
            {
                ViewBag.Error = "Usuario o clave incorrectos";
                TempData["returnUrl"] = returnUrl;
                return View();
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, e.Correo),
                new Claim("FullName", e.Nombre + " " + e.Apellido),
                new Claim("Rol", e.Datos.rol.ToString()),
                new Claim("Id", e.Id.ToString()),
            };

            var claimsIdentity = new ClaimsIdentity(
                claims,
                CookieAuthenticationDefaults.AuthenticationScheme
            );

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity)
            );
            TempData.Remove("returnUrl");
            ViewBag.UserRole = User.Claims.FirstOrDefault(c => c.Type == "Rol")?.Value;
            return RedirectToAction("Index", "Home");
        }
        TempData["returnUrl"] = returnUrl;
        return View();
    }

    [HttpGet]
    public IActionResult Loguin(string returnUrl)
    {
        return View();
    }

    [Route("salir", Name = "logout")]
    public async Task<ActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return View("Loguin");
    }

    [Authorize]
    public ActionResult Perfil()
    {
        RepositorioUsuario ru = new RepositorioUsuario();
        ViewData["Title"] = "Mi perfil";
        var u = ru.ObtenerPorEmail(User.Identity.Name);
        RepositorioRol repoRol = new RepositorioRol();
        ViewBag.Roles = repoRol.ObtenerRoles();
        return View("Editar", u);
    }

    [Authorize(Policy = "Administrador")]
    public IActionResult BuscarUsuario(string buscar)
    {
        try
        {
            RepositorioUsuario ru = new RepositorioUsuario();
            IList<Usuario> usuario = ru.ObtenerPorNombreOCorreo(buscar);
            return View("Index", usuario);
        }
        catch (Exception ex)
        {
            TempData["Error"] = "Ocurrio un error al buscar el usuario";
            return RedirectToAction(nameof(Index));
        }
    }
}

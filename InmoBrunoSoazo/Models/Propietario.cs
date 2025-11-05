using System.ComponentModel.DataAnnotations;

namespace PROYECTO_BRUNO_SOAZO.Models;

public class Propietario
{
    [Display(Name = "CÓDIGO")]
    [Required(ErrorMessage = "Campo obligatorio")]
    public int Id { get; set; }
    [Display(Name = "NOMBRE")]
    [Required(ErrorMessage = "Campo obligatorio")]
    public string? Nombre { get; set; }
    [Display(Name = "APELLIDO")]
    [Required(ErrorMessage = "Campo obligatorio")]
    public string? Apellido { get; set; }
    [Required(ErrorMessage = "Campo obligatorio")]
    [Display(Name = "E-MAIL")]
    public string? Email { get; set; }
    [Required(ErrorMessage = "Campo obligatorio")]
    [Display(Name = "DNI")]
    public string? Dni { get; set; }
    [Display(Name = "TELEFONO")]
    [Required(ErrorMessage = "Campo obligatorio")]
    public string? Telefono { get; set; }
    [Display(Name = "DOMICILIO")]
    [Required(ErrorMessage = "Campo obligatorio")]
    public string? Domicilio { get; set; }
    [Display(Name = "CIUDAD")]
    [Required(ErrorMessage = "Campo obligatorio")]
    public string? Ciudad { get; set; }
    public string? RequestId { get; set; }
    public int IdUsuario { get; set; }

    // public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

    private string GetToString()
    {
        return (this.Id) + " " + this.Apellido + " " + this.Nombre;
    }
}
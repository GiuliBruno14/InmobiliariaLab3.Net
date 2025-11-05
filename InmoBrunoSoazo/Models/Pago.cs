using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PROYECTO_BRUNO_SOAZO.Models
{
    public class Pago
    {
        [Display(Name = "CÓDIGO")]
        public int Id { get; set; }
        [Required(ErrorMessage = "Campo obligatorio")]
        [DataType(DataType.Date)]
        [Display(Name = "FECHA")]
        public DateTime Fecha { get; set; }

        [Required(ErrorMessage = "Campo obligatorio")]
        [Display(Name = "REFERENCIA")]
        public string? Referencia { get; set; }

        [Required(ErrorMessage = "Campo obligatorio")]
        [Range(1, double.MaxValue, ErrorMessage = "El monto debe ser mayor a 0")]
        [RegularExpression(@"^\d+(\.\d{1,2})?$", ErrorMessage = "El importe debe ser un número válido con hasta dos decimales.")]
        [Display(Name = "IMPORTE")]
        public double Importe { get; set; }

        [Required(ErrorMessage = "Campo obligatorio")]
        [Display(Name = "ANULADO")]
        public string? Anulado { get; set; }

        [Required(ErrorMessage = "Campo obligatorio")]
        [Display(Name = "CONTRATO")]
        public int IdContrato { get; set; }

        [Display(Name = "USUARIO QUE CREÓ EL PAGO")]
        public int IdUsuarioComenzo { get; set; }

        [Display(Name = "USUARIO QUE TERMINÓ EL PAGO")]
        public int? IdUsuarioTermino { get; set; } 

    }
}
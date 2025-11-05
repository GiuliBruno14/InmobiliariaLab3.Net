using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PROYECTO_BRUNO_SOAZO.Models
{
    public class Contrato
    {
        [Display(Name = "CÓDIGO")]
        public int Id { get; set; }

        [Required(ErrorMessage = "Campo obligatorio")]
        //Poner rango de fecha hoy
        [DataType(DataType.Date)]
        [Display(Name = "INICIO DEL CONTRATO")]
        public DateTime FechaInicio { get; set; }

        [Required(ErrorMessage = "Campo obligatorio")]
        //POner rango de fecha mayor a la de inicio
        [DataType(DataType.Date)]
        [Display(Name = "CULMINACIÓN")]
        public DateTime FechaTerm { get; set; }

        [Required(ErrorMessage = "Campo obligatorio")]
        [Display(Name = "MONTO MENSUAL")]
        [Range(1, double.MaxValue, ErrorMessage = "El monto debe ser mayor a 0")]
        [RegularExpression(
            @"^\d+(\.\d{1,2})?$",
            ErrorMessage = "El monto mensual debe ser un número válido con hasta dos decimales."
        )]
        public double MontoMensual { get; set; }

        [Required(ErrorMessage = "Campo obligatorio")]
        [Display(Name = "ARRENDATARIO")]
        public int IdInquilino { get; set; }

        [Required(ErrorMessage = "Campo obligatorio")]
        [Display(Name = "ARRENDATARIO")]
        public Inquilino? Arrendatario { get; set; }

        [Required(ErrorMessage = "Campo obligatorio")]
        [Display(Name = "DATOS DEL INMUEBLE")]
        public int IdInmueble { get; set; }

        [Display(Name = "USUARIO QUE CREÓ EL CONTRATO")]
        public int IdUsuarioComenzo { get; set; }

        [Display(Name = "USUARIO QUE TERMINÓ EL CONTRATO")]
        public int? IdUsuarioTermino { get; set; }

        [Display(Name = "ANULADO")]
        public bool Anulado { get; set; }

        public Inmueble? Datos { get; set; }

        [Display(Name = "FECHA DE FINALIZACION A PACTAR")]
        [DataType(DataType.Date)]
        public DateTime FechaFinalizacion { get; set; }
    }
}

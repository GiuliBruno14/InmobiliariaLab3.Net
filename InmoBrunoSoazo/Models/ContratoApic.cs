using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PROYECTO_BRUNO_SOAZO.Models
{
    public class ContratoApi
    {
        public int Id { get; set; }
        public DateTime FechaInicio { get; set; }
        public DateTime FechaTerm { get; set; }
        public double MontoMensual { get; set; }

        // Info básica del inquilino
        public int IdInquilino { get; set; }
        public string? NombreInquilino { get; set; }
        public string? ApellidoInquilino { get; set; }

        // Info básica del inmueble
        public int IdInmueble { get; set; }
        public string? Direccion { get; set; }
        public string? Tipo { get; set; }
        public double Precio { get; set; }
        public string? Imagen { get; set; }
    }
}

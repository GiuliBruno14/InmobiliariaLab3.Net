using System.Configuration;
using System.Data;
using Microsoft.Extensions.Diagnostics.Metrics.Configuration;
using MySql.Data.MySqlClient;
using Org.BouncyCastle.Asn1.X509.SigI;
using PROYECTO_BRUNO_SOAZO;

namespace PROYECTO_BRUNO_SOAZO.Models;

public class RepositorioTipoInmueble
{
    readonly string ConnectionString =
        "Server=localhost;Database=proyecto-bruno-soazo;User=root;Password=;";

    public RepositorioTipoInmueble() { }

    public int AltaTipoInmueble(TipoInmueble tipoInmueble)
    {
        try
        {
            int id = 0;
            using (var connection = new MySqlConnection(ConnectionString))
            {
                var sql =
                    @$"INSERT INTO tipoinmuebles ({nameof(TipoInmueble.Tipo)})
                                            VALUES (@{nameof(TipoInmueble.Tipo)});            
             SELECT LAST_INSERT_ID();";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue(
                        $"@{nameof(TipoInmueble.Tipo)}",
                        tipoInmueble.Tipo
                    );

                    connection.Open();
                    id = Convert.ToInt32(command.ExecuteScalar());
                    tipoInmueble.Id = id;
                    connection.Close();
                }
            }
            return id;
        }
        catch (Exception ex)
        {
            // Registrar el error o manejarlo adecuadamente
            Console.WriteLine($"Error al insertar el tipoinmueble: {ex.Message}");
            // Puedes relanzar la excepción o manejarla según sea necesario
            throw;
        }
    }

    public TipoInmueble? getTipoInmueble(int id)
    {
        TipoInmueble? tipoinmueble = null;
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT {nameof(TipoInmueble.Id)},{nameof(TipoInmueble.Tipo)}
            FROM tipoinmuebles WHERE {nameof(TipoInmueble.Id)} = @{nameof(TipoInmueble.Id)}";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(TipoInmueble.Id)}", id);
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        tipoinmueble = new TipoInmueble
                        {
                            Id = reader.GetInt32(nameof(TipoInmueble.Id)),
                            Tipo = reader.GetString(nameof(TipoInmueble.Tipo)),
                        };
                    }
                }
            }
        }
        return tipoinmueble;
    }

    public int ModificarTipoInmueble(TipoInmueble tipoinmueble)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"UPDATE tipoinmuebles 
            SET {nameof(TipoInmueble.Tipo)} = @{nameof(TipoInmueble.Tipo)},
          
            WHERE {nameof(TipoInmueble.Id)} = @{nameof(TipoInmueble.Id)} ";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(TipoInmueble.Id)}", tipoinmueble.Id);
                command.Parameters.AddWithValue($"@{nameof(TipoInmueble.Tipo)}", tipoinmueble.Tipo);

                connection.Open();
                command.ExecuteNonQuery();
                connection.Close();
            }
        }
        return 0;
    }

    public int EliminarTipoInmueble(int id)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"DELETE from tipoinmuebles WHERE {nameof(TipoInmueble.Id)} = @{nameof(TipoInmueble.Id)}";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(TipoInmueble.Id)}", id);
                connection.Open();
                command.ExecuteNonQuery();
                connection.Close();
            }
        }
        return 0;
    }

    public IList<TipoInmueble> BuscarPorTipo(string buscar)
    {
        var res = new List<TipoInmueble>();
        if (string.IsNullOrWhiteSpace(buscar))
        {
            return res;
        }
        buscar = "%" + buscar + "%";

        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT {nameof(TipoInmueble.Id)}, {nameof(TipoInmueble.Tipo)}
                    WHERE {nameof(TipoInmueble.Tipo)} LIKE @buscar";

            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.Add(
                    new MySqlParameter("buscar", MySqlDbType.VarChar) { Value = buscar }
                );
                command.CommandType = CommandType.Text;
                connection.Open();

                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var p = new TipoInmueble
                        {
                            Id = reader.GetInt32(reader.GetOrdinal(nameof(TipoInmueble.Id))),
                            Tipo = reader.GetString(reader.GetOrdinal(nameof(TipoInmueble.Tipo))),
                        };
                        res.Add(p);
                    }
                }
            }
        }

        return res;
    }

    public IList<TipoInmueble> ObtenerTipos()
    {
        var tipos = new List<TipoInmueble>();
        using (var connection = new MySqlConnection(ConnectionString))
        {
            string sql =
                @$"SELECT {nameof(TipoInmueble.Id)}, {nameof(TipoInmueble.Tipo)}
					FROM tipoinmuebles ORDER BY tipo ASC ";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.CommandType = CommandType.Text;
                connection.Open();
                var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    tipos.Add(
                        new TipoInmueble
                        {
                            Id = reader.GetInt32(nameof(TipoInmueble.Id)),
                            Tipo = reader.GetString(nameof(TipoInmueble.Tipo)),
                        }
                    );
                }
                connection.Close();
            }
        }
        return tipos;
    }
}

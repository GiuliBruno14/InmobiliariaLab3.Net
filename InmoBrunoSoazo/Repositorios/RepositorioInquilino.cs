using System.Configuration;
using System.Data;
using Microsoft.Extensions.Diagnostics.Metrics.Configuration;
using MySql.Data.MySqlClient;
using Org.BouncyCastle.Asn1.X509.SigI;
using PROYECTO_BRUNO_SOAZO;

namespace PROYECTO_BRUNO_SOAZO.Models;

public class RepositorioInquilino
{
    readonly string ConnectionString =
        "Server=localhost;Database=proyecto-bruno-soazo;User=root;Password=;";

    public RepositorioInquilino() { }

    public IList<Inquilino> GetInquilinos()
    {
        var inquilinos = new List<Inquilino>();
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT {nameof(Inquilino.Id)}, {nameof(Inquilino.Dni)}, 
            {nameof(Inquilino.Nombre)}, {nameof(Inquilino.Apellido)},  {nameof(Inquilino.Email)}, 
            {nameof(Inquilino.Telefono)}, {nameof(Inquilino.Domicilio)}, {nameof(Inquilino.Ciudad)}
            FROM inquilinos ORDER BY apellido LIMIT 10 OFFSET 0 ;";
            using (var command = new MySqlCommand(sql, connection))
            {
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        inquilinos.Add(
                            new Inquilino
                            {
                                Id = reader.GetInt32(nameof(Inquilino.Id)),
                                Nombre = reader.GetString(nameof(Inquilino.Nombre)),
                                Apellido = reader.GetString(nameof(Inquilino.Apellido)),
                                Dni = reader.GetString(nameof(Inquilino.Dni)),
                                Email = reader.GetString(nameof(Inquilino.Email)),
                                Telefono = reader.GetString(nameof(Inquilino.Telefono)),
                                Domicilio = reader.GetString(nameof(Inquilino.Domicilio)),
                                Ciudad = reader.GetString(nameof(Inquilino.Ciudad)),
                            }
                        );
                    }
                }
            }
        }
        return inquilinos;
    }

    public int AltaInquilino(Inquilino inquilino)
    {
        int id = 0;
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"INSERT INTO inquilinos ({nameof(Inquilino.Nombre)},{nameof(Inquilino.Apellido)},{nameof(Inquilino.Dni)},{nameof(Inquilino.Email)},{nameof(Inquilino.Telefono)},{nameof(Inquilino.Domicilio)},{nameof(Inquilino.Ciudad)})
                                            VALUES (@{nameof(Inquilino.Nombre)},@{nameof(Inquilino.Apellido)},@{nameof(Inquilino.Dni)},@{nameof(Inquilino.Email)},@{nameof(Inquilino.Telefono)},@{nameof(Inquilino.Domicilio)},@{nameof(Inquilino.Ciudad)});            
             SELECT LAST_INSERT_ID();";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Inquilino.Nombre)}", inquilino.Nombre);
                command.Parameters.AddWithValue(
                    $"@{nameof(Inquilino.Apellido)}",
                    inquilino.Apellido
                );
                command.Parameters.AddWithValue($"@{nameof(Inquilino.Dni)}", inquilino.Dni);
                command.Parameters.AddWithValue($"@{nameof(Inquilino.Email)}", inquilino.Email);
                command.Parameters.AddWithValue(
                    $"@{nameof(Inquilino.Telefono)}",
                    inquilino.Telefono
                );
                command.Parameters.AddWithValue(
                    $"@{nameof(Inquilino.Domicilio)}",
                    inquilino.Domicilio
                );
                command.Parameters.AddWithValue($"@{nameof(Inquilino.Ciudad)}", inquilino.Ciudad);

                connection.Open();
                id = Convert.ToInt32(command.ExecuteScalar());
                inquilino.Id = id;
                connection.Close();
            }
        }
        return id;
    }

    public Inquilino? GetInquilino(int id)
    {
        Inquilino? inquilino = null;
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT {nameof(Inquilino.Id)},{nameof(Inquilino.Nombre)},{nameof(Inquilino.Apellido)},{nameof(Inquilino.Dni)},{nameof(Inquilino.Email)},{nameof(Inquilino.Telefono)},{nameof(Inquilino.Domicilio)},{nameof(Inquilino.Ciudad)} 
            FROM inquilinos WHERE {nameof(Inquilino.Id)} = @{nameof(Inquilino.Id)}";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Inquilino.Id)}", id);
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        inquilino = new Inquilino
                        {
                            Id = reader.GetInt32(nameof(Inquilino.Id)),
                            Nombre = reader.GetString(nameof(Inquilino.Nombre)),
                            Apellido = reader.GetString(nameof(Inquilino.Apellido)),
                            Dni = reader.GetString(nameof(Inquilino.Dni)),
                            Email = reader.GetString(nameof(Inquilino.Email)),
                            Telefono = reader.GetString(nameof(Inquilino.Telefono)),
                            Domicilio = reader.GetString(nameof(Inquilino.Domicilio)),
                            Ciudad = reader.GetString(nameof(Inquilino.Ciudad)),
                        };
                    }
                }
            }
        }
        return inquilino;
    }

    public int ModificarInquilino(Inquilino inquilino)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"UPDATE Inquilinos 
            SET {nameof(Inquilino.Nombre)} = @{nameof(Inquilino.Nombre)},
            {nameof(Inquilino.Apellido)} = @{nameof(Inquilino.Apellido)},
            {nameof(Inquilino.Dni)} = @{nameof(Inquilino.Dni)},
            {nameof(Inquilino.Email)} = @{nameof(Inquilino.Email)},
            {nameof(Inquilino.Telefono)} = @{nameof(Inquilino.Telefono)},
            {nameof(Inquilino.Domicilio)} = @{nameof(Inquilino.Domicilio)},
            {nameof(Inquilino.Ciudad)} = @{nameof(Inquilino.Ciudad)}
            WHERE {nameof(Inquilino.Id)} = @{nameof(inquilino.Id)} ";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Inquilino.Id)}", inquilino.Id);
                command.Parameters.AddWithValue($"@{nameof(Inquilino.Nombre)}", inquilino.Nombre);
                command.Parameters.AddWithValue(
                    $"@{nameof(Inquilino.Apellido)}",
                    inquilino.Apellido
                );
                command.Parameters.AddWithValue($"@{nameof(Inquilino.Dni)}", inquilino.Dni);
                command.Parameters.AddWithValue($"@{nameof(Inquilino.Email)}", inquilino.Email);
                command.Parameters.AddWithValue(
                    $"@{nameof(Inquilino.Telefono)}",
                    inquilino.Telefono
                );
                command.Parameters.AddWithValue(
                    $"@{nameof(Inquilino.Domicilio)}",
                    inquilino.Domicilio
                );
                command.Parameters.AddWithValue($"@{nameof(Inquilino.Ciudad)}", inquilino.Ciudad);

                connection.Open();
                command.ExecuteNonQuery();
                connection.Close();
            }
        }
        return 0;
    }

    public int EliminarInquilino(int id)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"DELETE from Inquilinos WHERE {nameof(Inquilino.Id)} = @{nameof(Inquilino.Id)}";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Inquilino.Id)}", id);
                connection.Open();
                command.ExecuteNonQuery();
                connection.Close();
            }
        }
        return 0;
    }

    public IList<Inquilino> BuscarPorNombre(string nombre)
    {
        var res = new List<Inquilino>();
        nombre = "%" + nombre + "%"; // Usar comodines para la búsqueda parcial

        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT {nameof(Inquilino.Id)}, {nameof(Inquilino.Nombre)}, {nameof(Inquilino.Apellido)}, {nameof(Inquilino.Dni)}, {nameof(Inquilino.Email)}, {nameof(Inquilino.Telefono)}, {nameof(Inquilino.Domicilio)}, {nameof(Inquilino.Ciudad)} 
                    FROM inquilinos 
                    WHERE CONCAT({nameof(Inquilino.Nombre)}, ' ', {nameof(Inquilino.Apellido)}) LIKE @nombre
                    OR CONCAT({nameof(Inquilino.Apellido)}, ' ', {nameof(Inquilino.Nombre)}) LIKE @nombre
                    OR {nameof(Inquilino.Nombre)} LIKE @nombre 
                    OR {nameof(Inquilino.Apellido)} LIKE @nombre 
                    OR {nameof(Inquilino.Dni)} LIKE @nombre";

            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue("@nombre", nombre);
                command.CommandType = CommandType.Text;
                connection.Open();

                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var p = new Inquilino
                        {
                            Id = reader.GetInt32(reader.GetOrdinal(nameof(Inquilino.Id))),
                            Nombre = reader.GetString(reader.GetOrdinal(nameof(Inquilino.Nombre))),
                            Apellido = reader.GetString(
                                reader.GetOrdinal(nameof(Inquilino.Apellido))
                            ),
                            Dni = reader.GetString(reader.GetOrdinal(nameof(Inquilino.Dni))),
                            Telefono = reader.GetString(
                                reader.GetOrdinal(nameof(Inquilino.Telefono))
                            ),
                            Email = reader.GetString(reader.GetOrdinal(nameof(Inquilino.Email))),
                            Domicilio = reader.GetString(
                                reader.GetOrdinal(nameof(Inquilino.Domicilio))
                            ),
                            Ciudad = reader.GetString(reader.GetOrdinal(nameof(Inquilino.Ciudad))),
                        };
                        res.Add(p);
                    }
                }
            }
        }

        return res;
    }
}

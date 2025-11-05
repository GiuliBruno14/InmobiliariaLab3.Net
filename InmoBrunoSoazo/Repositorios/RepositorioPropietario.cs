using System.Configuration;
using System.Data;
using Microsoft.Extensions.Diagnostics.Metrics.Configuration;
using MySql.Data.MySqlClient;
using Org.BouncyCastle.Asn1.X509.SigI;
using PROYECTO_BRUNO_SOAZO;

namespace PROYECTO_BRUNO_SOAZO.Models;

public class RepositorioPropietario
{
    readonly string ConnectionString =
        "Server=localhost;Database=proyecto-bruno-soazo;User=root;Password=;";

    public RepositorioPropietario() { }

    public IList<Propietario> GetPropietarios()
    {
        var propietarios = new List<Propietario>();
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT {nameof(Propietario.Id)}, {nameof(Propietario.Dni)}, 
            {nameof(Propietario.Nombre)}, {nameof(Propietario.Apellido)},  {nameof(Propietario.Email)}, 
            {nameof(Propietario.Telefono)}, {nameof(Propietario.Domicilio)}, {nameof(Propietario.Ciudad)}
            FROM propietarios ORDER BY apellido LIMIT 10 OFFSET 0 ;";
            using (var command = new MySqlCommand(sql, connection))
            {
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        propietarios.Add(
                            new Propietario
                            {
                                Id = reader.GetInt32(nameof(Propietario.Id)),
                                Nombre = reader.GetString(nameof(Propietario.Nombre)),
                                Apellido = reader.GetString(nameof(Propietario.Apellido)),
                                Dni = reader.GetString(nameof(Propietario.Dni)),
                                Email = reader.GetString(nameof(Propietario.Email)),
                                Telefono = reader.GetString(nameof(Propietario.Telefono)),
                                Domicilio = reader.GetString(nameof(Propietario.Domicilio)),
                                Ciudad = reader.GetString(nameof(Propietario.Ciudad)),
                            }
                        );
                    }
                }
            }
        }
        return propietarios;
    }

    public int AltaPropietario(Propietario propietario)
    {
        try
        {
            int id = 0;
            using (var connection = new MySqlConnection(ConnectionString))
            {
                var sql =
                    @$"INSERT INTO propietarios ({nameof(Propietario.Nombre)},{nameof(Propietario.Apellido)},{nameof(Propietario.Dni)},{nameof(Propietario.Email)},{nameof(Propietario.Telefono)},{nameof(Propietario.Domicilio)},{nameof(Propietario.Ciudad)})
                                            VALUES (@{nameof(Propietario.Nombre)},@{nameof(Propietario.Apellido)},@{nameof(Propietario.Dni)},@{nameof(Propietario.Email)},@{nameof(Propietario.Telefono)},@{nameof(Propietario.Domicilio)},@{nameof(Propietario.Ciudad)});            
             SELECT LAST_INSERT_ID();";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue(
                        $"@{nameof(Propietario.Nombre)}",
                        propietario.Nombre
                    );
                    command.Parameters.AddWithValue(
                        $"@{nameof(Propietario.Apellido)}",
                        propietario.Apellido
                    );
                    command.Parameters.AddWithValue($"@{nameof(Propietario.Dni)}", propietario.Dni);
                    command.Parameters.AddWithValue(
                        $"@{nameof(Propietario.Email)}",
                        propietario.Email
                    );
                    command.Parameters.AddWithValue(
                        $"@{nameof(Propietario.Telefono)}",
                        propietario.Telefono
                    );
                    command.Parameters.AddWithValue(
                        $"@{nameof(Propietario.Domicilio)}",
                        propietario.Domicilio
                    );
                    command.Parameters.AddWithValue(
                        $"@{nameof(Propietario.Ciudad)}",
                        propietario.Ciudad
                    );

                    connection.Open();
                    id = Convert.ToInt32(command.ExecuteScalar());
                    propietario.Id = id;
                    connection.Close();
                }
            }
            return id;
        }
        catch (Exception ex)
        {
            // Registrar el error o manejarlo adecuadamente
            Console.WriteLine($"Error al insertar el propietario: {ex.Message}");
            // Puedes relanzar la excepción o manejarla según sea necesario
            throw;
        }
    }

    public Propietario? getPropietario(int id)
    {
        Propietario? propietario = null;
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT {nameof(Propietario.Id)},{nameof(Propietario.Nombre)},{nameof(Propietario.Apellido)},{nameof(Propietario.Dni)},{nameof(Propietario.Email)},{nameof(Propietario.Telefono)},{nameof(Propietario.Domicilio)},{nameof(Propietario.Ciudad)} 
            FROM propietarios WHERE {nameof(Propietario.Id)} = @{nameof(Propietario.Id)}";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Propietario.Id)}", id);
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        propietario = new Propietario
                        {
                            Id = reader.GetInt32(nameof(Propietario.Id)),
                            Nombre = reader.GetString(nameof(Propietario.Nombre)),
                            Apellido = reader.GetString(nameof(Propietario.Apellido)),
                            Dni = reader.GetString(nameof(Propietario.Dni)),
                            Email = reader.GetString(nameof(Propietario.Email)),
                            Telefono = reader.GetString(nameof(Propietario.Telefono)),
                            Domicilio = reader.GetString(nameof(Propietario.Domicilio)),
                            Ciudad = reader.GetString(nameof(Propietario.Ciudad)),
                        };
                    }
                }
            }
        }
        return propietario;
    }

    public int ModificarPropietario(Propietario propietario)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"UPDATE propietarios 
            SET {nameof(Propietario.Nombre)} = @{nameof(Propietario.Nombre)},
            {nameof(Propietario.Apellido)} = @{nameof(Propietario.Apellido)},
            {nameof(Propietario.Dni)} = @{nameof(Propietario.Dni)},
            {nameof(Propietario.Email)} = @{nameof(Propietario.Email)},
            {nameof(Propietario.Telefono)} = @{nameof(Propietario.Telefono)},
            {nameof(Propietario.Domicilio)} = @{nameof(Propietario.Domicilio)},
            {nameof(Propietario.Ciudad)} = @{nameof(Propietario.Ciudad)}
            WHERE {nameof(Propietario.Id)} = @{nameof(Propietario.Id)} ";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Propietario.Id)}", propietario.Id);
                command.Parameters.AddWithValue(
                    $"@{nameof(Propietario.Nombre)}",
                    propietario.Nombre
                );
                command.Parameters.AddWithValue(
                    $"@{nameof(Propietario.Apellido)}",
                    propietario.Apellido
                );
                command.Parameters.AddWithValue($"@{nameof(Propietario.Dni)}", propietario.Dni);
                command.Parameters.AddWithValue($"@{nameof(Propietario.Email)}", propietario.Email);
                command.Parameters.AddWithValue(
                    $"@{nameof(Propietario.Telefono)}",
                    propietario.Telefono
                );
                command.Parameters.AddWithValue(
                    $"@{nameof(Propietario.Domicilio)}",
                    propietario.Domicilio
                );
                command.Parameters.AddWithValue(
                    $"@{nameof(Propietario.Ciudad)}",
                    propietario.Ciudad
                );

                connection.Open();
                command.ExecuteNonQuery();
                Console.WriteLine($"Propietario modificado: {propietario.Id}");
                ActualizarUsuarioDePropietario(
                    connection,
                    propietario.Id,
                    propietario.Nombre,
                    propietario.Apellido,
                    propietario.Email
                );
                Console.WriteLine($"Propietario usuario modificado: {propietario.Id}");
                connection.Close();
            }
        }
        return 0;
    }

    public int EliminarPropietario(int id)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"DELETE from propietarios WHERE {nameof(Propietario.Id)} = @{nameof(Propietario.Id)}";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Propietario.Id)}", id);
                connection.Open();
                command.ExecuteNonQuery();
                connection.Close();
            }
        }
        return 0;
    }

    public IList<Propietario> BuscarPorNombre(string buscar)
    {
        var res = new List<Propietario>();
        if (string.IsNullOrWhiteSpace(buscar))
        {
            return res;
        }
        buscar = "%" + buscar + "%";

        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT {nameof(Propietario.Id)}, {nameof(Propietario.Nombre)}, {nameof(Propietario.Apellido)}, {nameof(Propietario.Dni)}, {nameof(Propietario.Email)}, {nameof(Propietario.Telefono)}, {nameof(Propietario.Domicilio)}, {nameof(Propietario.Ciudad)} 
                    FROM propietarios
                    WHERE CONCAT({nameof(Propietario.Nombre)}, ' ', {nameof(Propietario.Apellido)}) LIKE @buscar
                    OR CONCAT({nameof(Propietario.Apellido)}, ' ', {nameof(Propietario.Nombre)}) LIKE @buscar
                    OR {nameof(Propietario.Nombre)} LIKE @buscar
                    OR {nameof(Propietario.Apellido)} LIKE @buscar
                    OR {nameof(Propietario.Dni)} LIKE @buscar";

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
                        var p = new Propietario
                        {
                            Id = reader.GetInt32(reader.GetOrdinal(nameof(Propietario.Id))),
                            Nombre = reader.GetString(
                                reader.GetOrdinal(nameof(Propietario.Nombre))
                            ),
                            Apellido = reader.GetString(
                                reader.GetOrdinal(nameof(Propietario.Apellido))
                            ),
                            Dni = reader.GetString(reader.GetOrdinal(nameof(Propietario.Dni))),
                            Telefono = reader.GetString(
                                reader.GetOrdinal(nameof(Propietario.Telefono))
                            ),
                            Email = reader.GetString(reader.GetOrdinal(nameof(Propietario.Email))),
                            Domicilio = reader.GetString(
                                reader.GetOrdinal(nameof(Propietario.Domicilio))
                            ),
                            Ciudad = reader.GetString(
                                reader.GetOrdinal(nameof(Propietario.Ciudad))
                            ),
                        };
                        res.Add(p);
                    }
                }
            }
        }

        return res;
    }

    public Propietario? getPropietarioIdUsuario(int idUsuario)
    {
        Propietario? propietario = null;

        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT {nameof(Propietario.Id)},{nameof(Propietario.Nombre)},{nameof(Propietario.Apellido)},{nameof(Propietario.Dni)},{nameof(Propietario.Email)},{nameof(Propietario.Telefono)},{nameof(Propietario.Domicilio)},{nameof(Propietario.Ciudad)} 
            FROM propietarios WHERE {nameof(Propietario.IdUsuario)} = @IdUsuario;";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@IdUsuario", idUsuario);
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        propietario = new Propietario
                        {
                            Id = reader.GetInt32(nameof(Propietario.Id)),
                            Nombre = reader.GetString(nameof(Propietario.Nombre)),
                            Apellido = reader.GetString(nameof(Propietario.Apellido)),
                            Dni = reader.GetString(nameof(Propietario.Dni)),
                            Email = reader.GetString(nameof(Propietario.Email)),
                            Telefono = reader.GetString(nameof(Propietario.Telefono)),
                            Domicilio = reader.GetString(nameof(Propietario.Domicilio)),
                            Ciudad = reader.GetString(nameof(Propietario.Ciudad)),
                        };
                    }
                }
            }
        }
        return propietario;
    }

    private int ActualizarUsuarioDePropietario(
        MySqlConnection connection,
        int propietarioId,
        string nombre,
        string apellido,
        string email
    )
    {
        var sqlUsuario =
            $@"
        UPDATE usuarios u
        INNER JOIN propietarios p ON p.IdUsuario = u.Id
        SET u.Nombre = @Nombre,
            u.Apellido = @Apellido,
            u.Correo = @Email
        WHERE p.Id = @IdPropietario";

        using (var cmdUser = new MySqlCommand(sqlUsuario, connection))
        {
            cmdUser.Parameters.AddWithValue("@Nombre", nombre);
            cmdUser.Parameters.AddWithValue("@Apellido", apellido);
            cmdUser.Parameters.AddWithValue("@Email", email);
            cmdUser.Parameters.AddWithValue("@IdPropietario", propietarioId);

            return cmdUser.ExecuteNonQuery();
        }
    }

    public int ModificarPropietarioApp(Propietario propietario)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"UPDATE propietarios 
            SET {nameof(Propietario.Nombre)} = @{nameof(Propietario.Nombre)},
            {nameof(Propietario.Apellido)} = @{nameof(Propietario.Apellido)},
            {nameof(Propietario.Dni)} = @{nameof(Propietario.Dni)},
            {nameof(Propietario.Email)} = @{nameof(Propietario.Email)},
            {nameof(Propietario.Telefono)} = @{nameof(Propietario.Telefono)}
            WHERE {nameof(Propietario.Id)} = @{nameof(Propietario.Id)} ";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Propietario.Id)}", propietario.Id);
                command.Parameters.AddWithValue(
                    $"@{nameof(Propietario.Nombre)}",
                    propietario.Nombre
                );
                command.Parameters.AddWithValue(
                    $"@{nameof(Propietario.Apellido)}",
                    propietario.Apellido
                );
                command.Parameters.AddWithValue($"@{nameof(Propietario.Dni)}", propietario.Dni);
                command.Parameters.AddWithValue($"@{nameof(Propietario.Email)}", propietario.Email);
                command.Parameters.AddWithValue(
                    $"@{nameof(Propietario.Telefono)}",
                    propietario.Telefono
                );
                connection.Open();
                command.ExecuteNonQuery();
                Console.WriteLine($"Propietario modificado: {propietario.Id}");
                ActualizarUsuarioDePropietario(
                    connection,
                    propietario.Id,
                    propietario.Nombre,
                    propietario.Apellido,
                    propietario.Email
                );
                Console.WriteLine($"Propietario usuario modificado: {propietario.Id}");
                connection.Close();
            }
        }
        return 0;
    }
}

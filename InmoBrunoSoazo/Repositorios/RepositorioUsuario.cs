using System.Configuration;
using System.Data;
using Microsoft.Extensions.Diagnostics.Metrics.Configuration;
using MySql.Data.MySqlClient;
using Org.BouncyCastle.Asn1.X509.SigI;
using PROYECTO_BRUNO_SOAZO;

namespace PROYECTO_BRUNO_SOAZO.Models;

public class RepositorioUsuario
{
    readonly string ConnectionString =
        "Server=localhost;Database=proyecto-bruno-soazo;User=root;Password=;";

    public RepositorioUsuario() { }

    public IList<Usuario> GetUsuarios()
    {
        var usuarios = new List<Usuario>();
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT {nameof(Usuario.Id)},
            {nameof(Usuario.Nombre)}, {nameof(Usuario.Apellido)},  {nameof(Usuario.Correo)}, 
            {nameof(Usuario.AvatarURL)}, {nameof(Usuario.Rol)}
            FROM usuarios ORDER BY apellido LIMIT 10 OFFSET 0 ;";
            using (var command = new MySqlCommand(sql, connection))
            {
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        usuarios.Add(
                            new Usuario
                            {
                                Id = reader.GetInt32(nameof(Usuario.Id)),
                                Nombre = reader.GetString(nameof(Usuario.Nombre)),
                                Apellido = reader.GetString(nameof(Usuario.Apellido)),
                                Correo = reader.GetString(nameof(Usuario.Correo)),
                                AvatarURL = reader.IsDBNull(
                                    reader.GetOrdinal(nameof(Usuario.AvatarURL))
                                )
                                    ? null
                                    : reader.GetString(nameof(Usuario.AvatarURL)),
                                Rol = reader.GetInt32(nameof(Usuario.Rol)),
                            }
                        );
                    }
                }
            }
        }
        return usuarios;
    }

    public int AltaUsuario(Usuario usuario)
    {
        try
        {
            int id = 0;
            using (var connection = new MySqlConnection(ConnectionString))
            {
                var sql =
                    @$"INSERT INTO usuarios ({nameof(Usuario.Nombre)},{nameof(Usuario.Apellido)},{nameof(Usuario.Correo)},{nameof(Usuario.Clave)},{nameof(Usuario.Rol)})
                                            VALUES (@{nameof(Usuario.Nombre)},@{nameof(Usuario.Apellido)},@{nameof(Usuario.Correo)},@{nameof(Usuario.Clave)},@{nameof(Usuario.Rol)});         
             SELECT LAST_INSERT_ID();";
                using (var command = new MySqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue($"@{nameof(Usuario.Nombre)}", usuario.Nombre);
                    command.Parameters.AddWithValue(
                        $"@{nameof(Usuario.Apellido)}",
                        usuario.Apellido
                    );
                    command.Parameters.AddWithValue($"@{nameof(Usuario.Correo)}", usuario.Correo);
                    command.Parameters.AddWithValue($"@{nameof(Usuario.Clave)}", usuario.Clave);
                    command.Parameters.AddWithValue($"@{nameof(Usuario.Rol)}", usuario.Rol);

                    connection.Open();
                    id = Convert.ToInt32(command.ExecuteScalar());
                    usuario.Id = id;
                    connection.Close();
                }
            }
            return id;
        }
        catch (Exception ex)
        {
            // Registrar el error o manejarlo adecuadamente
            Console.WriteLine($"Error al insertar el Usuario: {ex.Message}");
            // Puedes relanzar la excepción o manejarla según sea necesario
            throw;
        }
    }

    public Usuario? getUsuario(int id)
    {
        Usuario? usuario = null;
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT u.{nameof(Usuario.Id)}, u.{nameof(Usuario.Nombre)}, u.{nameof(Usuario.Apellido)}, u.{nameof(Usuario.Correo)}, u.{nameof(Usuario.AvatarURL)}, r.{nameof(Rol.rol)}, r.{nameof(Rol.Numero)}  
        FROM usuarios u INNER JOIN roles r ON u.{nameof(Usuario.Rol)} = r.{nameof(Rol.Numero)} WHERE u.{nameof(Usuario.Id)} = @{nameof(Usuario.Id)}";

            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Usuario.Id)}", id);
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        usuario = new Usuario
                        {
                            Id = reader.GetInt32(reader.GetOrdinal(nameof(Usuario.Id))),
                            Nombre = reader.GetString(reader.GetOrdinal(nameof(Usuario.Nombre))),
                            Apellido = reader.GetString(
                                reader.GetOrdinal(nameof(Usuario.Apellido))
                            ),
                            Correo = reader.GetString(reader.GetOrdinal(nameof(Usuario.Correo))),
                            AvatarURL = reader.GetString(
                                reader.GetOrdinal(nameof(Usuario.AvatarURL))
                            ),
                            Datos = new Rol
                            {
                                Numero = reader.GetInt32(reader.GetOrdinal(nameof(Rol.Numero))),
                                rol = reader.GetString(reader.GetOrdinal(nameof(Rol.rol))),
                            },
                        };
                    }
                }
            }
        }
        return usuario;
    }

    public int ModificarUsuario(Usuario usuario)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            // Construir la consulta SQL con campos opcionales
            var sql =
                @$"UPDATE Usuarios 
            SET {nameof(Usuario.Nombre)} = @{nameof(Usuario.Nombre)},
            {nameof(Usuario.Apellido)} = @{nameof(Usuario.Apellido)},
            {nameof(Usuario.Correo)} = @{nameof(Usuario.Correo)},
            {nameof(Usuario.AvatarURL)} = @{nameof(Usuario.AvatarURL)},
            {nameof(Usuario.Rol)} = @{nameof(Usuario.Rol)}";

            // Solo añadir la columna de Clave si no está vacía
            if (!string.IsNullOrEmpty(usuario.Clave))
            {
                sql += $", {nameof(Usuario.Clave)} = @{nameof(Usuario.Clave)}";
            }

            sql += $" WHERE {nameof(Usuario.Id)} = @{nameof(Usuario.Id)}";

            using (var command = new MySqlCommand(sql, connection))
            {
                // Añadir los parámetros obligatorios
                command.Parameters.AddWithValue($"@{nameof(Usuario.Id)}", usuario.Id);
                command.Parameters.AddWithValue($"@{nameof(Usuario.Nombre)}", usuario.Nombre);
                command.Parameters.AddWithValue($"@{nameof(Usuario.Apellido)}", usuario.Apellido);
                command.Parameters.AddWithValue($"@{nameof(Usuario.Correo)}", usuario.Correo);
                command.Parameters.AddWithValue($"@{nameof(Usuario.AvatarURL)}", usuario.AvatarURL);
                command.Parameters.AddWithValue($"@{nameof(Usuario.Rol)}", usuario.Rol);

                // Solo añadir el parámetro Clave si está presente
                if (!string.IsNullOrEmpty(usuario.Clave))
                {
                    command.Parameters.AddWithValue($"@{nameof(Usuario.Clave)}", usuario.Clave);
                }

                connection.Open();
                command.ExecuteNonQuery();
                connection.Close();
            }
        }
        return 0;
    }

    public int EditarDatos(Usuario usuario)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"UPDATE Usuarios 
            SET {nameof(Usuario.Nombre)} = @{nameof(Usuario.Nombre)},
            {nameof(Usuario.Apellido)} = @{nameof(Usuario.Apellido)},
            {nameof(Usuario.Correo)} = @{nameof(Usuario.Correo)}
            WHERE {nameof(Usuario.Id)} = @{nameof(Usuario.Id)} ";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Usuario.Id)}", usuario.Id);
                command.Parameters.AddWithValue($"@{nameof(Usuario.Nombre)}", usuario.Nombre);
                command.Parameters.AddWithValue($"@{nameof(Usuario.Apellido)}", usuario.Apellido);
                command.Parameters.AddWithValue($"@{nameof(Usuario.Correo)}", usuario.Correo);
                connection.Open();
                command.ExecuteNonQuery();
                connection.Close();
            }
        }
        return 0;
    }

    public int EditarAvatar(Usuario usuario)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"UPDATE Usuarios 
            SET 
            {nameof(Usuario.AvatarURL)} = @{nameof(Usuario.AvatarURL)}
            WHERE {nameof(Usuario.Id)} = @{nameof(Usuario.Id)} ";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Usuario.Id)}", usuario.Id);
                command.Parameters.AddWithValue($"@{nameof(Usuario.AvatarURL)}", usuario.AvatarURL);
                connection.Open();
                command.ExecuteNonQuery();
                connection.Close();
            }
        }
        return 0;
    }

    public int EditarClave(Usuario usuario)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"UPDATE Usuarios 
            SET 
            {nameof(Usuario.Clave)} = @{nameof(Usuario.Clave)}
            WHERE {nameof(Usuario.Id)} = @{nameof(Usuario.Id)} ";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Usuario.Id)}", usuario.Id);
                command.Parameters.AddWithValue($"@{nameof(Usuario.Clave)}", usuario.Clave);
                connection.Open();
                command.ExecuteNonQuery();
                connection.Close();
            }
        }
        return 0;
    }

    public int EliminarUsuario(int id)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql = @$"DELETE from usuarios WHERE {nameof(Usuario.Id)} = @{nameof(Usuario.Id)}";
            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Usuario.Id)}", id);
                connection.Open();
                command.ExecuteNonQuery();
                connection.Close();
            }
        }
        return 0;
    }

    public IList<Usuario> BuscarPorNombre(string nombre)
    {
        var res = new List<Usuario>();
        nombre = "%" + nombre + "%";

        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT {nameof(Usuario.Id)},{nameof(Usuario.Nombre)},{nameof(Usuario.Apellido)},{nameof(Usuario.Correo)},{nameof(Usuario.Clave)},{nameof(Usuario.AvatarURL)},{nameof(Usuario.Rol)} FROM usuarios
                      WHERE {nameof(Usuario.Nombre)} LIKE @{nameof(Usuario.Nombre)} OR {nameof(Usuario.Apellido)} LIKE @{nameof(Usuario.Nombre)}";

            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.Add(
                    new MySqlParameter(nameof(nombre), MySqlDbType.VarChar) { Value = nombre }
                );
                command.CommandType = CommandType.Text;
                connection.Open();

                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var p = new Usuario
                        {
                            Id = reader.GetInt32(reader.GetOrdinal(nameof(Usuario.Id))),
                            Nombre = reader.GetString(reader.GetOrdinal(nameof(Usuario.Nombre))),
                            Apellido = reader.GetString(
                                reader.GetOrdinal(nameof(Usuario.Apellido))
                            ),
                            Correo = reader.GetString(reader.GetOrdinal(nameof(Usuario.Correo))),
                            Clave = reader.GetString(reader.GetOrdinal(nameof(Usuario.Clave))),
                            Rol = reader.GetInt32(reader.GetOrdinal(nameof(Usuario.Rol))),
                        };
                        res.Add(p);
                    }
                }
            }
        }

        return res;
    }

    public Usuario? ObtenerPorEmail(string email)
    {
        Usuario? usuario = null;
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT u.{nameof(Usuario.Id)}, u.{nameof(Usuario.Nombre)}, u.{nameof(Usuario.Apellido)}, u.{nameof(Usuario.Correo)}, u.{nameof(Usuario.Clave)}, u.{nameof(Usuario.AvatarURL)}, r.{nameof(Rol.rol)}, r.{nameof(Rol.Numero)}  
        FROM usuarios u INNER JOIN roles r ON u.{nameof(Usuario.Rol)} = r.{nameof(Rol.Numero)} WHERE u.{nameof(Usuario.Correo)} = @{nameof(Usuario.Correo)}";

            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Usuario.Correo)}", email);
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        usuario = new Usuario
                        {
                            Id = reader.GetInt32(reader.GetOrdinal(nameof(Usuario.Id))),
                            Nombre = reader.GetString(reader.GetOrdinal(nameof(Usuario.Nombre))),
                            Apellido = reader.GetString(
                                reader.GetOrdinal(nameof(Usuario.Apellido))
                            ),
                            Correo = reader.GetString(reader.GetOrdinal(nameof(Usuario.Correo))),
                            Clave = reader.GetString(reader.GetOrdinal(nameof(Usuario.Clave))),
                            AvatarURL = reader.IsDBNull(
                                reader.GetOrdinal(nameof(Usuario.AvatarURL))
                            )
                                ? null
                                : reader.GetString(reader.GetOrdinal(nameof(Usuario.AvatarURL))),
                            Datos = new Rol
                            {
                                Numero = reader.GetInt32(reader.GetOrdinal(nameof(Rol.Numero))),
                                rol = reader.GetString(reader.GetOrdinal(nameof(Rol.rol))),
                            },
                        };
                    }
                }
            }
        }
        return usuario;
    }

    public IList<Usuario> ObtenerPorNombreOCorreo(string nombreOCorreo)
    {
        var res = new List<Usuario>();
        nombreOCorreo = "%" + nombreOCorreo + "%"; // Usar comodines para la búsqueda parcial

        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                @$"SELECT u.{nameof(Usuario.Id)}, u.{nameof(Usuario.Nombre)}, u.{nameof(Usuario.Apellido)}, 
                            u.{nameof(Usuario.Correo)}, u.{nameof(Usuario.Clave)}, u.{nameof(Usuario.AvatarURL)}, 
                            r.{nameof(Rol.rol)}, r.{nameof(Rol.Numero)}  
                    FROM usuarios u 
                    INNER JOIN roles r ON u.{nameof(Usuario.Rol)} = r.{nameof(Rol.Numero)}
                    WHERE u.{nameof(Usuario.Nombre)} LIKE @nombreOCorreo 
                    OR u.{nameof(Usuario.Correo)} LIKE @nombreOCorreo";

            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@nombreOCorreo", nombreOCorreo);
                command.CommandType = CommandType.Text;
                connection.Open();
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var u = new Usuario
                        {
                            Id = reader.GetInt32(reader.GetOrdinal(nameof(Usuario.Id))),
                            Nombre = reader.GetString(reader.GetOrdinal(nameof(Usuario.Nombre))),
                            Apellido = reader.GetString(
                                reader.GetOrdinal(nameof(Usuario.Apellido))
                            ),
                            Correo = reader.GetString(reader.GetOrdinal(nameof(Usuario.Correo))),
                            Clave = reader.GetString(reader.GetOrdinal(nameof(Usuario.Clave))),
                            AvatarURL = reader.GetString(
                                reader.GetOrdinal(nameof(Usuario.AvatarURL))
                            ),
                            Datos = new Rol
                            {
                                Numero = reader.GetInt32(reader.GetOrdinal(nameof(Rol.Numero))),
                                rol = reader.GetString(reader.GetOrdinal(nameof(Rol.rol))),
                            },
                        };
                        res.Add(u);
                    }
                }
            }
        }

        return res;
    }

    public int ActualizarClave(string email, string nuevaClave)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            var sql =
                $"UPDATE Usuarios SET {nameof(Usuario.Clave)} = @{nameof(Usuario.Clave)} WHERE {nameof(Usuario.Correo)} = @{nameof(Usuario.Correo)}";

            using (var command = new MySqlCommand(sql, connection))
            {
                command.Parameters.AddWithValue($"@{nameof(Usuario.Correo)}", email);
                command.Parameters.AddWithValue($"@{nameof(Usuario.Clave)}", nuevaClave);

                connection.Open();
                command.ExecuteNonQuery();
            }
        }
        return 0;
    }
}

# Supabase: configuración de base de datos para Crypto Drive

Este documento explica cómo provisionar la base de datos PostgreSQL en Supabase y aplicar el esquema inicial (`schema.sql`).

## Pasos
1. Crear un nuevo proyecto en [Supabase](https://supabase.com/) y obtener la cadena de conexión (`postgresql://user:password@host:5432/postgres`).
2. En la consola SQL de Supabase, ejecutar el contenido de `schema.sql` para crear las tablas base (`users`, `files`) y los componentes criptográficos (`user_keys` para las claves del usuario, `ca_certs` para almacenar certificados y claves cifradas de la Root/Issuing CA, `user_certs` para los certificados X.509 emitidos a cada usuario con soporte de revocación, `file_shares` para reenvolver la clave simétrica cuando se comparte un fichero). 
3. Crear un usuario/rol dedicado para la aplicación (opcional pero recomendado) y otorgarle permisos sobre el esquema.
4. Configurar la variable de entorno `DATABASE_URL` en el backend con la cadena de conexión completa, por ejemplo:
   ```bash
   DATABASE_URL="postgresql+psycopg://USER:PASSWORD@HOST:5432/postgres"
   ```
5. Reiniciar o desplegar el backend con esta variable definida. SQLAlchemy usará esta URL para conectarse a Supabase.

## Notas
- `schema.sql` habilita la extensión `pgcrypto` para generar UUIDs con `gen_random_uuid()`.
- Añade reglas de seguridad de Supabase según sea necesario; el backend será responsable de la autenticación/autorización.
- El esquema también incluye `file_shares` para reenvolver claves simétricas cuando se comparten ficheros entre usuarios.

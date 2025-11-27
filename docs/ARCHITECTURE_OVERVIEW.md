# Arquitectura general

## Flujo principal
- Los usuarios se registran e inician sesión; el backend almacena hashes de contraseña y genera pares RSA por usuario, cifrando la clave privada con una clave derivada del `password_hash`.
- La PKI contiene una Root CA y una Issuing CA en la tabla `ca_certs`; los certificados X.509 de usuario se guardan en `user_certs` con un indicador `revoked` para revocación suave.
- Los ficheros se cifran con AES-256-GCM; la clave simétrica se envuelve con RSA-OAEP usando la clave pública del propietario y se guarda en `files.encrypted_key`.
- Al compartir, se reutiliza la clave simétrica original y se reenvuelve con la clave pública del destinatario, guardándola en `file_shares.encrypted_key_for_recipient`.

## Verificación y revocación
- La verificación de firma usa la clave pública del certificado del usuario; si el certificado está marcado como revocado, la respuesta indica `cert_revoked`.
- La revocación de certificados y la revocación de compartidos invalidan la confianza sin borrar los ficheros originales.

# Crypto Drive

Plataforma académica para almacenamiento y compartición de ficheros cifrados extremo a extremo. Combina cifrado simétrico AES-256-GCM, envoltura de claves con RSA-OAEP y una PKI interna (Root + Issuing CA) para emitir certificados X.509 y validar firmas.

## Tecnologías utilizadas
- **Backend:** FastAPI, SQLAlchemy, PostgreSQL/Supabase, cryptography, passlib/bcrypt.
- **Frontend:** React 18, Vite, TypeScript, TailwindCSS.

## Estructura del repositorio
- `backend/`: API FastAPI, lógica criptográfica, modelos SQLAlchemy y rutas REST.
- `frontend/`: SPA en React (login/registro, dashboard de ficheros, pantalla de seguridad).
- `db/`: `schema.sql` y guía de despliegue en Supabase.
- `docs/`: Resumen de arquitectura y notas adicionales.

## Arranque rápido (local)
1. **Requisitos:** Python 3.11+, Node 18+, y una base PostgreSQL (o proyecto Supabase).
2. **Base de datos:** Ejecuta `db/schema.sql` sobre tu instancia. Guía detallada en `db/SUPABASE_DB_SETUP.md`.
3. **Backend:**
   - `cd backend`
   - `python -m venv .venv && source .venv/bin/activate` (Windows: `.venv\\Scripts\\activate`)
   - `pip install -r requirements.txt`
   - Copia `.env.example` a `.env` y ajusta `DATABASE_URL` y `APP_NAME`.
   - `uvicorn app.main:app --reload`
4. **Frontend:**
   - `cd frontend`
   - `npm install`
   - `npm run dev`
   - Usa `VITE_API_BASE_URL` (por defecto `http://localhost:8000/api`) para apuntar al backend.

## Cómo usar Crypto Drive (demo)
1. Regístrate con dos usuarios desde `/register`.
2. Inicia sesión como usuario A (`/login`); el dashboard generará sus claves RSA automáticamente.
3. En `/security`, pulsa **Inicializar PKI** y solicita el certificado del usuario A.
4. Vuelve al dashboard, sube un fichero, descárgalo y verifica que funciona.
5. Comparte el fichero con el usuario B escribiendo su `username`.
6. Cierra sesión, entra como usuario B, revisa "Ficheros compartidos contigo" y descárgalo.
7. (Opcional) Emite certificado para el usuario B y prueba la verificación de firma.

## Seguridad y limitaciones
- Las claves privadas de usuario se cifran con una clave derivada de su `password_hash` (válido para entorno académico, no producción real).
- Las claves de la CA se protegen con un secreto maestro estático (`CA_MASTER_SECRET`) para simplificar la práctica.
- No sustituye a un HSM ni a un gestor de secretos completo.

## Guía para desarrolladores
- Ejecuta backend y frontend en paralelo (`uvicorn app.main:app --reload` y `npm run dev`).
- Para resetear la base de datos en pruebas, vuelve a aplicar `db/schema.sql` sobre una instancia limpia o usa otra BD vacía.
- Rutas clave:
  - `/auth`: registro y login.
  - `/keys`: generación de par RSA y gestión de clave cifrada.
  - `/files`: subida, descarga, compartición y verificación de firmas.
  - `/pki`: bootstrap de CA, emisión y revocación de certificados.

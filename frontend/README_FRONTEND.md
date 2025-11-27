# Frontend (React + Vite + Tailwind)

## Arranque rápido
- Instala dependencias: `npm install`
- Ejecuta el servidor de desarrollo: `npm run dev`

## Configuración de API
- El frontend consume el backend en `VITE_API_BASE_URL` (por defecto `http://localhost:8000/api`).
- Para sobrescribirlo, copia `.env.example` a `.env` y ajusta la URL.
- El login/registro está en `/auth` y el resto de flujos usan el header `X-User-Id` cargado desde `localStorage`.

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api';

/**
 * GET genérico que fuerza JSON y propaga errores.
 * Entradas: path relativo y opciones extra de fetch.
 * Salidas: cuerpo JSON parseado o excepción con el texto de error devuelto por la API.
 */
export async function apiGet(path: string, init?: RequestInit) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'API request failed');
  }

  return response.json();
}

/**
 * POST con JSON, útil para login y registro antes de manejar claves.
 * Entradas: path, cuerpo serializable y opciones de fetch.
 * Salidas: JSON de respuesta o error con el mensaje del backend.
 */
export async function apiPost(path: string, body: unknown, init?: RequestInit) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'API request failed');
  }

  return response.json();
}

/**
 * POST para formularios/multipart, usado al subir blobs cifrados.
 * Entradas: path y FormData con el archivo cifrado.
 * Salidas: JSON devuelto por el backend o excepción con el texto de error.
 */
export async function apiPostForm(path: string, formData: FormData, init?: RequestInit) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'API request failed');
  }

  return response.json();
}

/**
 * GET que devuelve blobs binarios (ej. ficheros cifrados) sin intentar parsear JSON.
 */
export async function apiGetBlob(path: string, init?: RequestInit) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    method: 'GET',
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || 'API request failed');
  }

  return response.blob();
}

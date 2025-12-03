// Importamos hooks de React
import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

// Importamos funciones de cliente API (GET, POST, POST FormData…)
import { API_BASE_URL, apiGet, apiGetBlob, apiPost, apiPostForm } from '../api/client'

// Claves que usamos para guardar el userId y username en localStorage
import { USER_STORAGE_KEY, USERNAME_STORAGE_KEY } from './Login'

/*
  Interfaces para tipar los objetos que recibimos del backend.
  Sirven para saber la estructura de cada fichero.
*/
interface FileItem {
  id: string
  owner_id: string
  filename: string
  encryption_algorithm: string
  key_encryption_algorithm: string
  signature: string | null
  signature_algorithm: string | null
  created_at: string
}

interface SharedFileItem {
  share_id: string
  file_id: string
  filename: string
  owner_username: string
  encryption_algorithm: string
  key_encryption_algorithm: string
  has_signature: boolean
  created_at: string
}

interface SharedByMeItem {
  share_id: string
  file_id: string
  filename: string
  recipient_username: string
  encryption_algorithm: string
  key_encryption_algorithm: string
  has_signature: boolean
  created_at: string
}

/*
  Componente principal del Dashboard.
  Aquí se gestiona:
  - Subida de ficheros
  - Descarga
  - Compartición
  - Verificación de firma digital
  - Ficheros que me han compartido
  - Ficheros que yo he compartido
*/
export default function Dashboard() {
  const navigate = useNavigate()

  // Estados del componente
  const [files, setFiles] = useState<FileItem[]>([])
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [uploading, setUploading] = useState(false)

  // Info del usuario autenticado
  const [username, setUsername] = useState<string>('')
  const [userId, setUserId] = useState<string | null>(null)

  // Estado para almacenar resultados de verificar firmas
  const [verifyResults, setVerifyResults] = useState<Record<string, string>>({})

  // Ficheros compartidos conmigo
  const [sharedFiles, setSharedFiles] = useState<SharedFileItem[]>([])

  // Ficheros que yo he compartido con otros
  const [sharedByMe, setSharedByMe] = useState<SharedByMeItem[]>([])

  /*
    useEffect: Cuando entras al Dashboard
    - Verifica si estás logueado (localStorage)
    - Ejecuta bootstrap:
        - Crea claves RSA si no existen
        - Carga tus ficheros
        - Carga compartidos contigo
        - Carga compartidos por ti
  */
  useEffect(() => {
    const storedUserId = localStorage.getItem(USER_STORAGE_KEY)
    const storedUsername = localStorage.getItem(USERNAME_STORAGE_KEY) || ''

    // Si no hay sesión, redirige a login
    if (!storedUserId) {
      navigate('/login')
      return
    }

    setUserId(storedUserId)
    setUsername(storedUsername)

    // Función que inicializa todo
    const bootstrap = async () => {
      setLoading(true)
      setError(null)

      try {
        // Verifica si existen claves públicas/privadas del usuario; si no, las crea
        await ensureKeys(storedUserId)

        // Carga todos los ficheros propios
        await loadFiles(storedUserId)

        // Carga archivos que otros han compartido contigo
        await loadSharedFiles(storedUserId)

        // Carga archivos que tú has compartido
        await loadSharedByMe(storedUserId)

      } catch (err) {
        const message = err instanceof Error ? err.message : 'No se pudieron cargar los ficheros'
        setError(message)
      } finally {
        setLoading(false)
      }
    }

    bootstrap()
  }, [navigate])

  /*
    ensureKeys:
    Comprueba si el backend tiene claves RSA generadas para este usuario.
    Si no las tiene → el backend las genera:
      - RSA pública
      - RSA privada cifrada con AES-GCM + PBKDF2
  */
  const ensureKeys = async (uid: string) => {
    const status = await apiGet('/keys/me', {
      headers: { 'X-User-Id': uid },
    })

    if (!status.has_keys) {
      // Genera claves
      await apiPost('/keys/me', {}, { headers: { 'X-User-Id': uid } })
    }
  }

  /*
    Cargar ficheros propios
  */
  const loadFiles = async (uid: string) => {
    const data = await apiGet('/files', { headers: { 'X-User-Id': uid } })
    setFiles(data)
  }

  /*
    Cargar ficheros compartidos contigo
  */
  const loadSharedFiles = async (uid: string) => {
    const data = await apiGet('/files/shared-with-me', { headers: { 'X-User-Id': uid } })
    setSharedFiles(data)
  }

  /*
    Cargar ficheros compartidos por mí
  */
  const loadSharedByMe = async (uid: string) => {
    const data = await apiGet('/files/shared-by-me', { headers: { 'X-User-Id': uid } })
    setSharedByMe(data)
  }

  /*
    handleUpload:
    - Sube un fichero al backend
    - Backend:
        - Cifra con AES-256-GCM
        - Envuelve la clave AES con RSA-OAEP
        - Firma (RSA-PSS) si procede
  */
  const handleUpload = async () => {
    if (!selectedFile || !userId) {
      setError('Selecciona un fichero antes de subirlo')
      return
    }

    setUploading(true)
    setError(null)
    setSuccess(null)

    try {
      const formData = new FormData()
      formData.append('uploaded_file', selectedFile)

      await apiPostForm('/files', formData, {
        headers: { 'X-User-Id': userId },
      })

      // Reiniciamos
      setSelectedFile(null)
      setVerifyResults({})

      // Recargar datos
      await loadFiles(userId)
      await loadSharedFiles(userId)
      await loadSharedByMe(userId)

      setSuccess('Fichero subido y cifrado correctamente.')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'No se pudo subir el fichero'
      setError(message)
      setSuccess(null)
    } finally {
      setUploading(false)
    }
  }

  /*
    handleDownload:
    Descarga un fichero propio.
    El backend:
      - Descifra la AES usando la clave privada RSA del usuario
      - Descifra con AES-GCM el contenido
      - Envía el fichero en claro
  */
  const handleDownload = async (file: FileItem) => {
    if (!userId) return

    try {
      const blob = await apiGetBlob(`/files/${file.id}/download`, {
        headers: { 'X-User-Id': userId },
      })

      // Descargar en navegador
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = file.filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)

    } catch (err) {
      const message = err instanceof Error ? err.message : 'No se pudo descargar el fichero'
      setError(message)
    }
  }

  /*
    handleShare:
    - Pide nombre de usuario destino
    - Backend envuelve la AES para ese destinatario usando su clave pública RSA
    - Se crea un registro en file_shares
  */
  const handleShare = async (file: FileItem) => {
    if (!userId) return

    const targetUsername = window.prompt('Introduce el usuario destino')
    if (!targetUsername) return

    try {
      setError(null)
      setSuccess(null)

      await apiPost(
        `/files/${file.id}/share`,
        { target_username: targetUsername },
        { headers: { 'X-User-Id': userId } }
      )

      await loadSharedFiles(userId)
      await loadSharedByMe(userId)

      setSuccess('Fichero compartido correctamente.')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'No se pudo compartir el fichero'
      setError(message)
      setSuccess(null)
    }
  }

  /*
    handleVerify:
    - Llama al backend: /files/:id/verify-signature
    El backend:
      - Carga el certificado X.509 del propietario
      - Extrae clave pública
      - Recalcula hash del archivo
      - Verifica firma digital RSA-PSS
  */
  const handleVerify = async (file: FileItem) => {
    if (!userId) return

    try {
      const result = await apiGet(`/files/${file.id}/verify-signature`, {
        headers: { 'X-User-Id': userId },
      })

      if (!result.signed) {
        setVerifyResults(prev => ({ ...prev, [file.id]: 'Sin firma' }))
        return
      }

      let statusText = result.valid ? 'Firma válida' : 'Firma NO válida'

      if (result.cert_revoked) {
        statusText = 'Certificado revocado: firma NO válida'
      }

      setVerifyResults(prev => ({
        ...prev,
        [file.id]: statusText,
      }))

    } catch (err) {
      const message = err instanceof Error ? err.message : 'No se pudo verificar la firma'
      setVerifyResults(prev => ({ ...prev, [file.id]: message }))
    }
  }

  /*
    handleDownloadShared:
    Descarga un fichero que otro usuario te ha compartido.
    El backend:
      - Descifra AES usando la copia envuelta para ti
      - Envía el fichero descifrado
  */
  const handleDownloadShared = async (item: SharedFileItem) => {
    if (!userId) return

    try {
      const blob = await apiGetBlob(`/files/shared/${item.share_id}/download`, {
        headers: { 'X-User-Id': userId },
      })

      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = item.filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)

    } catch (err) {
      const message = err instanceof Error ? err.message : 'No se pudo descargar el fichero compartido'
      setError(message)
    }
  }

  /*
    handleRevokeShare:
    - Revoca un acceso compartido previamente
    - El backend elimina file_shares correspondiente
  */
  const handleRevokeShare = async (item: SharedByMeItem) => {
    if (!userId) return

    const confirmMsg = window.confirm(
      `¿Seguro que quieres revocar el acceso a "${item.filename}" para ${item.recipient_username}?`,
    )
    if (!confirmMsg) return

    try {
      setError(null)

      const response = await fetch(`${API_BASE_URL}/files/shared/${item.share_id}`, {
        method: 'DELETE',
        headers: { 'X-User-Id': userId },
      })

      if (!response.ok) {
        const message = await response.text()
        throw new Error(message || 'No se pudo revocar el acceso')
      }

      await loadSharedByMe(userId)
      await loadSharedFiles(userId)

    } catch (err) {
      const message = err instanceof Error ? err.message : 'No se pudo revocar el acceso'
      setError(message)
    }
  }

  /*
    handleLogout:
    - Limpia localStorage
    - Redirige a login
  */
  const handleLogout = () => {
    localStorage.removeItem(USER_STORAGE_KEY)
    localStorage.removeItem(USERNAME_STORAGE_KEY)
    navigate('/login')
  }

  /*
    Renderizado de la UI
    Aquí solo mostramos la interfaz
  */
  return (
    <div className="min-h-screen bg-slate-100 px-4 py-8">
      <div className="max-w-6xl mx-auto space-y-6">
        
        {/* CABECERA */}
        <header className="flex items-center justify-between bg-white shadow p-4 rounded-md">
          <div>
            <h1 className="text-2xl font-semibold text-slate-900">Crypto Drive</h1>
            <p className="text-sm text-slate-600">Ficheros cifrados con AES-GCM y clave envuelta con RSA.</p>
          </div>

          <div className="flex items-center space-x-4">
            <Link
              to="/security"
              className="rounded-md border border-indigo-200 px-3 py-1 text-sm font-medium text-indigo-700 hover:bg-indigo-50"
            >
              Detalles de seguridad
            </Link>

            {/* Mostrar nombre de sesión */}
            {username && <span className="text-sm text-slate-700">Sesión: {username}</span>}

            <button
              onClick={handleLogout}
              className="rounded-md border border-slate-300 px-3 py-1 text-sm font-medium text-slate-700 hover:bg-slate-50"
            >
              Salir
            </button>
          </div>
        </header>

        {/* SUBIR FICHEROS */}
        <section className="bg-white shadow rounded-md p-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-lg font-semibold text-slate-900">Subir fichero</h2>
              <p className="text-sm text-slate-600">El backend cifrará y firmará (RSA-PSS) el contenido antes de almacenarlo.</p>

              {success && <p className="mt-2 text-sm text-emerald-700">{success}</p>}
            </div>

            <div className="flex items-center space-x-3">
              {/* Selector de archivo */}
              <input
                type="file"
                onChange={(e) => setSelectedFile(e.target.files ? e.target.files[0] : null)}
                className="text-sm"
              />

              <button
                onClick={handleUpload}
                disabled={uploading}
                className="rounded-md bg-indigo-600 px-4 py-2 text-white font-semibold hover:bg-indigo-700 disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {uploading ? 'Subiendo...' : 'Subir'}
              </button>
            </div>
          </div>

          {error && <p className="mt-3 text-sm text-red-600">{error}</p>}
        </section>

        {/* LISTADO DE FICHEROS PROPIOS */}
        <section className="bg-white shadow rounded-md p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-slate-900">Tus ficheros</h2>
              <p className="text-sm text-slate-600">
                Cifrados con AES-256-GCM, clave envuelta con RSA-OAEP y firma opcional.
              </p>
            </div>
            {loading && <span className="text-sm text-slate-500">Cargando...</span>}
          </div>

          {files.length === 0 ? (
            <p className="text-sm text-slate-600">Todavía no has subido ningún fichero.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Nombre</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Fecha</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Cifrado</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Clave envuelta</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Firma</th>
                    <th className="px-4 py-2" />
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-200">
                  {files.map((file) => (
                    <tr key={file.id}>
                      <td className="px-4 py-3 text-sm text-slate-800">{file.filename}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{new Date(file.created_at).toLocaleString()}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{file.encryption_algorithm}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{file.key_encryption_algorithm}</td>

                      {/* Estado de firma + resultado de verificación */}
                      <td className="px-4 py-3 text-sm text-slate-600">
                        {file.signature ? 'Firmado' : 'Sin firma'}
                        {verifyResults[file.id] && (
                          <div
                            className={`text-xs ${
                              verifyResults[file.id].includes('NO') ? 'text-red-600' : 'text-green-700'
                            }`}
                          >
                            {verifyResults[file.id]}
                          </div>
                        )}
                      </td>

                      {/* Botones de acciones */}
                      <td className="px-4 py-3 text-right space-x-2">
                        <button
                          onClick={() => handleDownload(file)}
                          className="rounded-md border border-indigo-200 px-3 py-1 text-sm font-medium text-indigo-700 hover:bg-indigo-50"
                        >
                          Descargar
                        </button>

                        <button
                          onClick={() => handleShare(file)}
                          className="rounded-md border border-amber-200 px-3 py-1 text-sm font-medium text-amber-700 hover:bg-amber-50"
                        >
                          Compartir
                        </button>

                        {file.signature && (
                          <button
                            onClick={() => handleVerify(file)}
                            className="rounded-md border border-emerald-200 px-3 py-1 text-sm font-medium text-emerald-700 hover:bg-emerald-50"
                          >
                            Verificar firma
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* FICHEROS COMPARTIDOS CONMIGO */}
        <section className="bg-white shadow rounded-md p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-slate-900">Ficheros compartidos contigo</h2>
              <p className="text-sm text-slate-600">Puedes descargar los ficheros que otros usuarios han compartido usando tu clave privada.</p>
            </div>
            {loading && <span className="text-sm text-slate-500">Cargando...</span>}
          </div>

          {sharedFiles.length === 0 ? (
            <p className="text-sm text-slate-600">Nadie te ha compartido ficheros todavía.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Nombre</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Propietario</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Fecha</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Cifrado</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Clave envuelta</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Firma</th>
                    <th className="px-4 py-2" />
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-200">
                  {sharedFiles.map((item) => (
                    <tr key={item.share_id}>
                      <td className="px-4 py-3 text-sm text-slate-800">{item.filename}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{item.owner_username}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{new Date(item.created_at).toLocaleString()}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{item.encryption_algorithm}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{item.key_encryption_algorithm}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{item.has_signature ? 'Firmado' : 'Sin firma'}</td>

                      <td className="px-4 py-3 text-right space-x-2">
                        <button
                          onClick={() => handleDownloadShared(item)}
                          className="rounded-md border border-indigo-200 px-3 py-1 text-sm font-medium text-indigo-700 hover:bg-indigo-50"
                        >
                          Descargar
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* FICHEROS QUE YO HE COMPARTIDO */}
        <section className="bg-white shadow rounded-md p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-slate-900">Ficheros que has compartido</h2>
              <p className="text-sm text-slate-600">Listado de accesos activos que has concedido a otros usuarios.</p>
            </div>
            {loading && <span className="text-sm text-slate-500">Cargando...</span>}
          </div>

          {sharedByMe.length === 0 ? (
            <p className="text-sm text-slate-600">No has compartido ningún fichero todavía.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Nombre</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Destinatario</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Fecha</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Cifrado</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Clave envuelta</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-slate-600">Firma</th>
                    <th className="px-4 py-2" />
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-200">
                  {sharedByMe.map((item) => (
                    <tr key={item.share_id}>
                      <td className="px-4 py-3 text-sm text-slate-800">{item.filename}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{item.recipient_username}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{new Date(item.created_at).toLocaleString()}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{item.encryption_algorithm}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{item.key_encryption_algorithm}</td>
                      <td className="px-4 py-3 text-sm text-slate-600">{item.has_signature ? 'Firmado' : 'Sin firma'}</td>

                      <td className="px-4 py-3 text-right space-x-2">
                        <button
                          onClick={() => handleRevokeShare(item)}
                          className="rounded-md border border-red-200 px-3 py-1 text-sm font-medium text-red-700 hover:bg-red-50"
                        >
                          Revocar acceso
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

      </div>
    </div>
  )
}

import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { API_BASE_URL, apiGet, apiGetBlob, apiPost, apiPostForm } from '../api/client'
import { USER_STORAGE_KEY, USERNAME_STORAGE_KEY } from './Login'

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

export default function Dashboard() {
  const navigate = useNavigate()
  const [files, setFiles] = useState<FileItem[]>([])
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [username, setUsername] = useState<string>('')
  const [userId, setUserId] = useState<string | null>(null)
  const [verifyResults, setVerifyResults] = useState<Record<string, string>>({})
  const [sharedFiles, setSharedFiles] = useState<SharedFileItem[]>([])
  const [sharedByMe, setSharedByMe] = useState<SharedByMeItem[]>([])

  useEffect(() => {
    const storedUserId = localStorage.getItem(USER_STORAGE_KEY)
    const storedUsername = localStorage.getItem(USERNAME_STORAGE_KEY) || ''
    if (!storedUserId) {
      navigate('/login')
      return
    }
    setUserId(storedUserId)
    setUsername(storedUsername)

    const bootstrap = async () => {
      setLoading(true)
      setError(null)
      try {
        await ensureKeys(storedUserId)
        await loadFiles(storedUserId)
        await loadSharedFiles(storedUserId)
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

  const ensureKeys = async (uid: string) => {
    const status = await apiGet('/keys/me', {
      headers: {
        'X-User-Id': uid,
      },
    })
    if (!status.has_keys) {
      await apiPost(
        '/keys/me',
        {},
        {
          headers: {
            'X-User-Id': uid,
          },
        },
      )
    }
  }

  const loadFiles = async (uid: string) => {
    const data = await apiGet('/files', {
      headers: {
        'X-User-Id': uid,
      },
    })
    setFiles(data)
  }

  const loadSharedFiles = async (uid: string) => {
    const data = await apiGet('/files/shared-with-me', {
      headers: {
        'X-User-Id': uid,
      },
    })
    setSharedFiles(data)
  }

  const loadSharedByMe = async (uid: string) => {
    const data = await apiGet('/files/shared-by-me', {
      headers: {
        'X-User-Id': uid,
      },
    })
    setSharedByMe(data)
  }

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
        headers: {
          'X-User-Id': userId,
        },
      })
      setSelectedFile(null)
      setVerifyResults({})
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

  const handleDownload = async (file: FileItem) => {
    if (!userId) return
    try {
      const blob = await apiGetBlob(`/files/${file.id}/download`, {
        headers: {
          'X-User-Id': userId,
        },
      })
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
        {
          headers: {
            'X-User-Id': userId,
          },
        },
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

  const handleVerify = async (file: FileItem) => {
    if (!userId) return
    try {
      const result = await apiGet(`/files/${file.id}/verify-signature`, {
        headers: {
          'X-User-Id': userId,
        },
      })
      if (!result.signed) {
        setVerifyResults((prev) => ({ ...prev, [file.id]: 'Sin firma' }))
        return
      }
      let statusText = result.valid ? 'Firma válida' : 'Firma NO válida'
      if (result.cert_revoked) {
        statusText = 'Certificado revocado: firma NO válida'
      }
      setVerifyResults((prev) => ({
        ...prev,
        [file.id]: statusText,
      }))
    } catch (err) {
      const message = err instanceof Error ? err.message : 'No se pudo verificar la firma'
      setVerifyResults((prev) => ({ ...prev, [file.id]: message }))
    }
  }

  const handleDownloadShared = async (item: SharedFileItem) => {
    if (!userId) return
    try {
      const blob = await apiGetBlob(`/files/shared/${item.share_id}/download`, {
        headers: {
          'X-User-Id': userId,
        },
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
        headers: {
          'X-User-Id': userId,
        },
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

  const handleLogout = () => {
    localStorage.removeItem(USER_STORAGE_KEY)
    localStorage.removeItem(USERNAME_STORAGE_KEY)
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-slate-100 px-4 py-8">
      <div className="max-w-6xl mx-auto space-y-6">
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
            {username && <span className="text-sm text-slate-700">Sesión: {username}</span>}
            <button
              onClick={handleLogout}
              className="rounded-md border border-slate-300 px-3 py-1 text-sm font-medium text-slate-700 hover:bg-slate-50"
            >
              Salir
            </button>
          </div>
        </header>

        <section className="bg-white shadow rounded-md p-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-lg font-semibold text-slate-900">Subir fichero</h2>
              <p className="text-sm text-slate-600">El backend cifrará y firmará (RSA-PSS) el contenido antes de almacenarlo.</p>
              {success && <p className="mt-2 text-sm text-emerald-700">{success}</p>}
            </div>
            <div className="flex items-center space-x-3">
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

        <section className="bg-white shadow rounded-md p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-slate-900">Tus ficheros</h2>
              <p className="text-sm text-slate-600">Cifrados con AES-256-GCM, clave envuelta con RSA-OAEP y firma opcional.</p>
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
                      <td className="px-4 py-3 text-sm text-slate-600">
                        {file.signature ? 'Firmado' : 'Sin firma'}
                        {verifyResults[file.id] && (
                          <div className={`text-xs ${verifyResults[file.id].includes('NO') ? 'text-red-600' : 'text-green-700'}`}>
                            {verifyResults[file.id]}
                          </div>
                        )}
                      </td>
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

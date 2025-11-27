import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiGet, apiPost } from '../api/client'
import { USER_STORAGE_KEY } from './Login'

interface CertResponse {
  user_cert_pem: string
  chain: string[]
  revoked?: boolean
}

export default function Security() {
  const navigate = useNavigate()
  const [userId, setUserId] = useState<string | null>(null)
  const [cert, setCert] = useState<CertResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    const uid = localStorage.getItem(USER_STORAGE_KEY)
    if (!uid) {
      navigate('/login')
      return
    }
    setUserId(uid)
    fetchCert(uid)
  }, [navigate])

  const fetchCert = async (uid: string) => {
    setLoading(true)
    setError(null)
    try {
      const data = await apiGet('/pki/cert/me', {
        headers: {
          'X-User-Id': uid,
        },
      })
      setCert(data)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'No se pudo obtener el certificado'
      if (message.toLowerCase().includes('not found')) {
        setMessage('Aún no tienes un certificado emitido.')
      } else {
        setError(message)
      }
      setCert(null)
    } finally {
      setLoading(false)
    }
  }

  const handleRequestCert = async () => {
    if (!userId) return
    setError(null)
    try {
      await apiPost(
        '/pki/cert/me',
        {},
        {
          headers: {
            'X-User-Id': userId,
          },
        },
      )
      await fetchCert(userId)
      setMessage('Certificado emitido correctamente.')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'No se pudo emitir el certificado'
      setError(message)
    }
  }

  const handleRevokeCert = async () => {
    if (!userId) return
    setError(null)
    const confirmMsg = window.confirm(
      '¿Seguro que quieres revocar tu certificado? Esta acción no se puede deshacer.',
    )
    if (!confirmMsg) return

    try {
      await apiPost(
        '/pki/cert/me/revoke',
        {},
        {
          headers: {
            'X-User-Id': userId,
          },
        },
      )
      await fetchCert(userId)
      setMessage('Certificado revocado.')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'No se pudo revocar el certificado'
      setError(message)
    }
  }

  const handleBootstrap = async () => {
    setError(null)
    try {
      await apiPost('/pki/bootstrap', {})
      if (userId) {
        await fetchCert(userId)
      }
      setMessage('PKI inicializada (Root + Issuing CA).')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'No se pudo inicializar la PKI'
      setError(message)
    }
  }

  const copyText = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setError(null)
      setMessage('Copiado al portapapeles')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'No se pudo copiar'
      setError(message)
    }
  }

  return (
    <div className="min-h-screen bg-slate-100 px-4 py-8">
      <div className="max-w-5xl mx-auto space-y-6">
        <header className="flex items-center justify-between bg-white shadow p-4 rounded-md">
          <div>
            <h1 className="text-2xl font-semibold text-slate-900">Detalles de seguridad</h1>
            <p className="text-sm text-slate-600">PKI (Root + Issuing) y certificados emitidos por usuario.</p>
          </div>
          <button
            onClick={() => navigate('/dashboard')}
            className="rounded-md border border-slate-300 px-3 py-1 text-sm font-medium text-slate-700 hover:bg-slate-50"
          >
            Volver al dashboard
          </button>
        </header>

        <section className="bg-white shadow rounded-md p-6 space-y-4">
          <div className="flex flex-wrap gap-3">
            <button
              onClick={handleBootstrap}
              className="rounded-md border border-indigo-200 px-3 py-2 text-sm font-medium text-indigo-700 hover:bg-indigo-50"
            >
              Inicializar PKI (Root + Issuing)
            </button>
            <button
              onClick={handleRequestCert}
              className="rounded-md border border-emerald-200 px-3 py-2 text-sm font-medium text-emerald-700 hover:bg-emerald-50"
            >
              Solicitar certificado
            </button>
            <button
              onClick={handleRevokeCert}
              disabled={!cert || cert.revoked}
              className="rounded-md border border-red-200 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-50 disabled:opacity-60 disabled:cursor-not-allowed"
            >
              Revocar mi certificado
            </button>
          </div>
          {loading && <p className="text-sm text-slate-600">Cargando...</p>}
          {error && <p className="text-sm text-red-600">{error}</p>}
          {message && <p className="text-sm text-emerald-700">{message}</p>}

          {cert ? (
            <div className="space-y-4">
              <div>
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-semibold text-slate-900">Certificado del usuario</h2>
                  <button
                    onClick={() => copyText(cert.user_cert_pem)}
                    className="text-sm text-indigo-700 hover:underline"
                  >
                    Copiar certificado
                  </button>
                </div>
                <pre className="mt-2 max-h-64 overflow-auto rounded-md bg-slate-900 p-4 text-xs text-slate-100 whitespace-pre-wrap">
{cert.user_cert_pem}
                </pre>
                {cert.revoked ? (
                  <p className="text-sm text-red-600 mt-2">Este certificado está revocado y ya no se considera de confianza.</p>
                ) : (
                  <p className="text-sm text-emerald-700 mt-2">Certificado activo.</p>
                )}
              </div>
              <div>
                <div className="flex items-center justify-between">
                  <h3 className="text-md font-semibold text-slate-900">Cadena de confianza (Root + Issuing)</h3>
                  <button
                    onClick={() => copyText(cert.chain.join('\n'))}
                    className="text-sm text-indigo-700 hover:underline"
                  >
                    Copiar cadena
                  </button>
                </div>
                <pre className="mt-2 max-h-64 overflow-auto rounded-md bg-slate-900 p-4 text-xs text-slate-100 whitespace-pre-wrap">
{cert.chain.join('\n\n')}
                </pre>
              </div>
            </div>
          ) : (
            !loading && <p className="text-sm text-slate-600">Aún no tienes un certificado emitido.</p>
          )}
        </section>
      </div>
    </div>
  )
}

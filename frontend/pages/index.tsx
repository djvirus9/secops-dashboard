import { useEffect, useState } from 'react'

export default function Dashboard() {
  const [healthStatus, setHealthStatus] = useState<string>('checking...')
  const [signalResponse, setSignalResponse] = useState<string>('')

  useEffect(() => {
    fetch('/api/health')
      .then((res) => res.json())
      .then((data) => setHealthStatus(data.status))
      .catch(() => setHealthStatus('error'))
  }, [])

  const sendTestSignal = async () => {
    try {
      const res = await fetch('/api/ingest/signal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'test',
          severity: 'low',
          message: 'Test signal from dashboard',
        }),
      })
      const data = await res.json()
      setSignalResponse(JSON.stringify(data, null, 2))
    } catch {
      setSignalResponse('Error sending signal')
    }
  }

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8">Dashboard</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-gray-400 text-sm mb-2">API Status</h3>
          <p className={`text-2xl font-bold ${healthStatus === 'ok' ? 'text-green-400' : 'text-red-400'}`}>
            {healthStatus}
          </p>
        </div>
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-gray-400 text-sm mb-2">Active Findings</h3>
          <p className="text-2xl font-bold text-yellow-400">24</p>
        </div>
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-gray-400 text-sm mb-2">Assets</h3>
          <p className="text-2xl font-bold text-blue-400">156</p>
        </div>
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-gray-400 text-sm mb-2">Risk Score</h3>
          <p className="text-2xl font-bold text-orange-400">72</p>
        </div>
      </div>

      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-xl font-bold mb-4">Test Signal Ingestion</h2>
        <button
          onClick={sendTestSignal}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors"
        >
          Send Test Signal
        </button>
        {signalResponse && (
          <pre className="mt-4 bg-gray-900 p-4 rounded-lg text-sm text-green-400 overflow-auto">
            {signalResponse}
          </pre>
        )}
      </div>
    </div>
  )
}

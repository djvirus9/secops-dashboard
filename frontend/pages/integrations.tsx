import { useState } from 'react'

export default function Integrations() {
  const [integrations] = useState([
    { id: 1, name: 'AWS CloudTrail', status: 'connected', lastSync: '2 mins ago' },
    { id: 2, name: 'Azure Sentinel', status: 'connected', lastSync: '5 mins ago' },
    { id: 3, name: 'Splunk', status: 'disconnected', lastSync: 'Never' },
    { id: 4, name: 'CrowdStrike', status: 'connected', lastSync: '1 min ago' },
    { id: 5, name: 'Tenable', status: 'pending', lastSync: 'Never' },
  ])

  const statusColors: Record<string, string> = {
    connected: 'bg-green-500',
    disconnected: 'bg-red-500',
    pending: 'bg-yellow-500',
  }

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8">Integrations</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {integrations.map((integration) => (
          <div key={integration.id} className="bg-gray-800 rounded-lg p-6">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold">{integration.name}</h3>
              <span className={`px-2 py-1 rounded text-xs text-white ${statusColors[integration.status]}`}>
                {integration.status}
              </span>
            </div>
            <p className="text-sm text-gray-400">Last sync: {integration.lastSync}</p>
            <button
              className={`mt-4 w-full py-2 rounded-lg transition-colors ${
                integration.status === 'connected'
                  ? 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                  : 'bg-blue-600 hover:bg-blue-700 text-white'
              }`}
            >
              {integration.status === 'connected' ? 'Disconnect' : 'Connect'}
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

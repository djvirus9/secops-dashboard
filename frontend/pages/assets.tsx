export default function Assets() {
  const assets = [
    { id: 1, name: 'web-server-01', type: 'Server', status: 'healthy', ip: '192.168.1.10' },
    { id: 2, name: 'db-primary', type: 'Database', status: 'healthy', ip: '192.168.1.20' },
    { id: 3, name: 'api-gateway', type: 'Network', status: 'warning', ip: '192.168.1.1' },
    { id: 4, name: 'storage-node-01', type: 'Storage', status: 'healthy', ip: '192.168.1.30' },
    { id: 5, name: 'workstation-42', type: 'Endpoint', status: 'critical', ip: '192.168.2.42' },
  ]

  const statusColors: Record<string, string> = {
    healthy: 'text-green-400',
    warning: 'text-yellow-400',
    critical: 'text-red-400',
  }

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8">Assets</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {assets.map((asset) => (
          <div key={asset.id} className="bg-gray-800 rounded-lg p-6">
            <div className="flex justify-between items-start mb-4">
              <h3 className="text-lg font-semibold">{asset.name}</h3>
              <span className={`text-sm ${statusColors[asset.status]}`}>{asset.status}</span>
            </div>
            <div className="space-y-2 text-sm text-gray-400">
              <p>Type: {asset.type}</p>
              <p>IP: {asset.ip}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

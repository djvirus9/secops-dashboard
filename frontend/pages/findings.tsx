export default function Findings() {
  const findings = [
    { id: 1, title: 'Unauthorized Access Attempt', severity: 'high', status: 'open', date: '2026-01-18' },
    { id: 2, title: 'Suspicious Network Traffic', severity: 'medium', status: 'investigating', date: '2026-01-17' },
    { id: 3, title: 'Failed Login Attempts', severity: 'low', status: 'resolved', date: '2026-01-16' },
    { id: 4, title: 'Malware Detection', severity: 'critical', status: 'open', date: '2026-01-18' },
    { id: 5, title: 'Configuration Drift', severity: 'medium', status: 'open', date: '2026-01-15' },
  ]

  const severityColors: Record<string, string> = {
    critical: 'bg-red-600',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-blue-500',
  }

  const statusColors: Record<string, string> = {
    open: 'text-red-400',
    investigating: 'text-yellow-400',
    resolved: 'text-green-400',
  }

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8">Findings</h1>

      <div className="bg-gray-800 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-700">
            <tr>
              <th className="text-left p-4">Title</th>
              <th className="text-left p-4">Severity</th>
              <th className="text-left p-4">Status</th>
              <th className="text-left p-4">Date</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <tr key={finding.id} className="border-t border-gray-700 hover:bg-gray-750">
                <td className="p-4">{finding.title}</td>
                <td className="p-4">
                  <span className={`px-2 py-1 rounded text-xs text-white ${severityColors[finding.severity]}`}>
                    {finding.severity}
                  </span>
                </td>
                <td className={`p-4 ${statusColors[finding.status]}`}>{finding.status}</td>
                <td className="p-4 text-gray-400">{finding.date}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

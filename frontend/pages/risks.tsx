export default function Risks() {
  const risks = [
    { id: 1, name: 'Data Breach', likelihood: 'medium', impact: 'high', score: 85 },
    { id: 2, name: 'DDoS Attack', likelihood: 'high', impact: 'medium', score: 72 },
    { id: 3, name: 'Insider Threat', likelihood: 'low', impact: 'high', score: 65 },
    { id: 4, name: 'Ransomware', likelihood: 'medium', impact: 'critical', score: 90 },
    { id: 5, name: 'Phishing', likelihood: 'high', impact: 'medium', score: 68 },
  ]

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'bg-red-500'
    if (score >= 60) return 'bg-orange-500'
    if (score >= 40) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8">Risk Assessment</h1>

      <div className="space-y-4">
        {risks.map((risk) => (
          <div key={risk.id} className="bg-gray-800 rounded-lg p-6">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold">{risk.name}</h3>
              <div className="flex items-center gap-4">
                <span className="text-sm text-gray-400">
                  Likelihood: <span className="text-white">{risk.likelihood}</span>
                </span>
                <span className="text-sm text-gray-400">
                  Impact: <span className="text-white">{risk.impact}</span>
                </span>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex-1 bg-gray-700 rounded-full h-4 overflow-hidden">
                <div
                  className={`h-full ${getScoreColor(risk.score)} transition-all`}
                  style={{ width: `${risk.score}%` }}
                />
              </div>
              <span className="text-lg font-bold w-12">{risk.score}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

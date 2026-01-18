import '@/styles/globals.css'
import type { AppProps } from 'next/app'
import Link from 'next/link'
import { useRouter } from 'next/router'

const navItems = [
  { href: '/', label: 'Dashboard' },
  { href: '/findings', label: 'Findings' },
  { href: '/assets', label: 'Assets' },
  { href: '/risks', label: 'Risks' },
  { href: '/integrations', label: 'Integrations' },
]

export default function App({ Component, pageProps }: AppProps) {
  const router = useRouter()

  return (
    <div className="min-h-screen flex">
      <nav className="w-64 bg-gray-800 p-4 flex flex-col">
        <h1 className="text-xl font-bold text-blue-400 mb-8">SecOps Dashboard</h1>
        <ul className="space-y-2">
          {navItems.map((item) => (
            <li key={item.href}>
              <Link
                href={item.href}
                className={`block px-4 py-2 rounded-lg transition-colors ${
                  router.pathname === item.href
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-300 hover:bg-gray-700'
                }`}
              >
                {item.label}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
      <main className="flex-1 p-8">
        <Component {...pageProps} />
      </main>
    </div>
  )
}

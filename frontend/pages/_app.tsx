import type { AppProps } from "next/app";
import Link from "next/link";
import "../styles/globals.css";

const nav = [
  { href: "/", label: "Dashboard" },
  { href: "/findings", label: "Findings" },
  { href: "/assets", label: "Assets" },
  { href: "/risks", label: "Risks" },
  { href: "/integrations", label: "Integrations" },
];

export default function App({ Component, pageProps, router }: AppProps) {
  return (
    <div className="min-h-screen bg-gray-50">
      <header className="border-b bg-white">
        <div className="mx-auto max-w-6xl px-6 py-4 flex items-center justify-between">
          <div className="font-semibold">SecOps Dashboard</div>
          <nav className="flex gap-2">
            {nav.map((n) => {
              const active = router.pathname === n.href;
              return (
                <Link
                  key={n.href}
                  href={n.href}
                  className={
                    "rounded-md px-3 py-1 text-sm border " +
                    (active ? "bg-black text-white border-black" : "bg-white text-gray-700 hover:bg-gray-100")
                  }
                >
                  {n.label}
                </Link>
              );
            })}
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-8">
        <Component {...pageProps} />
      </main>
    </div>
  );
}

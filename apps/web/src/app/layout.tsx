import type { Metadata } from 'next'
import { RealtimeProvider } from '@/components/RealtimeProvider'
import './globals.css'

export const metadata: Metadata = {
  title: 'HalimiSOC',
  description: 'Lightweight, AI-assisted security operations console',
  // The console is not a public site and must not be indexed.
  robots: { index: false, follow: false },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {/* The realtime provider wraps everything so the connection is opened
            once for the whole app rather than once per page. */}
        <RealtimeProvider>{children}</RealtimeProvider>
      </body>
    </html>
  )
}

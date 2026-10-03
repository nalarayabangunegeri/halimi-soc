import '@testing-library/jest-dom/vitest'
import { vi } from 'vitest'

// `server-only` is a marker module whose body throws on import. Next resolves it to
// an empty module under the `react-server` condition. Vitest does not apply that
// condition, so the marker is stubbed here for tests that exercise server-module
// logic directly.
//
// The real marker stays in place for the application build, which is where it does
// its job: preventing a server module from being pulled into a client bundle.
vi.mock('server-only', () => ({}))

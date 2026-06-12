import { describe, it, expect } from 'vitest'
import { fetchWithMetrics } from './test-utils.js'

describe('CORS validation', () => {
  it('should reject requests from disallowed origins', async () => {
    const response = await fetchWithMetrics('http://localhost/health', {
      headers: {
        Origin: 'https://malicious-site.com'
      }
    })

    expect(response.status).toBe(403)
    const text = await response.text()
    expect(text).toContain('Forbidden')
  })

  it('should include CORS headers on disallowed-origin rejections so clients can read the error', async () => {
    const response = await fetchWithMetrics('http://localhost/health', {
      headers: {
        Origin: 'https://malicious-site.com'
      }
    })

    expect(response.status).toBe(403)
    // The rejected origin is echoed so the calling page can read the 403 body
    // instead of seeing a generic CORS failure. This grants nothing: the body
    // is a static string and every request re-validates the origin.
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://malicious-site.com')
  })

  it('should include Vary: Origin so caches never serve one origin\'s CORS headers to another', async () => {
    const allowed = await fetchWithMetrics('http://localhost/health', {
      headers: { Origin: 'http://localhost:5173' }
    })
    expect(allowed.headers.get('Vary')).toBe('Origin')

    const rejected = await fetchWithMetrics('http://localhost/health', {
      headers: { Origin: 'https://malicious-site.com' }
    })
    expect(rejected.headers.get('Vary')).toBe('Origin')
  })

  it('should allow requests from allowed origins', async () => {
    const response = await fetchWithMetrics('http://localhost/health', {
      headers: {
        Origin: 'http://localhost:5173'
      }
    })

    expect(response.status).toBe(200)
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('http://localhost:5173')
  })

  it('should handle CORS preflight requests', async () => {
    const response = await fetchWithMetrics('http://localhost/proxy/getAccessToken', {
      method: 'OPTIONS',
      headers: {
        Origin: 'http://localhost:5173',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type'
      }
    })

    expect(response.status).toBe(204)
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('http://localhost:5173')
    expect(response.headers.get('Access-Control-Allow-Methods')).toContain('POST')
    expect(response.headers.get('Access-Control-Allow-Credentials')).toBe('true')
  })

  it('should allow requests without origin header', async () => {
    const response = await fetchWithMetrics('http://localhost/health')

    expect(response.status).toBe(200)
  })
})

describe('Health endpoint', () => {
  it('should return ok status', async () => {
    const response = await fetchWithMetrics('http://localhost/health', {
      headers: {
        Origin: 'http://localhost:5173'
      }
    })

    expect(response.status).toBe(200)
    const data = await response.json()
    expect(data.status).toBe('ok')
  })
})

describe('404 handling', () => {
  it('should return 404 for unknown routes', async () => {
    const response = await fetchWithMetrics('http://localhost/unknown-route', {
      headers: {
        Origin: 'http://localhost:5173'
      }
    })

    expect(response.status).toBe(404)
  })
})

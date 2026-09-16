import { describe, it, expect, beforeEach, vi } from 'vitest'
import { demoStore, authStore } from '../api'

describe('demoStore', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('defaults to disabled', () => {
    expect(demoStore.enabled).toBe(false)
  })

  it('can be enabled', () => {
    demoStore.enabled = true
    expect(demoStore.enabled).toBe(true)
    expect(localStorage.getItem('baraq-demo-mode')).toBe('1')
  })

  it('can be disabled', () => {
    demoStore.enabled = true
    demoStore.enabled = false
    expect(demoStore.enabled).toBe(false)
    expect(localStorage.getItem('baraq-demo-mode')).toBeNull()
  })
})

describe('authStore', () => {
  it('starts with no token', () => {
    expect(authStore.token).toBeNull()
  })

  it('can set and get token', () => {
    authStore.set('test-token-123')
    expect(authStore.token).toBe('test-token-123')
  })

  it('clears token with null', () => {
    authStore.set('token')
    authStore.set(null)
    expect(authStore.token).toBeNull()
  })
})

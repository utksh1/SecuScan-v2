/// <reference types="vitest/globals" />
import '@testing-library/jest-dom/vitest'

// Node 25+ exposes `localStorage` only when `--localstorage-file` is set.
// jsdom tests need a real in-memory Storage regardless.
const store = new Map<string, string>()
const memory: Storage = {
  get length() {
    return store.size
  },
  clear() {
    store.clear()
  },
  getItem(key) {
    return store.has(key) ? store.get(key)! : null
  },
  key(index) {
    return [...store.keys()][index] ?? null
  },
  removeItem(key) {
    store.delete(key)
  },
  setItem(key, value) {
    store.set(key, String(value))
  },
}
Object.defineProperty(globalThis, 'localStorage', {
  value: memory,
  configurable: true,
})

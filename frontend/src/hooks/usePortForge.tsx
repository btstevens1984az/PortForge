import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { PORTS, type PortEntry } from '../data/ports.ts'
import {
  createId,
  detectConflicts,
  type FirewallRule,
  type RuleConflict,
  suggestSafeRule,
} from '../lib/rules.ts'

const STORAGE_KEY = 'portforge-rules-v1'

interface PortForgeContextValue {
  ports: PortEntry[]
  rules: FirewallRule[]
  conflicts: RuleConflict[]
  addRule: (rule: Omit<FirewallRule, 'id' | 'createdAt'>) => void
  updateRule: (id: string, patch: Partial<FirewallRule>) => void
  removeRule: (id: string) => void
  clearRules: () => void
  forgeFromPort: (port: PortEntry) => void
  seedDemo: () => void
}

const PortForgeContext = createContext<PortForgeContextValue | null>(null)

function loadRules(): FirewallRule[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    return JSON.parse(raw) as FirewallRule[]
  } catch {
    return []
  }
}

export function PortForgeProvider({ children }: { children: ReactNode }) {
  const [rules, setRules] = useState<FirewallRule[]>(() =>
    typeof window === 'undefined' ? [] : loadRules(),
  )

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(rules))
  }, [rules])

  const conflicts = useMemo(() => detectConflicts(rules), [rules])

  const addRule = useCallback((rule: Omit<FirewallRule, 'id' | 'createdAt'>) => {
    setRules((prev) => [
      ...prev,
      { ...rule, id: createId(), createdAt: new Date().toISOString() },
    ])
  }, [])

  const updateRule = useCallback((id: string, patch: Partial<FirewallRule>) => {
    setRules((prev) => prev.map((r) => (r.id === id ? { ...r, ...patch } : r)))
  }, [])

  const removeRule = useCallback((id: string) => {
    setRules((prev) => prev.filter((r) => r.id !== id))
  }, [])

  const clearRules = useCallback(() => setRules([]), [])

  const forgeFromPort = useCallback(
    (port: PortEntry) => {
      const suggestion = suggestSafeRule(port)
      addRule({
        name: suggestion.name || port.service,
        action: suggestion.action || 'allow',
        direction: suggestion.direction || 'inbound',
        protocol: (port.proto === 'TCP/UDP' ? 'TCP/UDP' : port.proto) as FirewallRule['protocol'],
        port: String(port.port),
        source: suggestion.source || 'any',
        destination: suggestion.destination || 'any',
        notes: suggestion.notes || port.guidance,
      })
    },
    [addRule],
  )

  const seedDemo = useCallback(() => {
    setRules([
      {
        id: createId(),
        name: 'Corporate web inbound',
        action: 'allow',
        direction: 'inbound',
        protocol: 'TCP',
        port: '443',
        source: 'any',
        destination: 'web-vip',
        notes: 'Public HTTPS to load balancer',
        createdAt: new Date().toISOString(),
      },
      {
        id: createId(),
        name: 'Block cleartext HTTP',
        action: 'deny',
        direction: 'inbound',
        protocol: 'TCP',
        port: '80',
        source: 'any',
        destination: 'web-vip',
        notes: 'Except ACME handled upstream',
        createdAt: new Date().toISOString(),
      },
      {
        id: createId(),
        name: 'Jump to RDP brokers',
        action: 'allow',
        direction: 'inbound',
        protocol: 'TCP',
        port: '3389',
        source: 'vpn-pool',
        destination: 'rdp-broker',
        notes: 'NLA + MFA gateway required',
        createdAt: new Date().toISOString(),
      },
      {
        id: createId(),
        name: 'Dangerous wide RDP',
        action: 'allow',
        direction: 'inbound',
        protocol: 'TCP',
        port: '3389',
        source: 'any',
        destination: 'any',
        notes: 'Demo conflict — do not implement',
        createdAt: new Date().toISOString(),
      },
      {
        id: createId(),
        name: 'HL7 interface VPN',
        action: 'allow',
        direction: 'inbound',
        protocol: 'TCP',
        port: '2575',
        source: 'partner-vpn',
        destination: 'hl7-engine',
        notes: 'PHI path — TLS wrapper + audit',
        createdAt: new Date().toISOString(),
      },
    ])
  }, [])

  const value = useMemo(
    () => ({
      ports: PORTS,
      rules,
      conflicts,
      addRule,
      updateRule,
      removeRule,
      clearRules,
      forgeFromPort,
      seedDemo,
    }),
    [rules, conflicts, addRule, updateRule, removeRule, clearRules, forgeFromPort, seedDemo],
  )

  return <PortForgeContext.Provider value={value}>{children}</PortForgeContext.Provider>
}

export function usePortForge() {
  const ctx = useContext(PortForgeContext)
  if (!ctx) throw new Error('usePortForge must be used within PortForgeProvider')
  return ctx
}

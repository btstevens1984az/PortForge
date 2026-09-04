export type RuleAction = 'allow' | 'deny' | 'reject'
export type RuleDirection = 'inbound' | 'outbound' | 'bidirectional'

export interface FirewallRule {
  id: string
  name: string
  action: RuleAction
  direction: RuleDirection
  protocol: 'TCP' | 'UDP' | 'TCP/UDP' | 'ANY'
  port: string
  source: string
  destination: string
  notes: string
  createdAt: string
  riskOverride?: 'low' | 'medium' | 'high' | 'critical'
}

export type ConflictSeverity = 'info' | 'warning' | 'critical'

export interface RuleConflict {
  id: string
  severity: ConflictSeverity
  type: 'duplicate' | 'shadow' | 'contradiction' | 'overlap' | 'risky'
  title: string
  detail: string
  ruleIds: string[]
}

function parsePortToken(token: string): number[] {
  const t = token.trim().toLowerCase()
  if (!t || t === 'any' || t === '*') return [-1]
  if (t.includes('-')) {
    const [a, b] = t.split('-').map((x) => Number(x.trim()))
    if (!Number.isFinite(a) || !Number.isFinite(b) || a > b || a < 0 || b > 65535) return []
    const out: number[] = []
    const max = Math.min(b, a + 512)
    for (let i = a; i <= max; i++) out.push(i)
    return out
  }
  if (t.includes(',')) {
    return t.split(',').flatMap((p) => parsePortToken(p))
  }
  const n = Number(t)
  if (!Number.isFinite(n) || n < 0 || n > 65535) return []
  return [n]
}

function portsOverlap(a: string, b: string): boolean {
  const pa = parsePortToken(a)
  const pb = parsePortToken(b)
  if (pa.includes(-1) || pb.includes(-1)) return true
  const setB = new Set(pb)
  return pa.some((p) => setB.has(p))
}

function protoCompatible(a: FirewallRule['protocol'], b: FirewallRule['protocol']): boolean {
  if (a === 'ANY' || b === 'ANY') return true
  if (a === 'TCP/UDP' || b === 'TCP/UDP') return true
  return a === b
}

function endpointLooseMatch(a: string, b: string): boolean {
  const na = a.trim().toLowerCase() || 'any'
  const nb = b.trim().toLowerCase() || 'any'
  if (na === 'any' || nb === 'any' || na === '*' || nb === '*') return true
  return na === nb
}

const RISKY_PORTS = new Set([23, 3389, 445, 135, 139, 5900, 2375, 6379, 9200, 27017, 11211, 10000])

export function detectConflicts(rules: FirewallRule[]): RuleConflict[] {
  const conflicts: RuleConflict[] = []

  rules.forEach((rule, i) => {
    const ports = parsePortToken(rule.port)
    const hitsRisky = ports.some((p) => RISKY_PORTS.has(p)) || ports.includes(-1)
    if (rule.action === 'allow' && hitsRisky) {
      const openWide =
        (!rule.source || rule.source.toLowerCase() === 'any') ||
        (!rule.destination || rule.destination.toLowerCase() === 'any')
      if (openWide) {
        conflicts.push({
          id: `risky-${rule.id}`,
          severity: 'critical',
          type: 'risky',
          title: `Wide allow on sensitive port(s)`,
          detail: `Rule "${rule.name}" allows ${rule.port}/${rule.protocol} with a broad source or destination. Prefer VPN, jump hosts, or explicit CIDRs.`,
          ruleIds: [rule.id],
        })
      }
    }

    for (let j = i + 1; j < rules.length; j++) {
      const other = rules[j]
      if (!protoCompatible(rule.protocol, other.protocol)) continue
      if (!portsOverlap(rule.port, other.port)) continue
      if (!endpointLooseMatch(rule.source, other.source)) continue
      if (!endpointLooseMatch(rule.destination, other.destination)) continue

      if (rule.action === other.action && rule.direction === other.direction) {
        conflicts.push({
          id: `dup-${rule.id}-${other.id}`,
          severity: 'info',
          type: 'duplicate',
          title: 'Possible duplicate rules',
          detail: `"${rule.name}" and "${other.name}" appear to cover the same traffic with the same action.`,
          ruleIds: [rule.id, other.id],
        })
      } else if (rule.action !== other.action) {
        conflicts.push({
          id: `contra-${rule.id}-${other.id}`,
          severity: 'critical',
          type: 'contradiction',
          title: 'Contradictory actions',
          detail: `"${rule.name}" (${rule.action}) conflicts with "${other.name}" (${other.action}) for overlapping traffic. Order/priority will decide — document intent.`,
          ruleIds: [rule.id, other.id],
        })
      } else {
        conflicts.push({
          id: `overlap-${rule.id}-${other.id}`,
          severity: 'warning',
          type: 'overlap',
          title: 'Overlapping coverage',
          detail: `"${rule.name}" and "${other.name}" overlap on port/protocol/endpoints. Review for shadowing.`,
          ruleIds: [rule.id, other.id],
        })
      }

      const aAnySrc = !rule.source || rule.source.toLowerCase() === 'any'
      const bSpecificSrc = other.source && other.source.toLowerCase() !== 'any'
      if (aAnySrc && bSpecificSrc && rule.action === 'allow' && i < j) {
        conflicts.push({
          id: `shadow-${rule.id}-${other.id}`,
          severity: 'warning',
          type: 'shadow',
          title: 'Broader rule may shadow',
          detail: `"${rule.name}" (any source) may shadow the more specific "${other.name}" depending on evaluation order.`,
          ruleIds: [rule.id, other.id],
        })
      }
    }
  })

  return conflicts
}

export function createId(): string {
  return `r_${Math.random().toString(36).slice(2, 10)}_${Date.now().toString(36)}`
}

export function suggestSafeRule(input: {
  port: number
  service: string
  risk: string
  guidance: string
}): Partial<FirewallRule> {
  const highRisk = input.risk === 'critical' || input.risk === 'high'
  return {
    name: `${input.service} ${highRisk ? 'restricted' : 'standard'}`,
    action: 'allow',
    direction: 'inbound',
    protocol: 'TCP',
    port: String(input.port),
    source: highRisk ? 'vpn-pool / jump-host' : 'app-tier',
    destination: highRisk ? `${input.service.toLowerCase()}-hosts` : 'service-vip',
    notes: `Safe baseline: ${input.guidance}`,
  }
}

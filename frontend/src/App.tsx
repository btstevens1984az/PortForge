import { AnimatePresence, motion } from 'framer-motion'
import {
  AlertTriangle,
  Anvil,
  BookOpen,
  CheckCircle2,
  Copy,
  Download,
  Flame,
  Hammer,
  Search,
  Shield,
  Sparkles,
  Trash2,
  X,
} from 'lucide-react'
import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { CATEGORIES, RISK_ORDER, type PortCategory, type PortEntry, type RiskLevel } from './data/ports.ts'
import { PortForgeProvider, usePortForge } from './hooks/usePortForge.tsx'
import { exportAsa, exportCsv, exportIptables, exportMarkdown } from './lib/export.ts'
import type { FirewallRule, RuleAction, RuleDirection } from './lib/rules.ts'
import clsx from 'clsx'

type Tab = 'encyclopedia' | 'forge' | 'conflicts' | 'export'

function riskClass(risk: RiskLevel) {
  return {
    critical: 'risk-critical',
    high: 'risk-high',
    medium: 'risk-medium',
    low: 'risk-low',
  }[risk]
}

function AppShell() {
  const [tab, setTab] = useState<Tab>('encyclopedia')
  const { rules, conflicts, seedDemo } = usePortForge()
  const criticalCount = conflicts.filter((c) => c.severity === 'critical').length

  return (
    <div className="app-shell">
      <div className="forge-glow" aria-hidden />
      <div className="grid-overlay" aria-hidden />

      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <Anvil size={22} strokeWidth={2.2} />
          </div>
          <div>
            <h1>PortForge</h1>
            <p>Interactive port encyclopedia · firewall documentation · safe rule generator</p>
          </div>
        </div>
        <div className="top-stats">
          <div className="stat">
            <span className="stat-label">Rules</span>
            <strong>{rules.length}</strong>
          </div>
          <div className="stat">
            <span className="stat-label">Conflicts</span>
            <strong className={criticalCount ? 'text-ember' : ''}>{conflicts.length}</strong>
          </div>
          <button type="button" className="btn btn-ghost" onClick={seedDemo}>
            <Sparkles size={16} /> Load demo
          </button>
        </div>
      </header>

      <nav className="tabs" aria-label="Primary">
        {(
          [
            ['encyclopedia', BookOpen, 'Encyclopedia'],
            ['forge', Hammer, 'Rule Forge'],
            ['conflicts', Shield, 'Conflicts'],
            ['export', Download, 'Export'],
          ] as const
        ).map(([id, Icon, label]) => (
          <button
            key={id}
            type="button"
            className={clsx('tab', tab === id && 'active')}
            onClick={() => setTab(id)}
          >
            <Icon size={16} />
            {label}
            {id === 'conflicts' && conflicts.length > 0 && (
              <span className="badge">{conflicts.length}</span>
            )}
          </button>
        ))}
      </nav>

      <main className="main-stage">
        <AnimatePresence mode="wait">
          <motion.div
            key={tab}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.22 }}
          >
            {tab === 'encyclopedia' && <Encyclopedia onForge={() => setTab('forge')} />}
            {tab === 'forge' && <RuleForge />}
            {tab === 'conflicts' && <ConflictsPanel />}
            {tab === 'export' && <ExportPanel />}
          </motion.div>
        </AnimatePresence>
      </main>

      <footer className="footer">
        <Flame size={14} className="text-ember" />
        <span>PortForge — forge safer firewall docs before the change window.</span>
      </footer>
    </div>
  )
}

function Encyclopedia({ onForge }: { onForge: () => void }) {
  const { ports, forgeFromPort } = usePortForge()
  const [q, setQ] = useState('')
  const [category, setCategory] = useState<PortCategory | 'all'>('all')
  const [risk, setRisk] = useState<RiskLevel | 'all'>('all')
  const [selected, setSelected] = useState<PortEntry | null>(null)

  const filtered = useMemo(() => {
    const query = q.trim().toLowerCase()
    return ports
      .filter((p) => (category === 'all' ? true : p.category === category))
      .filter((p) => (risk === 'all' ? true : p.risk === risk))
      .filter((p) => {
        if (!query) return true
        const blob = [
          p.port,
          p.service,
          p.note,
          p.guidance,
          p.category,
          p.risk,
          ...(p.aliases || []),
        ]
          .join(' ')
          .toLowerCase()
        return blob.includes(query)
      })
      .sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk] || a.port - b.port)
  }, [ports, q, category, risk])

  return (
    <div className="panel-grid encyclopedia">
      <section className="panel">
        <div className="panel-head">
          <h2>Port encyclopedia</h2>
          <span className="muted">{filtered.length} services</span>
        </div>

        <div className="search-row">
          <div className="search-box">
            <Search size={16} />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search port, service, HL7, RDP, risk…"
              autoFocus
            />
          </div>
        </div>

        <div className="chip-row">
          {CATEGORIES.map((c) => (
            <button
              key={c.id}
              type="button"
              className={clsx('chip', category === c.id && 'active')}
              onClick={() => setCategory(c.id)}
            >
              {c.label}
            </button>
          ))}
        </div>

        <div className="chip-row risk-chips">
          {(['all', 'critical', 'high', 'medium', 'low'] as const).map((r) => (
            <button
              key={r}
              type="button"
              className={clsx('chip', risk === r && 'active', r !== 'all' && riskClass(r))}
              onClick={() => setRisk(r)}
            >
              {r}
            </button>
          ))}
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Port</th>
                <th>Proto</th>
                <th>Service</th>
                <th>Risk</th>
                <th>Category</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((p) => (
                <tr
                  key={`${p.port}-${p.service}`}
                  className={clsx(selected?.port === p.port && selected.service === p.service && 'selected')}
                  onClick={() => setSelected(p)}
                >
                  <td className="mono">{p.port}</td>
                  <td>{p.proto}</td>
                  <td>{p.service}</td>
                  <td>
                    <span className={clsx('pill', riskClass(p.risk))}>{p.risk}</span>
                  </td>
                  <td className="muted">{p.category}</td>
                  <td className="note-cell">{p.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <aside className="panel detail-panel">
        {selected ? (
          <>
            <div className="panel-head">
              <h2>
                {selected.service} <span className="mono muted">:{selected.port}</span>
              </h2>
              <span className={clsx('pill', riskClass(selected.risk))}>{selected.risk}</span>
            </div>
            <dl className="detail-list">
              <div>
                <dt>Protocol</dt>
                <dd>{selected.proto}</dd>
              </div>
              <div>
                <dt>Category</dt>
                <dd>{selected.category}</dd>
              </div>
              <div>
                <dt>Summary</dt>
                <dd>{selected.note}</dd>
              </div>
              <div>
                <dt>Safe guidance</dt>
                <dd>{selected.guidance}</dd>
              </div>
              {selected.aliases && selected.aliases.length > 0 && (
                <div>
                  <dt>Aliases</dt>
                  <dd>{selected.aliases.join(', ')}</dd>
                </div>
              )}
              {selected.related && selected.related.length > 0 && (
                <div>
                  <dt>Related ports</dt>
                  <dd className="mono">{selected.related.join(', ')}</dd>
                </div>
              )}
            </dl>
            <div className="action-row">
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => {
                  forgeFromPort(selected)
                  onForge()
                }}
              >
                <Hammer size={16} /> Forge safe rule
              </button>
            </div>
          </>
        ) : (
          <div className="empty">
            <BookOpen size={28} />
            <p>Select a port to inspect risk, guidance, and forge a baseline rule.</p>
          </div>
        )}
      </aside>
    </div>
  )
}

function RuleForge() {
  const { rules, addRule, removeRule, clearRules } = usePortForge()
  const [form, setForm] = useState({
    name: '',
    action: 'allow' as RuleAction,
    direction: 'inbound' as RuleDirection,
    protocol: 'TCP' as FirewallRule['protocol'],
    port: '',
    source: '',
    destination: '',
    notes: '',
  })

  const set = (key: keyof typeof form, value: string) =>
    setForm((f) => ({ ...f, [key]: value }))

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!form.port.trim()) return
    addRule({
      name: form.name.trim() || `Rule ${form.port}`,
      action: form.action,
      direction: form.direction,
      protocol: form.protocol,
      port: form.port.trim(),
      source: form.source.trim() || 'any',
      destination: form.destination.trim() || 'any',
      notes: form.notes.trim(),
    })
    setForm((f) => ({ ...f, name: '', port: '', notes: '' }))
  }

  return (
    <div className="panel-grid forge-grid">
      <section className="panel">
        <div className="panel-head">
          <h2>Visual rule builder</h2>
          <span className="muted">Source → action → destination → port</span>
        </div>

        <div className="flow-strip" aria-hidden>
          <div className="flow-node">Source</div>
          <div className="flow-arrow" />
          <div className="flow-node accent">Action</div>
          <div className="flow-arrow" />
          <div className="flow-node">Destination</div>
          <div className="flow-arrow" />
          <div className="flow-node ember">Port</div>
        </div>

        <form className="rule-form" onSubmit={submit}>
          <label>
            Rule name
            <input value={form.name} onChange={(e) => set('name', e.target.value)} placeholder="e.g. HL7 partner inbound" />
          </label>
          <div className="form-row">
            <label>
              Action
              <select value={form.action} onChange={(e) => set('action', e.target.value)}>
                <option value="allow">allow</option>
                <option value="deny">deny</option>
                <option value="reject">reject</option>
              </select>
            </label>
            <label>
              Direction
              <select value={form.direction} onChange={(e) => set('direction', e.target.value)}>
                <option value="inbound">inbound</option>
                <option value="outbound">outbound</option>
                <option value="bidirectional">bidirectional</option>
              </select>
            </label>
            <label>
              Protocol
              <select value={form.protocol} onChange={(e) => set('protocol', e.target.value)}>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="TCP/UDP">TCP/UDP</option>
                <option value="ANY">ANY</option>
              </select>
            </label>
          </div>
          <div className="form-row">
            <label>
              Source
              <input value={form.source} onChange={(e) => set('source', e.target.value)} placeholder="vpn-pool / CIDR / any" />
            </label>
            <label>
              Destination
              <input
                value={form.destination}
                onChange={(e) => set('destination', e.target.value)}
                placeholder="app-vip / host group / any"
              />
            </label>
            <label>
              Port
              <input
                value={form.port}
                onChange={(e) => set('port', e.target.value)}
                placeholder="443 or 8000-8010"
                required
              />
            </label>
          </div>
          <label>
            Notes
            <textarea
              value={form.notes}
              onChange={(e) => set('notes', e.target.value)}
              placeholder="Change ticket context, owner, rollback…"
              rows={3}
            />
          </label>
          <div className="action-row">
            <button type="submit" className="btn btn-primary">
              <Hammer size={16} /> Add rule
            </button>
          </div>
        </form>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Rule set</h2>
          <button type="button" className="btn btn-ghost danger" onClick={clearRules} disabled={!rules.length}>
            <Trash2 size={14} /> Clear
          </button>
        </div>
        {rules.length === 0 ? (
          <div className="empty">
            <Hammer size={28} />
            <p>No rules yet. Forge from the encyclopedia or add one manually.</p>
          </div>
        ) : (
          <ul className="rule-list">
            {rules.map((r) => (
              <li key={r.id} className="rule-card">
                <div className="rule-card-top">
                  <strong>{r.name}</strong>
                  <button type="button" className="icon-btn" onClick={() => removeRule(r.id)} aria-label="Remove">
                    <X size={14} />
                  </button>
                </div>
                <div className="rule-visual">
                  <span className="mono">{r.source}</span>
                  <span className={clsx('pill', r.action === 'allow' ? 'risk-low' : 'risk-critical')}>
                    {r.action}
                  </span>
                  <span className="mono">{r.destination}</span>
                  <span className="pill">{r.protocol}/{r.port}</span>
                </div>
                {r.notes && <p className="muted small">{r.notes}</p>}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}

function ConflictsPanel() {
  const { conflicts, rules } = usePortForge()

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Conflict detection</h2>
        <span className="muted">
          {conflicts.length} issue{conflicts.length === 1 ? '' : 's'} across {rules.length} rules
        </span>
      </div>
      {conflicts.length === 0 ? (
        <div className="empty success">
          <CheckCircle2 size={28} />
          <p>No conflicts detected. Your rule set looks clean.</p>
        </div>
      ) : (
        <ul className="conflict-list">
          {conflicts.map((c) => (
            <li key={c.id} className={clsx('conflict-card', c.severity)}>
              <div className="conflict-icon">
                <AlertTriangle size={18} />
              </div>
              <div>
                <div className="conflict-top">
                  <strong>{c.title}</strong>
                  <span className="pill">{c.severity}</span>
                  <span className="pill muted-pill">{c.type}</span>
                </div>
                <p>{c.detail}</p>
                <p className="muted small mono">rules: {c.ruleIds.join(', ')}</p>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function ExportPanel() {
  const { rules } = usePortForge()
  const [format, setFormat] = useState<'markdown' | 'csv' | 'iptables' | 'asa'>('markdown')
  const [copied, setCopied] = useState(false)

  const content = useMemo(() => {
    if (!rules.length) return 'No rules to export. Forge a rule set first.'
    switch (format) {
      case 'csv':
        return exportCsv(rules)
      case 'iptables':
        return exportIptables(rules)
      case 'asa':
        return exportAsa(rules)
      default:
        return exportMarkdown(rules)
    }
  }, [rules, format])

  useEffect(() => {
    setCopied(false)
  }, [format, rules])

  const copy = async () => {
    await navigator.clipboard.writeText(content)
    setCopied(true)
  }

  const download = () => {
    const ext = format === 'markdown' ? 'md' : format === 'csv' ? 'csv' : 'txt'
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `portforge-rules.${ext}`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Documentation export</h2>
        <div className="chip-row">
          {(['markdown', 'csv', 'iptables', 'asa'] as const).map((f) => (
            <button key={f} type="button" className={clsx('chip', format === f && 'active')} onClick={() => setFormat(f)}>
              {f}
            </button>
          ))}
        </div>
      </div>
      <div className="action-row" style={{ marginBottom: '0.85rem' }}>
        <button type="button" className="btn btn-primary" onClick={copy} disabled={!rules.length}>
          <Copy size={16} /> {copied ? 'Copied' : 'Copy'}
        </button>
        <button type="button" className="btn btn-ghost" onClick={download} disabled={!rules.length}>
          <Download size={16} /> Download
        </button>
      </div>
      <pre className="export-pre">{content}</pre>
    </section>
  )
}

export default function App() {
  return (
    <PortForgeProvider>
      <AppShell />
    </PortForgeProvider>
  )
}

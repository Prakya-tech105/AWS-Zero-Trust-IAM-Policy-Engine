import { useEffect, useMemo, useRef } from 'react'
import Editor, { type Monaco } from '@monaco-editor/react'
import { AlertTriangle, FileJson, CheckCircle2 } from 'lucide-react'
import type { PolicyDocument } from '../types'

interface PolicyDiffViewerProps {
  currentPolicy: PolicyDocument | string | null
  leastPrivilegePolicy: PolicyDocument | string | null
  simulationValid: boolean | null
}

const editorOptions = {
  readOnly: true,
  minimap: { enabled: false },
  lineNumbers: 'off' as const,
  scrollBeyondLastLine: false,
  fontSize: 12,
  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
  renderLineHighlight: 'none' as const,
  automaticLayout: true,
  tabSize: 2,
}

// Robust helper to ensure policy values become clean, multi-line JSON strings
function formatPolicyProp(policy: unknown, fallback: string): string {
  if (!policy) return fallback

  let data = policy

  // If passed as a string, attempt recursive un-escaping & parsing
  while (typeof data === 'string') {
    try {
      const parsed = JSON.parse(data)
      if (parsed === data) break
      data = parsed
    } catch {
      // Handle escaped string scenarios like \" and \n
      try {
        const unescaped = data.replace(/\\"/g, '"').replace(/\\n/g, '\n')
        data = JSON.parse(unescaped)
      } catch {
        break
      }
    }
  }

  return typeof data === 'object' && data !== null
    ? JSON.stringify(data, null, 2)
    : String(data)
}

function useWildcardDecorations(
  editorRef: React.MutableRefObject<unknown>,
  monaco: Monaco | null,
  value: string,
  color: string,
) {
  useEffect(() => {
    const ed = editorRef.current as { createDecorationsCollection?: (d: unknown[]) => unknown; deltaDecorations?: (old: unknown[], d: unknown[]) => unknown[] } | null
    if (!ed) return
    const lines = value.split('\n')
    const decorations = lines.map((line, i) => {
      const lineNo = i + 1
      if (/:\s*"\*"/.test(line) || /"\*:\*"/.test(line)) {
        return {
          range: { startLineNumber: lineNo, startColumn: 1, endLineNumber: lineNo, endColumn: 1 },
          options: {
            isWholeLine: true,
            className: `zt-wildcard-${color}`,
            overviewRuler: { color: '#ef4444', position: 4 },
          },
        }
      }
      if (/:\s*"[a-z0-9-]+:[A-Za-z0-9*?]+"/.test(line)) {
        return {
          range: { startLineNumber: lineNo, startColumn: 1, endLineNumber: lineNo, endColumn: 1 },
          options: {
            isWholeLine: true,
            className: `zt-exact-${color}`,
            overviewRuler: { color: '#10b981', position: 4 },
          },
        }
      }
      return null
    }).filter(Boolean)
    if (ed.createDecorationsCollection) {
      ed.createDecorationsCollection(decorations)
    }
  }, [value, color, editorRef, monaco])
}

function Panel({
  title,
  badge,
  badgeCls,
  sub,
  value,
  color,
}: {
  title: string
  badge: string
  badgeCls: string
  sub: string
  value: string
  color: string
}) {
  const editorRef = useRef<unknown>(null)
  useWildcardDecorations(editorRef, null, value, color)

  return (
    <div>
      <div className="flex items-center gap-2 border-b border-slate-800/60 px-4 py-1.5">
        <span className={`rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest ${badgeCls}`}>
          {title} · {badge}
        </span>
        <span className="text-[10px] text-slate-500">{sub}</span>
      </div>
      <Editor
        height="320px"
        language="json"
        theme="vs-dark"
        value={value}
        options={editorOptions}
        onMount={(editor) => {
          editorRef.current = editor
        }}
      />
    </div>
  )
}

export default function PolicyDiffViewer({
  currentPolicy,
  leastPrivilegePolicy,
  simulationValid,
}: PolicyDiffViewerProps) {
  const currentJson = useMemo(
    () => formatPolicyProp(currentPolicy, '// no policy data yet'),
    [currentPolicy],
  )
  const leastJson = useMemo(
    () => formatPolicyProp(leastPrivilegePolicy, '// ingest an event to generate the least-privilege policy'),
    [leastPrivilegePolicy],
  )

  const hasWildcards = currentJson.includes('*')

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900/60">
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 bg-slate-900 px-4 py-2.5">
        <FileJson className="h-4 w-4 text-slate-400" />
        <h2 className="text-sm font-semibold text-slate-200">Policy Diff Viewer</h2>
        <span className="text-[10px] uppercase tracking-widest text-slate-500">current vs zero-trust</span>
        <div className="ml-auto flex items-center gap-3 text-[10px] uppercase tracking-wider">
          {hasWildcards && (
            <span className="flex items-center gap-1 text-red-400">
              <AlertTriangle className="h-3 w-3" /> over-privileged
            </span>
          )}
          {simulationValid === true && (
            <span className="flex items-center gap-1 text-emerald-400">
              <CheckCircle2 className="h-3 w-3" /> simulator passed
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 divide-y divide-slate-800 lg:grid-cols-2 lg:divide-x lg:divide-y-0">
        <Panel
          title="Left"
          badge="Current"
          badgeCls="bg-red-500/10 text-red-400"
          sub="over-privileged"
          value={currentJson}
          color="red"
        />
        <Panel
          title="Right"
          badge="Zero-Trust"
          badgeCls="bg-emerald-500/10 text-emerald-400"
          sub="least-privilege candidate"
          value={leastJson}
          color="green"
        />
      </div>
    </section>
  )
}
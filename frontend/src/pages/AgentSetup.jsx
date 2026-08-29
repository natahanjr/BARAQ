import { AgentIcon } from "../components/icons.jsx";

function Step({ n, title, children }) {
  return (
    <div className="rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-6">
      <div className="flex items-start gap-3">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-cyan)]/10 text-[12px] font-bold text-[var(--accent-cyan)] ring-1 ring-[var(--accent-cyan)]/20">
          {n}
        </span>
        <div className="min-w-0 flex-1">
          <h3 className="text-[15px] font-bold text-[var(--fg-primary)]">{title}</h3>
          <div className="mt-2 text-[13px] leading-relaxed text-[var(--fg-secondary)]">{children}</div>
        </div>
      </div>
    </div>
  );
}

function Code({ children }) {
  return (
    <pre
      className="mt-3 overflow-x-auto rounded-xl border p-4 font-mono text-[13px] leading-relaxed shadow-inner"
      style={{ background: "var(--bg-inset)", borderColor: "var(--border-subtle)", color: "var(--accent-cyan)" }}
    >
      {children}
    </pre>
  );
}

const AGENT_ACTIONS = [
  { action: "block_ip", glue: "Block an IP", detail: "adds a firewall rule on the host" },
  { action: "kill_process", glue: "Terminate a process", detail: "kills the named process" },
  { action: "quarantine", glue: "Quarantine a file", detail: "moves the file out of reach" },
  { action: "isolate", glue: "Isolate the endpoint", detail: "cuts its network access" },
  { action: "disable_account", glue: "Disable a user account", detail: "locks the Windows account" },
  { action: "escalate", glue: "Escalate for review", detail: "flags analysis for an analyst" },
];

export default function AgentSetup() {
  return (
    <div className="space-y-6 pb-12">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[var(--tracking-widest)] text-[var(--fg-muted)]">SETUP</p>
          <h1 className="mt-1 text-[28px] font-bold tracking-tight text-[var(--fg-primary)]">Agent Setup</h1>
          <p className="mt-0.5 text-[13px] text-[var(--fg-muted)]">Deploy BARAQ agents to remote endpoints</p>
        </div>
        <span className="inline-flex items-center gap-2 rounded-xl border border-[var(--accent-cyan)]/20 bg-[var(--accent-cyan)]/[0.06] px-3.5 py-2 text-[12px] text-[var(--accent-cyan)]">
          <AgentIcon className="h-4 w-4" />
          Ships Windows telemetry home via HTTPS 8443
        </span>
      </header>

      <Step n={1} title="Open inbound access">
        <p>
          The agent talks to this server over{" "}
          <span className="font-mono text-[var(--fg-primary)]">HTTPS 8443</span> (and 8001 for the web
          console). Make sure firewall rules on this host allow inbound TCP 8443 from the campus
          network, and that the server has a certificate the agents trust — see{" "}
          <span className="font-mono text-[var(--fg-primary)]">documentation/deployment_guide.md</span> for
          the self-signed CA setup before enrolling any host.
        </p>
      </Step>

      <Step n={2} title="Provision a host key">
        <p>
          Every agent is identified by a key generated on the server, stored in the DPAPI vault
          (<span className="font-mono text-[var(--fg-primary)]">secrets.dat</span>) and written to{" "}
          <span className="font-mono text-[var(--fg-primary)]">agent_configs\</span>. Run this on the server:
        </p>
        <Code>{`venv\Scripts\python scripts\provision_agent.py add ws-lib-01 https://soc.example.com:8443 --org univ-a --tls-cert certs\baraq.crt`}</Code>
        <p className="mt-3 text-[11px] text-[var(--fg-muted)]">
          One launch line per host is written to{" "}
          <span className="font-mono text-[var(--fg-primary)]">{"agent_configs\\{org}-manifest.json"}</span>; the
          server also loads the same keys at startup via{" "}
          <span className="font-mono text-[var(--fg-primary)]">BARAQ_AGENT_KEYS</span> /{" "}
          <span className="font-mono text-[var(--fg-primary)]">BARAQ_AGENT_ORGS</span>. Use{" "}
          <span className="font-mono text-[var(--fg-primary)]">list</span> and{" "}
          <span className="font-mono text-[var(--fg-primary)]">revoke</span> subcommands to manage them.
        </p>
      </Step>

      <Step n={3} title="Run the agent (scripted mode)">
        <p>On a host with Python, launch the agent with its provisioned key:</p>
        <Code>{`python scripts\agent.py --server https://soc.example.com:8443 --key "<host-key>" --tls-ca .\baraq.crt --interval 15`}</Code>
      </Step>

      <Step n={4} title="Deploy the packaged fleet agent">
        <p>
          Hosts without Python run the one-file build: copy{" "}
          <span className="font-mono text-[var(--fg-primary)]">{"dist\\agent\\{host}\\"}</span> (a PyInstaller
          build with the launch line baked in) to the target and install it as a service from an
          admin shell:
        </p>
        <Code>{`agent.exe --install`}</Code>
        <p className="mt-3 text-[11px] text-[var(--fg-muted)]">
          The registered service ships telemetry every cycle and auto-starts on boot. In both
          modes the agent re-registers with the server on each ship cycle, so new endpoints appear
          under <span className="font-mono text-[var(--fg-primary)]">Endpoints</span> automatically.
        </p>
      </Step>

      <Step n={5} title="Remote actions (analyst-driven)">
        <p>
          From the <span className="font-mono text-[var(--fg-primary)]">Endpoints</span> page, an admin can
          queue actions the agent pulls within 15 seconds and reports back on:
        </p>
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          {AGENT_ACTIONS.map((a) => (
            <div
              key={a.action}
              className="rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-inset)] px-3.5 py-3"
            >
              <p className="font-mono text-[12px] font-semibold text-[var(--accent-cyan)]">{a.action}</p>
              <p className="mt-0.5 text-[11px] text-[var(--fg-secondary)]">
                {a.glue} — {a.detail}
              </p>
            </div>
          ))}
        </div>
      </Step>

      <div className="rounded-[var(--radius-2xl)] border border-[var(--status-healthy)]/15 bg-gradient-to-br from-[var(--status-healthy)]/[0.04] to-transparent p-6">
        <h3 className="text-[15px] font-bold text-[var(--fg-primary)]">Direct ingestion</h3>
        <p className="mt-1 text-[13px] leading-relaxed text-[var(--fg-secondary)]">
          Anything that can speak HTTP can ship telemetry into the pipeline:{" "}
          <span className="font-mono text-[var(--fg-primary)]">POST /api/ingest</span> with an{" "}
          <span className="font-mono text-[var(--fg-primary)]">X-Agent-Key</span> header. Scripts and
          integrations use this path when a full agent install is overkill.
        </p>
      </div>

      <div className="flex justify-center pt-4">
        <p className="text-[11px] font-medium text-[var(--fg-faint)]">BARAQ · Real-Time Endpoint Security Operations</p>
      </div>
    </div>
  );
}

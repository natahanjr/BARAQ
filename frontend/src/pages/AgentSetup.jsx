import Card from "../components/Card.jsx";
import PageHeader from "../components/PageHeader.jsx";
import { AgentIcon } from "../components/icons.jsx";

function Step({ n, title, children }) {
  return (
    <Card>
      <div className="flex items-start gap-3">
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-cyan-500/15 text-xs font-bold text-cyan-400">
          {n}
        </span>
        <div className="min-w-0 flex-1">
          <h3 className="text-base font-semibold text-white">{title}</h3>
          <div className="mt-2 text-sm leading-relaxed text-slate-400">{children}</div>
        </div>
      </div>
    </Card>
  );
}

function Code({ children }) {
  return (
    <pre className="mt-3 overflow-x-auto rounded-lg border border-slate-700/50 bg-slate-950/70 p-3.5 font-mono text-xs leading-relaxed text-cyan-200">
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
      <PageHeader
        title="Agent Setup"
        subtitle="Deploy BARAQ agents to remote endpoints"
        actions={
          <span className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3.5 py-2 text-sm text-cyan-300">
            <AgentIcon className="h-4 w-4" />
            Ships Windows telemetry home via HTTPS 8443
          </span>
        }
      />

      <Step n={1} title="Open inbound access">
        <p>
          The agent talks to this server over{" "}
          <span className="font-mono text-slate-200">HTTPS 8443</span> (and 8001 for the web
          console). Make sure firewall rules on this host allow inbound TCP 8443 from the campus
          network, and that the server has a certificate the agents trust — see{" "}
          <span className="font-mono text-slate-200">documentation/deployment_guide.md</span> for
          the self-signed CA setup before enrolling any host.
        </p>
      </Step>

      <Step n={2} title="Provision a host key">
        <p>
          Every agent is identified by a key generated on the server, stored in the DPAPI vault
          (<span className="font-mono text-slate-200">secrets.dat</span>) and written to{" "}
          <span className="font-mono text-slate-200">agent_configs\</span>. Run this on the server:
        </p>
        <Code>{`venv\Scripts\python scripts\provision_agent.py add ws-lib-01 https://soc.example.com:8443 --org univ-a --tls-cert certs\baraq.crt`}</Code>
        <p className="mt-3 text-xs text-slate-500">
          One launch line per host is written to{" "}
          <span className="font-mono text-slate-200">{"agent_configs\\{org}-manifest.json"}</span>; the
          server also loads the same keys at startup via{" "}
          <span className="font-mono text-slate-200">BARAQ_AGENT_KEYS</span> /{" "}
          <span className="font-mono text-slate-200">BARAQ_AGENT_ORGS</span>. Use{" "}
          <span className="font-mono text-slate-200">list</span> and{" "}
          <span className="font-mono text-slate-200">revoke</span> subcommands to manage them.
        </p>
      </Step>

      <Step n={3} title="Run the agent (scripted mode)">
        <p>On a host with Python, launch the agent with its provisioned key:</p>
        <Code>{`python scripts\agent.py --server https://soc.example.com:8443 --key "<host-key>" --tls-ca .\baraq.crt --interval 15`}</Code>
      </Step>

      <Step n={4} title="Deploy the packaged fleet agent">
        <p>
          Hosts without Python run the one-file build: copy{" "}
          <span className="font-mono text-slate-200">{"dist\\agent\\{host}\\"}</span> (a PyInstaller
          build with the launch line baked in) to the target and install it as a service from an
          admin shell:
        </p>
        <Code>{`agent.exe --install`}</Code>
        <p className="mt-3 text-xs text-slate-500">
          The registered service ships telemetry every cycle and auto-starts on boot. In both
          modes the agent re-registers with the server on each ship cycle, so new endpoints appear
          under <span className="font-mono text-slate-200">Endpoints</span> automatically.
        </p>
      </Step>

      <Step n={5} title="Remote actions (analyst-driven)">
        <p>
          From the <span className="font-mono text-slate-200">Endpoints</span> page, an admin can
          queue actions the agent pulls within 15 seconds and reports back on:
        </p>
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          {AGENT_ACTIONS.map((a) => (
            <div
              key={a.action}
              className="rounded-lg border border-slate-800/60 bg-slate-900/40 px-3 py-2.5 text-xs"
            >
              <p className="font-mono font-semibold text-cyan-300">{a.action}</p>
              <p className="mt-0.5 text-slate-400">
                {a.glue} — {a.detail}
              </p>
            </div>
          ))}
        </div>
      </Step>

      <Card tone="emerald">
        <h3 className="text-base font-semibold text-white">Direct ingestion</h3>
        <p className="mt-1 text-sm leading-relaxed text-slate-400">
          Anything that can speak HTTP can ship telemetry into the pipeline:{" "}
          <span className="font-mono text-slate-200">POST /api/ingest</span> with an{" "}
          <span className="font-mono text-slate-200">X-Agent-Key</span> header. Scripts and
          integrations use this path when a full agent install is overkill.
        </p>
      </Card>
    </div>
  );
}
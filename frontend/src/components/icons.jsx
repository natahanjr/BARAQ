const BASE = {
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.8,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": true,
};

function Icon({ children, className = "h-5 w-5" }) {
  return (
    <svg {...BASE} className={className}>
      {children}
    </svg>
  );
}

export function DashboardIcon(props) {
  return (
    <Icon {...props}>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </Icon>
  );
}

export function AlertsIcon(props) {
  return (
    <Icon {...props}>
      <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
      <path d="M12 9v4" />
      <path d="M12 17h.01" />
    </Icon>
  );
}

export function InvestigationIcon(props) {
  return (
    <Icon {...props}>
      <circle cx="11" cy="11" r="7" />
      <path d="m21 21-4.3-4.3" />
      <path d="M11 8v6" />
      <path d="M8 11h6" />
    </Icon>
  );
}

export function EventsIcon(props) {
  return (
    <Icon {...props}>
      <path d="M8 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2h-3" />
      <path d="M8 3v4h8V3" />
      <path d="M9 13h6" />
      <path d="M9 17h6" />
    </Icon>
  );
}

export function TelemetryIcon(props) {
  return (
    <Icon {...props}>
      <path d="M3 12h4l2-7 4 14 3-7h5" />
    </Icon>
  );
}

export function AssistantIcon(props) {
  return (
    <Icon {...props}>
      <rect x="4" y="3" width="16" height="14" rx="3" />
      <path d="M8 21h8" />
      <path d="M12 17v4" />
      <circle cx="9" cy="10" r="0.5" fill="currentColor" />
      <circle cx="15" cy="10" r="0.5" fill="currentColor" />
    </Icon>
  );
}

export function ReportsIcon(props) {
  return (
    <Icon {...props}>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" />
      <path d="M14 2v6h6" />
      <path d="M8 13h8" />
      <path d="M8 17h5" />
    </Icon>
  );
}

export function EvaluationIcon(props) {
  return (
    <Icon {...props}>
      <path d="M9 3H5a2 2 0 0 0-2 2v4" />
      <path d="M9 21H5a2 2 0 0 1-2-2v-4" />
      <path d="M15 3h4a2 2 0 0 1 2 2v4" />
      <path d="M15 21h4a2 2 0 0 0 2-2v-4" />
      <path d="m8.5 12.5 2.5 2.5 4.5-4.5" />
    </Icon>
  );
}

export function SystemIcon(props) {
  return (
    <Icon {...props}>
      <path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1-1.55 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.55-1 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34h.09a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.55 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.09a1.7 1.7 0 0 0 1.55 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.51 1Z" />
    </Icon>
  );
}

export function ShieldIcon(props) {
  return (
    <Icon {...props}>
      <path d="M12 22s8-3.5 8-10V5l-8-3-8 3v7c0 6.5 8 10 8 10Z" />
      <path d="m9 12 2 2 4-4" />
    </Icon>
  );
}

export function MenuIcon(props) {
  return (
    <Icon {...props}>
      <path d="M4 6h16" />
      <path d="M4 12h16" />
      <path d="M4 18h16" />
    </Icon>
  );
}

export function RefreshIcon(props) {
  return (
    <Icon {...props}>
      <path d="M21 12a9 9 0 1 1-2.6-6.3" />
      <path d="M21 3v6h-6" />
    </Icon>
  );
}

export function DownloadIcon(props) {
  return (
    <Icon {...props}>
      <path d="M12 3v12" />
      <path d="m7 10 5 5 5-5" />
      <path d="M5 21h14" />
    </Icon>
  );
}

export function AlertIcon(props) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v4" />
      <path d="M12 16h.01" />
    </Icon>
  );
}

export function BoltIcon(props) {
  return (
    <Icon {...props}>
      <path d="M13 2 4 14h6l-1 8 9-12h-6l1-8Z" />
    </Icon>
  );
}

export function ActivityIcon(props) {
  return (
    <Icon {...props}>
      <path d="M22 12h-4l-3 8-6-16-3 8H2" />
    </Icon>
  );
}

export function BoxesIcon(props) {
  return (
    <Icon {...props}>
      <path d="M2 7h20" />
      <path d="M5 21V7" />
      <path d="M19 21V7" />
      <path d="M12 21V7" />
    </Icon>
  );
}

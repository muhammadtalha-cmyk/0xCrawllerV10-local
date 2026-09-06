import type { SVGProps } from "react";

function IconBase(props: SVGProps<SVGSVGElement>) {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props} />;
}

export const RadarIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 18.5 5.5"/><circle cx="12" cy="12" r="1"/></IconBase>;
export const PlayIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="m8 5 11 7-11 7V5Z"/></IconBase>;
export const ShieldIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="M12 3 5 6v5c0 4.5 2.7 8.2 7 10 4.3-1.8 7-5.5 7-10V6l-7-3Z"/><path d="m9 12 2 2 4-5"/></IconBase>;
export const ClockIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></IconBase>;
export const FileIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5"/><path d="M9 13h6M9 17h6"/></IconBase>;
export const ImageIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="m21 15-5-5L5 20"/></IconBase>;
export const DatabaseIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v7c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12v7c0 1.7 3.6 3 8 3s8-1.3 8-3v-7"/></IconBase>;
export const TerminalIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/></IconBase>;
export const ArrowIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="M5 12h14M14 7l5 5-5 5"/></IconBase>;
export const CheckIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="m5 12 4 4L19 6"/></IconBase>;
export const XIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="m6 6 12 12M18 6 6 18"/></IconBase>;
export const DownloadIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="M12 3v12M7 10l5 5 5-5M5 21h14"/></IconBase>;
export const ExternalIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="M14 4h6v6M20 4l-9 9"/><path d="M18 13v6H5V6h6"/></IconBase>;
export const ChevronIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="m9 18 6-6-6-6"/></IconBase>;

// Added for the report dashboard (stat cards, findings table, and pipeline-stage sub-tabs).
export const GlobeIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 3.8 5.8 3.8 9s-1.3 6.5-3.8 9c-2.5-2.5-3.8-5.8-3.8-9s1.3-6.5 3.8-9Z"/></IconBase>;
export const LayersIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="m12 3 8 4.5-8 4.5-8-4.5L12 3Z"/><path d="m4 12 8 4.5 8-4.5"/><path d="m4 16.5 8 4.5 8-4.5"/></IconBase>;
export const CompassIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><circle cx="12" cy="12" r="9"/><path d="m15 9-2 6-6 2 2-6 6-2Z"/></IconBase>;
export const FingerprintIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="M12 3a7 7 0 0 0-7 7v2c0 3 1 5.5 2.5 7"/><path d="M12 3a7 7 0 0 1 7 7v2c0 4-1.5 6.5-3 8"/><path d="M9 21c1-2 1.5-4 1.5-7v-2a1.5 1.5 0 0 1 3 0v2c0 2 .3 3.6 1 5"/><path d="M12 8a3 3 0 0 0-3 3v3c0 1.5.3 2.8.8 4"/></IconBase>;
export const ShieldAlertIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="M12 3 5 6v5c0 4.5 2.7 8.2 7 10 4.3-1.8 7-5.5 7-10V6l-7-3Z"/><path d="M12 8v4"/><circle cx="12" cy="15.5" r="0.5" fill="currentColor"/></IconBase>;
export const SearchIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></IconBase>;
export const SortIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="M7 9V3M7 3 4 6M7 3l3 3"/><path d="M17 15v6m0 0 3-3m-3 3-3-3"/></IconBase>;export const BellIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/></IconBase>;
export const PlusIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="M12 5v14M5 12h14"/></IconBase>;
export const UserIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-5 14.5-5 16 0"/></IconBase>;
export const LinkIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1.1 1.1"/><path d="M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1.1-1.1"/></IconBase>;
export const ServerIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01M11 7h6M11 17h6"/></IconBase>;
export const ActivityIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><path d="M3 12h4l2-7 4 14 2-7h6"/></IconBase>;
export const CopyIcon = (props: SVGProps<SVGSVGElement>) => <IconBase {...props}><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></IconBase>;
export const SunIcon = (props: SVGProps<SVGSVGElement>) => (
  <IconBase {...props}>
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
  </IconBase>
);
export const MoonIcon = (props: SVGProps<SVGSVGElement>) => (
  <IconBase {...props}>
    <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
  </IconBase>
);


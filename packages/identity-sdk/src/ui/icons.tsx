"use client";

/** Inline SVG icon set — zero-dependency, currentColor-based. */

import * as React from "react";

interface IconProps {
  readonly className?: string;
  readonly "aria-hidden"?: boolean;
}

const base = "shrink-0";

export function FingerprintIcon({ className, ...rest }: IconProps): React.ReactElement {
  return (
    <svg className={`${base} ${className ?? ""}`.trim()} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden {...rest}>
      <path d="M5.5 8a8 8 0 0 1 13 0" />
      <path d="M3.5 11a10 10 0 0 1 17 0" />
      <path d="M7.5 11a6 6 0 0 1 9 0" />
      <path d="M9.5 11a4 4 0 0 1 5 0" />
      <path d="M12 15v6" />
      <path d="M9 18.5c0 1 .5 2 1.5 2.5" />
      <path d="M14.5 13.5v3a3 3 0 0 0 1 2.3" />
    </svg>
  );
}

export function ShieldCheckIcon({ className, ...rest }: IconProps): React.ReactElement {
  return (
    <svg className={`${base} ${className ?? ""}`.trim()} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden {...rest}>
      <path d="M12 2.5 4 5v6c0 5 3.4 9 8 11 4.6-2 8-6 8-11V5l-8-2.5z" />
      <path d="M9 12.2l2 2 4-4.4" />
    </svg>
  );
}

export function ChevronDownIcon({ className, ...rest }: IconProps): React.ReactElement {
  return (
    <svg className={`${base} ${className ?? ""}`.trim()} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden {...rest}>
      <path d="M6 9l6 6 6-6" />
    </svg>
  );
}

export function XIcon({ className, ...rest }: IconProps): React.ReactElement {
  return (
    <svg className={`${base} ${className ?? ""}`.trim()} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden {...rest}>
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}

export function CopyIcon({ className, ...rest }: IconProps): React.ReactElement {
  return (
    <svg className={`${base} ${className ?? ""}`.trim()} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden {...rest}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15V5a2 2 0 0 1 2-2h10" />
    </svg>
  );
}

export function CheckIcon({ className, ...rest }: IconProps): React.ReactElement {
  return (
    <svg className={`${base} ${className ?? ""}`.trim()} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden {...rest}>
      <path d="M5 12l4 4L19 7" />
    </svg>
  );
}

export function GlobeIcon({ className, ...rest }: IconProps): React.ReactElement {
  return (
    <svg className={`${base} ${className ?? ""}`.trim()} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden {...rest}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18" />
      <path d="M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18" />
    </svg>
  );
}

export function ServerIcon({ className, ...rest }: IconProps): React.ReactElement {
  return (
    <svg className={`${base} ${className ?? ""}`.trim()} viewBox="0 0 24 24" fill="none"
         stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden {...rest}>
      <rect x="3" y="4" width="18" height="6" rx="2" />
      <rect x="3" y="14" width="18" height="6" rx="2" />
      <circle cx="7" cy="7" r="0.8" fill="currentColor" />
      <circle cx="7" cy="17" r="0.8" fill="currentColor" />
    </svg>
  );
}

export function SpinnerIcon({ className, ...rest }: IconProps): React.ReactElement {
  return (
    <svg className={`${base} animate-spin ${className ?? ""}`.trim()} viewBox="0 0 24 24" fill="none" aria-hidden {...rest}>
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="2.5" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  );
}

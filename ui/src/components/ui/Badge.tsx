import type { HTMLAttributes } from "react";

type BadgeTone = "neutral" | "active" | "success" | "warning" | "danger";

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
}

export function Badge({ tone = "neutral", className = "", ...props }: BadgeProps) {
  return <span className={`badge badge-${tone} ${className}`} {...props} />;
}

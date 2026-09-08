import type { HTMLAttributes, ReactNode } from "react";
import { CARD_CLASSES, CARD_PADDING } from "@/design-system/tokens";

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
  padded?: boolean;
  accentClassName?: string;
}

/** The single canonical card surface. Replaces the
 * `rounded-xl border border-gray-800 bg-gray-900 p-5` string literal
 * that was independently written in 57 files. */
export function Card({ children, padded = true, accentClassName, className = "", ...rest }: CardProps) {
  const classes = [CARD_CLASSES, padded ? CARD_PADDING : "", accentClassName ?? "", className]
    .filter(Boolean)
    .join(" ");
  return (
    <div className={classes} {...rest}>
      {children}
    </div>
  );
}

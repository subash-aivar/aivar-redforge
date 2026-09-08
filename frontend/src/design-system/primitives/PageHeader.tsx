import type { ReactNode } from "react";
import { PAGE_SUBTITLE_CLASSES, PAGE_TITLE_CLASSES } from "@/design-system/tokens";

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}

/** Canonical page-level header. Markup and spacing (`mb-6` wrapper)
 * are byte-identical to `cc.tsx`'s `PageHeader` — the two components
 * previously shared a name but rendered different title weights and
 * spacing; normalized so a page built on either primitive library
 * looks identical at the header. */
export function PageHeader({ title, subtitle, actions }: PageHeaderProps) {
  return (
    <div className="mb-6 flex items-start justify-between gap-4">
      <div>
        <h1 className={PAGE_TITLE_CLASSES}>{title}</h1>
        {subtitle && <p className={PAGE_SUBTITLE_CLASSES}>{subtitle}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

import type { ReactNode } from "react";
import { SECTION_HEADER_CLASSES } from "@/design-system/tokens";

interface SectionHeaderProps {
  title: string;
  actions?: ReactNode;
}

export function SectionHeader({ title, actions }: SectionHeaderProps) {
  return (
    <div className="flex items-center justify-between">
      <h2 className={SECTION_HEADER_CLASSES}>{title}</h2>
      {actions}
    </div>
  );
}

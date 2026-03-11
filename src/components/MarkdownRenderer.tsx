import { useMemo } from "react";
import { marked } from "marked";

marked.setOptions({
  breaks: true,
  gfm: true,
});

interface MarkdownRendererProps {
  content: string;
  className?: string;
}

export function MarkdownRenderer({ content, className }: MarkdownRendererProps) {
  const html = useMemo(() => {
    if (!content) return "";
    return marked.parse(content, { async: false }) as string;
  }, [content]);

  return (
    <div
      className={`markdown-content ${className ?? ""}`}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

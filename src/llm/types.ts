export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface BatchRenameResult {
  address: number;
  currentName: string;
  suggestedName: string;
  confidence: number;
  reasoning: string;
  accepted: boolean | null;
}

export interface AIScanFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  functionAddress: number;
  functionName: string;
  remediation: string;
  source: "ai-scan";
}

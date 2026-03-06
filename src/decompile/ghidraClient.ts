export interface GhidraDecompileResult {
  code: string;
  lineMap: [number, number][];
}

export class GhidraClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(baseUrl: string, apiKey?: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey ?? "";
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) h["Authorization"] = `Bearer ${this.apiKey}`;
    return h;
  }

  private async throwWithDetail(res: Response, fallback: string): Promise<never> {
    let detail = fallback;
    try {
      const body = await res.json();
      if (body?.detail) detail = body.detail;
    } catch {}
    throw new Error(detail);
  }

  async ping(): Promise<{ version: string }> {
    const res = await fetch(`${this.baseUrl}/api/v1/ping`, { headers: this.headers() });
    if (!res.ok) await this.throwWithDetail(res, `Ghidra server error (${res.status})`);
    return res.json();
  }

  async uploadBinary(bytes: Uint8Array): Promise<{ projectId: string }> {
    const form = new FormData();
    form.append("file", new Blob([bytes]), "binary.exe");
    const headers: Record<string, string> = {};
    if (this.apiKey) headers["Authorization"] = `Bearer ${this.apiKey}`;
    const res = await fetch(`${this.baseUrl}/api/v1/binary`, {
      method: "POST",
      headers,
      body: form,
    });
    if (!res.ok) await this.throwWithDetail(res, `Upload failed (${res.status})`);
    return res.json();
  }

  async decompileFunction(
    projectId: string,
    funcAddr: number,
    is64: boolean,
  ): Promise<GhidraDecompileResult> {
    const res = await fetch(`${this.baseUrl}/api/v1/decompile`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({ projectId, funcAddr, is64 }),
    });
    if (!res.ok) await this.throwWithDetail(res, `Decompile failed (${res.status})`);
    return res.json();
  }
}

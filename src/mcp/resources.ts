/**
 * MCP resource registrations for Peek-a-Bin.
 * Exposes PE file data as pe://{fileId}/* resources.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import type { AnalyzedFile, FileSession } from './session';

type ResourceResult = {
  contents: { uri: string; mimeType: string; text: string }[];
};

/** Format an address the way every tool/resource response does. */
function hex(n: number): string {
  return `0x${n.toString(16)}`;
}

/**
 * Resolve a loaded file or fail the read.
 *
 * `resources/read` has no `isError` field (unlike `tools/call`), so an unknown fileId
 * is reported as a JSON-RPC error rather than a successful read whose body happens to
 * contain `{"error": ...}` — which clients would otherwise treat as valid PE data.
 */
function withFile(
  session: FileSession,
  fileId: unknown,
  uri: URL,
  fn: (af: AnalyzedFile) => unknown,
): ResourceResult {
  const id = String(fileId);
  const af = session.getFile(id);
  if (!af) {
    throw new McpError(ErrorCode.InvalidParams, `file "${id}" not loaded`);
  }
  return {
    contents: [{
      uri: uri.href,
      mimeType: 'application/json',
      text: JSON.stringify(fn(af), null, 2),
    }],
  };
}

export function registerResources(server: McpServer, session: FileSession): void {
  // ── pe://{fileId}/headers ──
  server.resource(
    'pe-headers',
    new ResourceTemplate('pe://{fileId}/headers', { list: undefined }),
    async (uri, { fileId }) => withFile(session, fileId, uri, (af) => {
      const pe = af.pe;
      const opt = pe.optionalHeader;
      return {
        is64: pe.is64,
        machine: pe.coffHeader.machine,
        numberOfSections: pe.coffHeader.numberOfSections,
        timeDateStamp: pe.coffHeader.timeDateStamp,
        characteristics: pe.coffHeader.characteristics,
        imageBase: hex(opt.imageBase),
        addressOfEntryPoint: hex(opt.addressOfEntryPoint),
        sectionAlignment: opt.sectionAlignment,
        fileAlignment: opt.fileAlignment,
        subsystem: opt.subsystem,
        dllCharacteristics: hex(opt.dllCharacteristics),
        sizeOfImage: opt.sizeOfImage,
        checksum: hex(opt.checksum),
      };
    }),
  );

  // ── pe://{fileId}/sections ──
  server.resource(
    'pe-sections',
    new ResourceTemplate('pe://{fileId}/sections', { list: undefined }),
    async (uri, { fileId }) => withFile(session, fileId, uri, (af) =>
      af.pe.sections.map(s => ({
        name: s.name,
        virtualAddress: hex(s.virtualAddress),
        virtualSize: s.virtualSize,
        rawSize: s.sizeOfRawData,
        rawOffset: hex(s.pointerToRawData),
        characteristics: hex(s.characteristics),
        flags: decodeCharacteristics(s.characteristics),
      })),
    ),
  );

  // ── pe://{fileId}/imports ──
  server.resource(
    'pe-imports',
    new ResourceTemplate('pe://{fileId}/imports', { list: undefined }),
    async (uri, { fileId }) => withFile(session, fileId, uri, (af) =>
      af.pe.imports.map(imp => ({
        library: imp.libraryName,
        functions: imp.functions.map((fn, i) => ({
          name: fn,
          iatAddress: i < imp.iatAddresses.length ? hex(imp.iatAddresses[i]) : undefined,
        })),
      })),
    ),
  );

  // ── pe://{fileId}/exports ──
  server.resource(
    'pe-exports',
    new ResourceTemplate('pe://{fileId}/exports', { list: undefined }),
    async (uri, { fileId }) => withFile(session, fileId, uri, (af) =>
      af.pe.exports.map(e => ({
        name: e.name,
        ordinal: e.ordinal,
        address: hex(e.address),
      })),
    ),
  );

  // ── pe://{fileId}/strings ──
  server.resource(
    'pe-strings',
    new ResourceTemplate('pe://{fileId}/strings', { list: undefined }),
    async (uri, { fileId }) => withFile(session, fileId, uri, (af) =>
      Array.from(af.stringMap.entries()).map(([addr, value]) => ({
        address: hex(addr),
        value,
        type: af.stringTypes.get(addr) ?? 'ascii',
      })),
    ),
  );

  // ── pe://{fileId}/functions ──
  server.resource(
    'pe-functions',
    new ResourceTemplate('pe://{fileId}/functions', { list: undefined }),
    async (uri, { fileId }) => withFile(session, fileId, uri, (af) =>
      af.functions.map(f => ({
        name: f.name,
        address: hex(f.address),
        size: f.size,
        isThunk: f.isThunk ?? false,
        tailCallTarget: f.tailCallTarget !== undefined ? hex(f.tailCallTarget) : undefined,
      })),
    ),
  );

  // ── pe://{fileId}/anomalies ──
  server.resource(
    'pe-anomalies',
    new ResourceTemplate('pe://{fileId}/anomalies', { list: undefined }),
    async (uri, { fileId }) => withFile(session, fileId, uri, (af) => af.anomalies),
  );

  // ── pe://{fileId}/driver ──
  server.resource(
    'pe-driver',
    new ResourceTemplate('pe://{fileId}/driver', { list: undefined }),
    async (uri, { fileId }) => withFile(session, fileId, uri, (af) => af.driverInfo),
  );
}

function decodeCharacteristics(ch: number): string[] {
  const flags: string[] = [];
  if (ch & 0x00000020) flags.push('CODE');
  if (ch & 0x00000040) flags.push('INITIALIZED_DATA');
  if (ch & 0x00000080) flags.push('UNINITIALIZED_DATA');
  if (ch & 0x20000000) flags.push('MEM_EXECUTE');
  if (ch & 0x40000000) flags.push('MEM_READ');
  if (ch & 0x80000000) flags.push('MEM_WRITE');
  return flags;
}

/**
 * MCP resource registrations for Peek-a-Bin.
 * Exposes PE file data as pe://{fileId}/* resources.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { FileSession } from './session';

export function registerResources(server: McpServer, session: FileSession): void {
  // ── pe://{fileId}/headers ──
  server.resource(
    'pe-headers',
    new ResourceTemplate('pe://{fileId}/headers', { list: undefined }),
    async (uri, { fileId }) => {
      const af = session.getFile(fileId as string);
      if (!af) return { contents: [{ uri: uri.href, mimeType: 'application/json', text: '{"error":"file not loaded"}' }] };

      const pe = af.pe;
      const opt = pe.optionalHeader;
      return {
        contents: [{
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify({
            is64: pe.is64,
            machine: pe.coffHeader.machine,
            numberOfSections: pe.coffHeader.numberOfSections,
            timeDateStamp: pe.coffHeader.timeDateStamp,
            characteristics: pe.coffHeader.characteristics,
            imageBase: `0x${opt.imageBase.toString(16)}`,
            addressOfEntryPoint: `0x${opt.addressOfEntryPoint.toString(16)}`,
            sectionAlignment: opt.sectionAlignment,
            fileAlignment: opt.fileAlignment,
            subsystem: opt.subsystem,
            dllCharacteristics: `0x${opt.dllCharacteristics.toString(16)}`,
            sizeOfImage: opt.sizeOfImage,
            checksum: `0x${opt.checksum.toString(16)}`,
          }, null, 2),
        }],
      };
    },
  );

  // ── pe://{fileId}/sections ──
  server.resource(
    'pe-sections',
    new ResourceTemplate('pe://{fileId}/sections', { list: undefined }),
    async (uri, { fileId }) => {
      const af = session.getFile(fileId as string);
      if (!af) return { contents: [{ uri: uri.href, mimeType: 'application/json', text: '{"error":"file not loaded"}' }] };

      const sections = af.pe.sections.map(s => ({
        name: s.name,
        virtualAddress: `0x${s.virtualAddress.toString(16)}`,
        virtualSize: s.virtualSize,
        rawSize: s.sizeOfRawData,
        rawOffset: `0x${s.pointerToRawData.toString(16)}`,
        characteristics: `0x${s.characteristics.toString(16)}`,
        flags: decodeCharacteristics(s.characteristics),
      }));

      return {
        contents: [{
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(sections, null, 2),
        }],
      };
    },
  );

  // ── pe://{fileId}/imports ──
  server.resource(
    'pe-imports',
    new ResourceTemplate('pe://{fileId}/imports', { list: undefined }),
    async (uri, { fileId }) => {
      const af = session.getFile(fileId as string);
      if (!af) return { contents: [{ uri: uri.href, mimeType: 'application/json', text: '{"error":"file not loaded"}' }] };

      const imports = af.pe.imports.map(imp => ({
        library: imp.libraryName,
        functions: imp.functions.map((fn, i) => ({
          name: fn,
          iatAddress: i < imp.iatAddresses.length ? `0x${imp.iatAddresses[i].toString(16)}` : undefined,
        })),
      }));

      return {
        contents: [{
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(imports, null, 2),
        }],
      };
    },
  );

  // ── pe://{fileId}/exports ──
  server.resource(
    'pe-exports',
    new ResourceTemplate('pe://{fileId}/exports', { list: undefined }),
    async (uri, { fileId }) => {
      const af = session.getFile(fileId as string);
      if (!af) return { contents: [{ uri: uri.href, mimeType: 'application/json', text: '{"error":"file not loaded"}' }] };

      const exports = af.pe.exports.map(e => ({
        name: e.name,
        ordinal: e.ordinal,
        address: `0x${e.address.toString(16)}`,
      }));

      return {
        contents: [{
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(exports, null, 2),
        }],
      };
    },
  );

  // ── pe://{fileId}/strings ──
  server.resource(
    'pe-strings',
    new ResourceTemplate('pe://{fileId}/strings', { list: undefined }),
    async (uri, { fileId }) => {
      const af = session.getFile(fileId as string);
      if (!af) return { contents: [{ uri: uri.href, mimeType: 'application/json', text: '{"error":"file not loaded"}' }] };

      const strings = Array.from(af.stringMap.entries()).map(([addr, value]) => ({
        address: `0x${addr.toString(16)}`,
        value,
        type: af.stringTypes.get(addr) ?? 'ascii',
      }));

      return {
        contents: [{
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(strings, null, 2),
        }],
      };
    },
  );

  // ── pe://{fileId}/functions ──
  server.resource(
    'pe-functions',
    new ResourceTemplate('pe://{fileId}/functions', { list: undefined }),
    async (uri, { fileId }) => {
      const af = session.getFile(fileId as string);
      if (!af) return { contents: [{ uri: uri.href, mimeType: 'application/json', text: '{"error":"file not loaded"}' }] };

      const functions = af.functions.map(f => ({
        name: f.name,
        address: `0x${f.address.toString(16)}`,
        size: f.size,
        isThunk: f.isThunk ?? false,
        tailCallTarget: f.tailCallTarget ? `0x${f.tailCallTarget.toString(16)}` : undefined,
      }));

      return {
        contents: [{
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(functions, null, 2),
        }],
      };
    },
  );

  // ── pe://{fileId}/anomalies ──
  server.resource(
    'pe-anomalies',
    new ResourceTemplate('pe://{fileId}/anomalies', { list: undefined }),
    async (uri, { fileId }) => {
      const af = session.getFile(fileId as string);
      if (!af) return { contents: [{ uri: uri.href, mimeType: 'application/json', text: '{"error":"file not loaded"}' }] };

      return {
        contents: [{
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(af.anomalies, null, 2),
        }],
      };
    },
  );

  // ── pe://{fileId}/driver ──
  server.resource(
    'pe-driver',
    new ResourceTemplate('pe://{fileId}/driver', { list: undefined }),
    async (uri, { fileId }) => {
      const af = session.getFile(fileId as string);
      if (!af) return { contents: [{ uri: uri.href, mimeType: 'application/json', text: '{"error":"file not loaded"}' }] };

      return {
        contents: [{
          uri: uri.href,
          mimeType: 'application/json',
          text: JSON.stringify(af.driverInfo, null, 2),
        }],
      };
    },
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

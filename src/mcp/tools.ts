/**
 * MCP tool registrations for Peek-a-Bin.
 */

import { z } from 'zod';
import { readFileSync, writeFileSync } from 'fs';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { FileSession } from './session';
import { analyzeStackFrame } from '../disasm/stack';
import { inferSignature } from '../disasm/signatures';
import { decompileFunction } from '../disasm/decompile/pipeline';
import { validateImport, type ExportSchemaV1 } from '../utils/exportSchema';

export function registerTools(server: McpServer, session: FileSession): void {
  // ── load_pe ──
  server.tool(
    'load_pe',
    'Load and auto-analyze a PE file from disk',
    {
      filePath: z.string().describe('Absolute path to the PE file'),
      id: z.string().optional().describe('Identifier for the loaded file (auto-generated from filename if omitted)'),
    },
    async ({ filePath, id }) => {
      const buffer = readFileSync(filePath);
      const ab = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
      const fileName = filePath.split('/').pop() ?? filePath;
      const fileId = id ?? fileName.replace(/[^a-zA-Z0-9._-]/g, '_');

      const analyzed = await session.loadFile(fileId, fileName, ab);
      const pe = analyzed.pe;

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            id: fileId,
            fileName,
            is64: pe.is64,
            imageBase: `0x${pe.optionalHeader.imageBase.toString(16)}`,
            entryPoint: `0x${pe.optionalHeader.addressOfEntryPoint.toString(16)}`,
            subsystem: pe.optionalHeader.subsystem,
            sectionCount: pe.sections.length,
            importCount: pe.imports.length,
            exportCount: pe.exports.length,
            functionCount: analyzed.functions.length,
            anomalyCount: analyzed.anomalies.length,
            isDriver: analyzed.driverInfo.isDriver,
            driverInfo: analyzed.driverInfo.isDriver ? analyzed.driverInfo : undefined,
          }, null, 2),
        }],
      };
    },
  );

  // ── list_files ──
  server.tool(
    'list_files',
    'List all loaded PE files',
    {},
    async () => {
      const files = session.listFiles().map(f => {
        const af = session.getFile(f.id)!;
        return {
          id: f.id,
          fileName: f.fileName,
          is64: af.pe.is64,
          sectionCount: af.pe.sections.length,
          functionCount: af.functions.length,
        };
      });
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(files, null, 2) }],
      };
    },
  );

  // ── list_functions ──
  server.tool(
    'list_functions',
    'List detected functions in a loaded PE file',
    {
      fileId: z.string().describe('ID of the loaded PE file'),
      filter: z.string().optional().describe('Filter function names (substring match)'),
      offset: z.number().optional().describe('Pagination offset (default 0)'),
      limit: z.number().optional().describe('Max results to return (default 100)'),
    },
    async ({ fileId, filter, offset: off, limit: lim }) => {
      const af = session.getFile(fileId);
      if (!af) return { content: [{ type: 'text' as const, text: `Error: file "${fileId}" not loaded` }], isError: true };

      let fns = af.functions;
      if (filter) {
        const lower = filter.toLowerCase();
        fns = fns.filter(f => f.name.toLowerCase().includes(lower));
      }
      const start = off ?? 0;
      const count = lim ?? 100;
      const page = fns.slice(start, start + count);

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            total: fns.length,
            offset: start,
            count: page.length,
            functions: page.map(f => ({
              name: f.name,
              address: `0x${f.address.toString(16)}`,
              size: f.size,
              isThunk: f.isThunk ?? false,
              tailCallTarget: f.tailCallTarget ? `0x${f.tailCallTarget.toString(16)}` : undefined,
            })),
          }, null, 2),
        }],
      };
    },
  );

  // ── decompile_function ──
  server.tool(
    'decompile_function',
    'Decompile a function to C-like pseudocode',
    {
      fileId: z.string().describe('ID of the loaded PE file'),
      address: z.union([z.number(), z.string()]).describe('Function address (hex string like "0x1234" or number)'),
    },
    async ({ fileId, address }) => {
      const af = session.getFile(fileId);
      if (!af) return { content: [{ type: 'text' as const, text: `Error: file "${fileId}" not loaded` }], isError: true };

      const addr = typeof address === 'string' ? parseInt(address, 16) : address;
      const func = af.functions.find(f => f.address === addr);
      if (!func) return { content: [{ type: 'text' as const, text: `Error: no function at address 0x${addr.toString(16)}` }], isError: true };

      // Get function instructions
      const endAddr = func.address + func.size;
      const funcInsns = af.instructions.filter(i => i.address >= func.address && i.address < endAddr);

      const stackFrame = analyzeStackFrame(func, af.instructions, af.pe.is64);
      const signature = inferSignature(func, af.instructions, af.pe.is64);

      const funcMap = new Map(af.functions.map(f => [
        f.address,
        { name: af.renames[String(f.address)] ?? f.name, address: f.address },
      ]));

      const result = decompileFunction(
        func,
        funcInsns,
        af.xrefMap,
        stackFrame,
        signature,
        af.pe.is64,
        af.jumpTables,
        af.iatMap,
        af.stringMap,
        funcMap,
        af.structRegistry,
        af.pe.runtimeFunctions,
      );

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            functionName: af.renames[String(func.address)] ?? func.name,
            address: `0x${func.address.toString(16)}`,
            code: result.code,
            lineMap: result.lineMap.map(([line, addr]) => ({ line, address: `0x${addr.toString(16)}` })),
          }, null, 2),
        }],
      };
    },
  );

  // ── disassemble_function ──
  server.tool(
    'disassemble_function',
    'Get raw disassembly for a function',
    {
      fileId: z.string().describe('ID of the loaded PE file'),
      address: z.union([z.number(), z.string()]).describe('Function address (hex string like "0x1234" or number)'),
    },
    async ({ fileId, address }) => {
      const af = session.getFile(fileId);
      if (!af) return { content: [{ type: 'text' as const, text: `Error: file "${fileId}" not loaded` }], isError: true };

      const addr = typeof address === 'string' ? parseInt(address, 16) : address;
      const func = af.functions.find(f => f.address === addr);
      if (!func) return { content: [{ type: 'text' as const, text: `Error: no function at address 0x${addr.toString(16)}` }], isError: true };

      const endAddr = func.address + func.size;
      const funcInsns = af.instructions.filter(i => i.address >= func.address && i.address < endAddr);

      const lines = funcInsns.map(insn => {
        const addrHex = insn.address.toString(16).toUpperCase().padStart(af.pe.is64 ? 16 : 8, '0');
        const bytesHex = Array.from(insn.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
        const line = `${addrHex}  ${bytesHex.padEnd(24)}  ${insn.mnemonic.padEnd(8)} ${insn.opStr}`;
        return insn.comment ? `${line}  ; ${insn.comment}` : line;
      });

      return {
        content: [{
          type: 'text' as const,
          text: `; ${func.name} (0x${func.address.toString(16)}, ${func.size} bytes)\n${lines.join('\n')}`,
        }],
      };
    },
  );

  // ── get_xrefs ──
  server.tool(
    'get_xrefs',
    'Get cross-references to/from an address',
    {
      fileId: z.string().describe('ID of the loaded PE file'),
      address: z.union([z.number(), z.string()]).describe('Target address'),
    },
    async ({ fileId, address }) => {
      const af = session.getFile(fileId);
      if (!af) return { content: [{ type: 'text' as const, text: `Error: file "${fileId}" not loaded` }], isError: true };

      const addr = typeof address === 'string' ? parseInt(address, 16) : address;
      const xrefs = af.xrefMap.get(addr) ?? [];

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            address: `0x${addr.toString(16)}`,
            xrefCount: xrefs.length,
            xrefs: xrefs.map(x => ({
              from: `0x${x.from.toString(16)}`,
              type: x.type,
            })),
          }, null, 2),
        }],
      };
    },
  );

  // ── detect_anomalies ──
  server.tool(
    'detect_anomalies',
    'Get security anomalies for a loaded PE file',
    {
      fileId: z.string().describe('ID of the loaded PE file'),
    },
    async ({ fileId }) => {
      const af = session.getFile(fileId);
      if (!af) return { content: [{ type: 'text' as const, text: `Error: file "${fileId}" not loaded` }], isError: true };

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            fileId,
            anomalyCount: af.anomalies.length,
            anomalies: af.anomalies.map(a => ({
              severity: a.severity,
              title: a.title,
              detail: a.detail,
            })),
          }, null, 2),
        }],
      };
    },
  );

  // ── add_comment ──
  server.tool(
    'add_comment',
    'Add or remove a comment at an address',
    {
      fileId: z.string().describe('ID of the loaded PE file'),
      address: z.union([z.number(), z.string()]).describe('Address to comment'),
      text: z.string().describe('Comment text (empty string to remove)'),
    },
    async ({ fileId, address, text }) => {
      const af = session.getFile(fileId);
      if (!af) return { content: [{ type: 'text' as const, text: `Error: file "${fileId}" not loaded` }], isError: true };

      const addr = typeof address === 'string' ? parseInt(address, 16) : address;
      if (text === '') {
        session.deleteComment(fileId, addr);
      } else {
        session.setComment(fileId, addr, text);
      }

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({ fileId, address: `0x${addr.toString(16)}`, text }, null, 2),
        }],
      };
    },
  );

  // ── rename_function ──
  server.tool(
    'rename_function',
    'Rename a function at an address',
    {
      fileId: z.string().describe('ID of the loaded PE file'),
      address: z.union([z.number(), z.string()]).describe('Function address'),
      name: z.string().describe('New name (empty string to remove rename)'),
    },
    async ({ fileId, address, name }) => {
      const af = session.getFile(fileId);
      if (!af) return { content: [{ type: 'text' as const, text: `Error: file "${fileId}" not loaded` }], isError: true };

      const addr = typeof address === 'string' ? parseInt(address, 16) : address;
      if (name === '') {
        session.deleteRename(fileId, addr);
      } else {
        session.setRename(fileId, addr, name);
      }

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({ fileId, address: `0x${addr.toString(16)}`, name }, null, 2),
        }],
      };
    },
  );

  // ── add_bookmark ──
  server.tool(
    'add_bookmark',
    'Toggle a bookmark at an address',
    {
      fileId: z.string().describe('ID of the loaded PE file'),
      address: z.union([z.number(), z.string()]).describe('Address to bookmark'),
      label: z.string().optional().describe('Bookmark label (default "")'),
    },
    async ({ fileId, address, label }) => {
      const af = session.getFile(fileId);
      if (!af) return { content: [{ type: 'text' as const, text: `Error: file "${fileId}" not loaded` }], isError: true };

      const addr = typeof address === 'string' ? parseInt(address, 16) : address;
      const existing = af.bookmarks.find(b => b.address === addr);
      let action: 'added' | 'removed';
      if (existing) {
        session.removeBookmark(fileId, addr);
        action = 'removed';
      } else {
        session.addBookmark(fileId, addr, label ?? '');
        action = 'added';
      }

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({ fileId, address: `0x${addr.toString(16)}`, action }, null, 2),
        }],
      };
    },
  );

  // ── list_comments ──
  server.tool(
    'list_comments',
    'List all annotations (comments, renames, bookmarks) for a file',
    {
      fileId: z.string().describe('ID of the loaded PE file'),
    },
    async ({ fileId }) => {
      const af = session.getFile(fileId);
      if (!af) return { content: [{ type: 'text' as const, text: `Error: file "${fileId}" not loaded` }], isError: true };

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            comments: Object.entries(af.comments).map(([address, text]) => ({ address: `0x${Number(address).toString(16)}`, text })),
            renames: Object.entries(af.renames).map(([address, name]) => ({ address: `0x${Number(address).toString(16)}`, name })),
            bookmarks: af.bookmarks.map(b => ({ address: `0x${b.address.toString(16)}`, label: b.label })),
          }, null, 2),
        }],
      };
    },
  );

  // ── export_analysis ──
  server.tool(
    'export_analysis',
    'Export analysis annotations as ExportSchemaV1 JSON',
    {
      fileId: z.string().describe('ID of the loaded PE file'),
      outputPath: z.string().optional().describe('File path to write JSON to (optional)'),
    },
    async ({ fileId, outputPath }) => {
      const af = session.getFile(fileId);
      if (!af) return { content: [{ type: 'text' as const, text: `Error: file "${fileId}" not loaded` }], isError: true };

      const exported: ExportSchemaV1 = {
        version: 1,
        fileName: af.fileName,
        exportedAt: new Date().toISOString(),
        bookmarks: af.bookmarks,
        renames: af.renames,
        comments: af.comments,
        hexPatches: [],
        functions: af.functions.map(f => ({
          address: f.address,
          name: af.renames[String(f.address)] ?? f.name,
          size: f.size,
        })),
      };

      const json = JSON.stringify(exported, null, 2);
      if (outputPath) {
        writeFileSync(outputPath, json, 'utf-8');
      }

      return {
        content: [{
          type: 'text' as const,
          text: json,
        }],
      };
    },
  );

  // ── import_analysis ──
  server.tool(
    'import_analysis',
    'Import analysis annotations from an ExportSchemaV1 JSON file',
    {
      fileId: z.string().describe('ID of the loaded PE file'),
      inputPath: z.string().describe('Path to ExportSchemaV1 JSON file'),
    },
    async ({ fileId, inputPath }) => {
      const af = session.getFile(fileId);
      if (!af) return { content: [{ type: 'text' as const, text: `Error: file "${fileId}" not loaded` }], isError: true };

      let raw: unknown;
      try {
        raw = JSON.parse(readFileSync(inputPath, 'utf-8'));
      } catch (e) {
        return { content: [{ type: 'text' as const, text: `Error: failed to read/parse "${inputPath}": ${e}` }], isError: true };
      }

      const data = validateImport(raw);
      if (!data) {
        return { content: [{ type: 'text' as const, text: `Error: invalid ExportSchemaV1 format` }], isError: true };
      }

      // Merge renames and comments (new overrides old)
      Object.assign(af.renames, data.renames);
      Object.assign(af.comments, data.comments);

      // Dedup bookmarks by address
      const existingAddrs = new Set(af.bookmarks.map(b => b.address));
      for (const b of data.bookmarks) {
        if (!existingAddrs.has(b.address)) {
          af.bookmarks.push(b);
          existingAddrs.add(b.address);
        }
      }

      session.onAnnotationChange?.(fileId, af);

      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            fileId,
            imported: {
              comments: Object.keys(data.comments).length,
              renames: Object.keys(data.renames).length,
              bookmarks: data.bookmarks.length,
            },
          }, null, 2),
        }],
      };
    },
  );
}

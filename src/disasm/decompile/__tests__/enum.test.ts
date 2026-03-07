import { describe, it, expect } from 'vitest';
import { inferTypes, typeToString, meetTypes, type DecompType } from '../typeInfer';
import type { IRStmt, IRSwitch } from '../ir';
import { irReg, irConst } from '../ir';

describe('Enum Type Inference', () => {
  it('should infer enum from switch with 3+ cases', () => {
    const switchStmt: IRSwitch = {
      kind: 'switch',
      expr: irReg('eax'),
      cases: [
        { values: [1], body: [] },
        { values: [2], body: [] },
        { values: [3], body: [] },
      ],
    };
    const body: IRStmt[] = [switchStmt];
    const ctx = inferTypes(body, new Map());
    const type = ctx.types.get('rax'); // canonicalized
    expect(type).toBeDefined();
    expect(type!.kind).toBe('enum');
    if (type!.kind === 'enum') {
      expect(type!.members.size).toBe(3);
      expect(type!.members.has(1)).toBe(true);
      expect(type!.members.has(2)).toBe(true);
      expect(type!.members.has(3)).toBe(true);
    }
  });

  it('should not infer enum from switch with <3 cases', () => {
    const switchStmt: IRSwitch = {
      kind: 'switch',
      expr: irReg('eax'),
      cases: [
        { values: [1], body: [] },
        { values: [2], body: [] },
      ],
    };
    const body: IRStmt[] = [switchStmt];
    const ctx = inferTypes(body, new Map());
    const type = ctx.types.get('rax');
    expect(type?.kind).not.toBe('enum');
  });

  it('should format enum type name', () => {
    const t: DecompType = { kind: 'enum', name: 'enum_0', members: new Map() };
    expect(typeToString(t)).toBe('enum_0');
  });

  it('meetTypes: enum wins over int', () => {
    const enumType: DecompType = { kind: 'enum', name: 'enum_0', members: new Map([[1, 'VAL_0x1']]) };
    const intType: DecompType = { kind: 'int', size: 4, signed: true };
    expect(meetTypes(enumType, intType).kind).toBe('enum');
    expect(meetTypes(intType, enumType).kind).toBe('enum');
  });

  it('meetTypes: same enum name -> keep', () => {
    const a: DecompType = { kind: 'enum', name: 'enum_0', members: new Map() };
    const b: DecompType = { kind: 'enum', name: 'enum_0', members: new Map() };
    expect(meetTypes(a, b).kind).toBe('enum');
  });

  it('meetTypes: different enum names -> unknown', () => {
    const a: DecompType = { kind: 'enum', name: 'enum_0', members: new Map() };
    const b: DecompType = { kind: 'enum', name: 'enum_1', members: new Map() };
    expect(meetTypes(a, b).kind).toBe('unknown');
  });
});

import { useEffect, useState, type Dispatch } from 'react';
import type { AppAction } from './usePEFile';
import { validateAnnotations, type AnnotationPayload } from '../utils/exportSchema';

const WS_URL = `ws://localhost:${19283}`;
const RECONNECT_DELAY = 3000;

/**
 * Decide what to do with one raw frame from the MCP bridge.
 *
 * Extracted from the socket handler so the decision is testable without a React
 * renderer or a live socket. Returns the validated payload to import, or null
 * for anything that should be ignored — an unparseable frame, a frame for a
 * different binary, or one whose annotations fail validation.
 *
 * Never throws: this is remote input, and a bad frame must not take down the
 * socket handler.
 */
export function parseAnnotationMessage(
  raw: unknown,
  fileName: string,
): AnnotationPayload | null {
  let msg: unknown;
  try {
    msg = JSON.parse(String(raw));
  } catch {
    return null;
  }
  if (typeof msg !== 'object' || msg === null) return null;

  const envelope = msg as { type?: unknown; fileName?: unknown };
  if (envelope.type !== 'annotations') return null;
  if (envelope.fileName !== fileName) return null;

  // Remote input over a WebSocket — validate the shape (and coerce the string
  // keys to numbers) before it reaches app state.
  return validateAnnotations(msg);
}

export function useMcpSync(
  fileName: string | null,
  dispatch: Dispatch<AppAction>,
): 'connected' | 'disconnected' {
  const [status, setStatus] = useState<'connected' | 'disconnected'>('disconnected');

  useEffect(() => {
    if (!fileName) return;
    // Captured so the narrowing survives into the nested socket callbacks.
    const activeFile = fileName;

    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let disposed = false;

    function connect() {
      if (disposed) return;
      ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        if (!disposed) setStatus('connected');
      };

      ws.onmessage = (ev) => {
        if (disposed) return;
        const data = parseAnnotationMessage(ev.data, activeFile);
        if (!data) return;

        dispatch({
          type: 'IMPORT_ANNOTATIONS',
          bookmarks: data.bookmarks,
          renames: data.renames,
          comments: data.comments,
          // Background sync: clears the redo branch (so a stale redo cannot
          // revert what just arrived) without consuming an undo slot.
          source: 'mcp',
        });
      };

      ws.onclose = () => {
        if (disposed) return;
        setStatus('disconnected');
        reconnectTimer = setTimeout(connect, RECONNECT_DELAY);
      };

      ws.onerror = () => {
        // onclose will fire after onerror, triggering reconnect
        ws?.close();
      };
    }

    connect();

    return () => {
      disposed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [fileName, dispatch]);

  return status;
}

import { useEffect, useState, type Dispatch } from 'react';
import type { AppAction } from './usePEFile';

const WS_URL = `ws://localhost:${19283}`;
const RECONNECT_DELAY = 3000;

export function useMcpSync(
  fileName: string | null,
  dispatch: Dispatch<AppAction>,
): 'connected' | 'disconnected' {
  const [status, setStatus] = useState<'connected' | 'disconnected'>('disconnected');

  useEffect(() => {
    if (!fileName) return;

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
        try {
          const msg = JSON.parse(String(ev.data));
          if (msg.type !== 'annotations' || msg.fileName !== fileName) return;

          // Convert string-keyed objects to number-keyed
          const renames: Record<number, string> = Object.fromEntries(
            Object.entries(msg.renames ?? {} as Record<string, string>).map(([k, v]) => [Number(k), v as string]),
          );
          const comments: Record<number, string> = Object.fromEntries(
            Object.entries(msg.comments ?? {} as Record<string, string>).map(([k, v]) => [Number(k), v as string]),
          );

          dispatch({
            type: 'IMPORT_ANNOTATIONS',
            bookmarks: msg.bookmarks ?? [],
            renames,
            comments,
          });
        } catch { /* ignore malformed messages */ }
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

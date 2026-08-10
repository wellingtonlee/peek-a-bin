import { useEffect, useState, type Dispatch } from 'react';
import type { AppAction } from './usePEFile';
import { validateAnnotations } from '../utils/exportSchema';

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

          // Remote input over a WebSocket — validate the shape (and coerce the
          // string keys to numbers) before dispatching into app state.
          const data = validateAnnotations(msg);
          if (!data) {
            console.warn('[peek-a-bin] ignoring malformed annotation message from MCP bridge');
            return;
          }

          dispatch({
            type: 'IMPORT_ANNOTATIONS',
            bookmarks: data.bookmarks,
            renames: data.renames,
            comments: data.comments,
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

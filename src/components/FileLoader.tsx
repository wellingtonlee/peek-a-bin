import { useState, useCallback, useRef } from "react";

interface FileLoaderProps {
  onFile: (buffer: ArrayBuffer) => void;
  loading: boolean;
  error: string | null;
}

export function FileLoader({ onFile, loading, error }: FileLoaderProps) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(
    (file: File) => {
      const reader = new FileReader();
      reader.onload = () => {
        if (reader.result instanceof ArrayBuffer) {
          onFile(reader.result);
        }
      };
      reader.readAsArrayBuffer(file);
    },
    [onFile],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(true);
  }, []);

  const onDragLeave = useCallback(() => setDragging(false), []);

  const onChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  return (
    <div className="flex items-center justify-center h-screen bg-gray-950">
      <div
        className={`flex flex-col items-center justify-center w-[600px] h-[350px] border-2 border-dashed rounded-xl cursor-pointer transition-colors ${
          dragging
            ? "border-blue-400 bg-blue-400/10"
            : "border-gray-600 hover:border-gray-400"
        }`}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onClick={() => inputRef.current?.click()}
      >
        <svg
          className="w-16 h-16 mb-4 text-gray-500"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M9 8h6m-5 0a3 3 0 110 6H9l3 3m-3-3h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V17a2 2 0 01-2 2z"
          />
        </svg>
        <p className="text-xl text-gray-300 mb-2">
          {loading ? "Parsing..." : "Drop a PE file here"}
        </p>
        <p className="text-sm text-gray-500">
          or click to browse (.exe, .dll)
        </p>
        {error && (
          <p className="mt-4 text-sm text-red-400 max-w-md text-center">
            {error}
          </p>
        )}
        <input
          ref={inputRef}
          type="file"
          accept=".exe,.dll,.sys,.ocx"
          onChange={onChange}
          className="hidden"
        />
      </div>
    </div>
  );
}

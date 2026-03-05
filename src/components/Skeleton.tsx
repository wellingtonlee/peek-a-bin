export function Skeleton({ width = "100%", height = "12px" }: { width?: string; height?: string }) {
  return (
    <div
      className="skeleton-shimmer rounded"
      style={{ width, height }}
    />
  );
}

export function SkeletonRows({ count = 10 }: { count?: number }) {
  return (
    <div className="space-y-1.5 p-2">
      {Array.from({ length: count }, (_, i) => (
        <Skeleton
          key={i}
          width={`${60 + (i * 17) % 35}%`}
          height="14px"
        />
      ))}
    </div>
  );
}

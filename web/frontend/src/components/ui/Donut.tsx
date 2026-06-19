// Dependency-free SVG donut. Segments are stroked arcs on a single ring; colors
// are passed as CSS values (so they can be --sx-* tokens and recolor per theme).
export type DonutSegment = { label: string; value: number; color: string }

export function Donut({ segments, size = 168, thickness = 18 }: {
  segments: DonutSegment[]
  size?: number
  thickness?: number
}) {
  const r = (size - thickness) / 2
  const circumference = 2 * Math.PI * r
  const center = size / 2
  const sum = segments.reduce((a, s) => a + s.value, 0)

  let offset = 0
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90" role="img" aria-label="Distribution chart">
      {/* track */}
      <circle cx={center} cy={center} r={r} fill="none" stroke="var(--sx-surface-2)" strokeWidth={thickness} />
      {sum > 0 && segments.map((s, i) => {
        if (s.value <= 0) return null
        const dash = (s.value / sum) * circumference
        const seg = (
          <circle
            key={i}
            cx={center}
            cy={center}
            r={r}
            fill="none"
            stroke={s.color}
            strokeWidth={thickness}
            strokeDasharray={`${dash} ${circumference - dash}`}
            strokeDashoffset={-offset}
          />
        )
        offset += dash
        return seg
      })}
    </svg>
  )
}

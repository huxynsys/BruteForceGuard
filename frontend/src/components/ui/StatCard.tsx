interface StatCardProps {
  label: string
  value: number | string
  hint?: string
}

export default function StatCard({ label, value, hint }: StatCardProps) {
  return (
    <div className="neo-card neo-card--hover">
      <div className="stat-label">{label}</div>
      <div className="stat-value">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      {hint && <div className="stat-sub">{hint}</div>}
    </div>
  )
}

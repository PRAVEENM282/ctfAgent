interface ProgressProps {
  value: number;
  label: string;
}

export function Progress({ value, label }: ProgressProps) {
  return (
    <div className="progress-track" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={value} aria-label={label}>
      <span className="progress-value" style={{ width: `${value}%` }} />
    </div>
  );
}

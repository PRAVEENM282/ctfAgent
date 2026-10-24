import { Button } from "./ui/Button";
import { Card, CardBody } from "./ui/Card";

interface LabErrorProps {
  message: string;
  canRetry: boolean;
  onRetry: () => void;
}

export function LabError({ message, canRetry, onRetry }: LabErrorProps) {
  return (
    <Card className="error-card" role="alert">
      <CardBody className="error-content">
        <div className="error-icon" aria-hidden="true">!</div>
        <div>
          <strong>Something needs attention</strong>
          <p>{message}</p>
        </div>
        {canRetry && <Button variant="secondary" onClick={onRetry}>Try again</Button>}
      </CardBody>
    </Card>
  );
}

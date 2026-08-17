import type { ScanStep } from "@/lib/types";
import { CheckIcon, XIcon } from "./Icons";

export function Pipeline({ steps }: { steps: ScanStep[] }) {
  return (
    <div className="pipeline" aria-label="Scan pipeline">
      {steps.map((step, index) => (
        <div className={`pipeline-step ${step.status}`} key={step.step_key}>
          <div className="pipeline-node">
            {step.status === "completed" ? <CheckIcon /> : step.status === "failed" ? <XIcon /> : <span>{step.position}</span>}
          </div>
          {index < steps.length - 1 && <div className="pipeline-line"><span /></div>}
          <div className="pipeline-copy">
            <strong>{step.name}</strong>
            <small>{step.message || (step.status === "pending" ? "Waiting" : step.status)}</small>
          </div>
        </div>
      ))}
    </div>
  );
}

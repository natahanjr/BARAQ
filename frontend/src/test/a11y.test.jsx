import { render } from "@testing-library/react";
import { axe } from "jest-axe";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import RiskBadge from "../components/RiskBadge.jsx";
import MetricCard from "../components/ui/MetricCard.jsx";

describe("a11y smoke (axe-core)", () => {
  it("SeverityBadge renders accessibly", async () => {
    const { container } = render(<SeverityBadge severity="critical" />);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("StatusBadge renders accessibly", async () => {
    const { container } = render(<StatusBadge status="open" />);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("RiskBadge renders accessibly", async () => {
    const { container } = render(<RiskBadge level="HIGH" score={42} />);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("MetricCard renders accessibly", async () => {
    const { container } = render(
      <MetricCard label="Events" value={128} icon={() => null} accent="cyan" />
    );
    expect(await axe(container)).toHaveNoViolations();
  });
});

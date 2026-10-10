import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SAMPLE_ALERT, SAMPLE_ALERT_WORKFLOW, createMockApi } from "../test/fixtures";
import { AlertDetail } from "./alert-detail";


describe("AlertDetail Windows event context", () => {
  it("renders event identity and untrusted values as text", () => {
    const { container } = render(
      <AlertDetail
        workflow={{
          ...SAMPLE_ALERT_WORKFLOW,
          alert: {
            ...SAMPLE_ALERT,
            user: "<script>synthetic-user</script>",
            windows: {
              event_id: "4625",
              channel: "Security",
              provider: "Microsoft-Windows-Security-Auditing",
              computer: "WIN-392LNNLLAT3",
            },
          },
        }}
        api={createMockApi()}
        onClose={() => undefined}
      />,
    );
    const detail = screen.getByRole("complementary", { name: "Alert detail" });
    expect(within(detail).getByText("4625")).toBeInTheDocument();
    expect(within(detail).getByText("Microsoft-Windows-Security-Auditing")).toBeInTheDocument();
    expect(within(detail).getByText("<script>synthetic-user</script>")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });
});

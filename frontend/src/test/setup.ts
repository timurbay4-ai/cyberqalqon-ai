import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach } from "vitest";

// Route chunks are transformed on demand in Vitest. Keep async DOM assertions
// bounded but allow a cold transform to finish on the supported low-resource lab.
configure({ asyncUtilTimeout: 5_000 });

afterEach(() => {
  cleanup();
  window.history.replaceState({}, "", "/");
});

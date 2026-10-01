/**
 * Vitest setup.
 *
 * `fetch` is stubbed per test (see `src/test/helpers.tsx`); anything reaching the
 * real network from a unit test is a bug, so the default stub throws loudly
 * rather than hanging on a connection attempt.
 *
 * Known noise: these tests emit React "update was not wrapped in act(...)"
 * warnings. They come from the data hooks' promise chains settling after
 * `userEvent`'s own act scope closes -- a reload fired by a mutation handler.
 * The assertions are unaffected (every one waits on real state via `waitFor` or
 * `findBy*`), and the warnings are deliberately NOT silenced: suppressing them
 * would also hide a genuinely un-acted update. Reducing them properly means
 * moving the hooks onto a library with act-aware scheduling, which is a bigger
 * change than this test suite warrants.
 */
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";
import { useAuthStore } from "../store/authStore";

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      throw new Error(`Unstubbed fetch to ${String(input)} -- stub it with mockApi() in the test.`);
    }),
  );
  // Both halves matter. Clearing localStorage alone is not enough: the Zustand
  // store holds its state in memory, so a previous test's session would still
  // satisfy the next test's auth guard and an "unauthenticated visitor is
  // redirected" test would pass for the wrong reason -- or, as it did here, fail
  // confusingly.
  window.localStorage.clear();
  useAuthStore.getState().logout();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

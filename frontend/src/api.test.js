import { afterEach, describe, expect, it, vi } from "vitest";

import { apiRequest } from "./api.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiRequest", () => {
  it("formats validation errors for display", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            detail: [{ msg: "Enter a valid email address." }],
          }),
          { status: 422, headers: { "Content-Type": "application/json" } },
        ),
      ),
    );

    await expect(apiRequest("/api/auth/register")).rejects.toMatchObject({
      message: "Enter a valid email address.",
      status: 422,
    });
  });
});

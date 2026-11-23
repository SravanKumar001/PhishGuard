import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { App } from "./App.jsx";

describe("App", () => {
  it("renders the product name and purpose", () => {
    const markup = renderToStaticMarkup(<App />);

    expect(markup).toContain('aria-label="PhishGuard"');
    expect(markup).toContain("secure session");
  });
});

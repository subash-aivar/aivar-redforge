import "@testing-library/jest-dom/vitest";

// jsdom doesn't implement matchMedia. Default to "matches: true" (desktop)
// so every existing test keeps its current desktop-shaped behavior unless
// a test explicitly overrides `window.matchMedia` to simulate a narrow
// viewport (see NavigationShell.test.tsx's mobile-drawer tests).
if (typeof window !== "undefined" && typeof window.matchMedia !== "function") {
  window.matchMedia = (query: string) =>
    ({
      matches: true,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList;
}

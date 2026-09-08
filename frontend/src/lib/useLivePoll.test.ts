import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { renderHook } from "@testing-library/react";
import { useLivePoll } from "@/lib/useLivePoll";

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("useLivePoll", () => {
  it("calls the function immediately and then on every interval tick", () => {
    const fn = vi.fn();
    renderHook(() => useLivePoll(fn, 1000));

    expect(fn).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(3000);
    expect(fn).toHaveBeenCalledTimes(4);
  });

  it("does not poll when disabled", () => {
    const fn = vi.fn();
    renderHook(() => useLivePoll(fn, 1000, false));

    vi.advanceTimersByTime(5000);
    expect(fn).not.toHaveBeenCalled();
  });

  it("clears the interval on unmount — no leaked timers", () => {
    const fn = vi.fn();
    const { unmount } = renderHook(() => useLivePoll(fn, 1000));
    unmount();
    const callsAtUnmount = fn.mock.calls.length;

    vi.advanceTimersByTime(5000);
    expect(fn).toHaveBeenCalledTimes(callsAtUnmount);
  });

  it("always invokes the latest closure, not a stale one captured at mount", () => {
    let value = "first";
    const fn = vi.fn(() => value);
    const { rerender } = renderHook(({ f }) => useLivePoll(f, 1000), {
      initialProps: { f: fn },
    });
    value = "second";
    rerender({ f: fn });

    vi.advanceTimersByTime(1000);
    expect(fn).toHaveLastReturnedWith("second");
  });
});

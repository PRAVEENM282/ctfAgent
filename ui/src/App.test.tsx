import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import * as api from "./api";
import type { LabSnapshot } from "./types";

vi.mock("./api", () => ({
  createLab: vi.fn(),
  getLab: vi.fn(),
  publishLab: vi.fn(),
  stopLab: vi.fn(),
}));

const createSnapshot = (overrides: Partial<LabSnapshot> = {}): LabSnapshot => ({
  run_id: "run-abc123def456",
  state: "created",
  phase: "queued",
  message: "Lab creation queued.",
  can_publish: false,
  can_stop: true,
  cleanup_confirmed: false,
  public_url: null,
  public_access_warning: null,
  error_code: null,
  ...overrides,
});

describe("VulnForge dashboard", () => {
  afterEach(() => cleanup());
  beforeEach(() => vi.clearAllMocks());

  it("requires a description and starts a queued lab", async () => {
    vi.mocked(api.createLab).mockResolvedValue(createSnapshot());
    const user = userEvent.setup();
    render(<App />);

    expect(screen.getByRole("heading", { name: /build a vulnerable site/i })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /generate lab/i }));
    expect(screen.getByRole("alert")).toHaveTextContent(/describe the site/i);

    await user.type(screen.getByLabelText(/site description/i), "Create a search lesson.");
    await user.click(screen.getByRole("button", { name: /generate lab/i }));

    await waitFor(() => expect(api.createLab).toHaveBeenCalledWith("Create a search lesson."));
    expect(screen.getByText(/lab creation queued/i)).toBeInTheDocument();
  });

  it("publishes only after verification and confirms cleanup", async () => {
    vi.mocked(api.createLab).mockResolvedValue(createSnapshot({ phase: "awaiting_publication", message: "Private verification passed. Publish the lab when ready." }));
    vi.mocked(api.publishLab).mockResolvedValue(createSnapshot({ state: "succeeded", phase: "published", message: "Lab published.", public_url: "https://opaque.celesto.dev/lab", public_access_warning: "Published URLs are public and unauthenticated." }));
    vi.mocked(api.stopLab).mockResolvedValue(createSnapshot({ state: "deleted", phase: "cleaned_up", message: "The public route was revoked and the sandbox was deleted.", can_stop: false, cleanup_confirmed: true }));
    const user = userEvent.setup();
    render(<App />);

    await user.type(screen.getByLabelText(/site description/i), "Create a search lesson.");
    await user.click(screen.getByRole("button", { name: /generate lab/i }));
    expect(await screen.findByRole("button", { name: /publish lab/i })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /publish lab/i }));
    expect(await screen.findByText("https://opaque.celesto.dev/lab")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /stop sandbox/i }));
    expect(await screen.findByText(/cleanup confirmed/i)).toBeInTheDocument();
  });

  it("shows a safe failure state and only enables retry after cleanup", async () => {
    vi.mocked(api.createLab).mockResolvedValue(
      createSnapshot({
        state: "failed",
        phase: "failed",
        message: "The model provider could not complete generation.",
        can_stop: false,
        cleanup_confirmed: true,
        error_code: "provider_request_failed",
      }),
    );
    const user = userEvent.setup();
    render(<App />);

    await user.type(screen.getByLabelText(/site description/i), "Create a search lesson.");
    await user.click(screen.getByRole("button", { name: /generate lab/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/model provider could not complete/i);
    expect(screen.getByRole("button", { name: /try again/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /generate lab/i })).toBeEnabled();
  });
});

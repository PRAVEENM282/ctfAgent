import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import * as api from "./api";
import type { AppConfig, LabSnapshot } from "./types";

vi.mock("./api", () => ({
  getConfig: vi.fn(),
  getRuns: vi.fn(),
  getCommands: vi.fn(),
  createLab: vi.fn(),
  getLab: vi.fn(),
  approvePublish: vi.fn(),
  destroyLab: vi.fn(),
  submitFlag: vi.fn(),
  setAccessCode: vi.fn(),
  subscribeLab: vi.fn(() => () => undefined),
}));

const config: AppConfig = {
  celesto_provider: "local",
  celesto_backend: "qemu",
  llm_provider: "ollama",
  llm_model: "qwen2.5-coder:1.5b",
  max_active_labs: 1,
  sandbox_ttl_minutes: 15,
  access_code_required: false,
  valid: true,
  errors: [],
};

const snapshot = (overrides: Partial<LabSnapshot> = {}): LabSnapshot => ({
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
  sandbox_name: "sbx-0123456789ab",
  model: "qwen2.5-coder:1.5b",
  boot_to_ready_s: 0.2,
  egress_status: "blocked",
  llm_fallback_used: false,
  local_preview: true,
  solved: false,
  flag_submissions: 0,
  steps: [],
  hints: [],
  ...overrides,
});

describe("VulnForge dashboard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getConfig).mockResolvedValue(config);
  });
  afterEach(() => cleanup());

  it("shows the active Celesto and LLM mode from config", async () => {
    render(<App />);
    expect(await screen.findByText(/Celesto: local/i)).toBeInTheDocument();
    expect(screen.getByText(/LLM: ollama/i)).toBeInTheDocument();
  });

  it("requires a description and queues a lab", async () => {
    vi.mocked(api.createLab).mockResolvedValue(snapshot());
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText(/Celesto: local/i);

    await user.click(screen.getByRole("button", { name: /generate lab/i }));
    expect(await screen.findByText(/describe the site you want/i)).toBeInTheDocument();

    await user.type(screen.getByLabelText(/site description/i), "A bookstore search page.");
    await user.click(screen.getByRole("button", { name: /generate lab/i }));
    await waitFor(() =>
      expect(api.createLab).toHaveBeenCalledWith("A bookstore search page.", "single", ["sql_injection"]),
    );
  });
});

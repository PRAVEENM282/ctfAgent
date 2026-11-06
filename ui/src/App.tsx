import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  Clock,
  ExternalLink,
  Flag,
  Loader2,
  Lock,
  Server,
  ShieldCheck,
  Trash2,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import {
  approvePublish,
  createLab,
  destroyLab,
  getCommands,
  getConfig,
  getLab,
  getRuns,
  setAccessCode,
  submitFlag,
  subscribeLab,
} from "./api";
import {
  ApiError,
  VULNERABILITIES,
  type AppConfig,
  type CommandRow,
  type LabSnapshot,
  type LabStep,
  type RunRow,
  type VulnerabilityId,
  type VulnerabilityMode,
} from "./types";
import { Alert, AlertDescription, AlertTitle } from "./components/ui/alert";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "./components/ui/dialog";
import { Input } from "./components/ui/input";
import { Label } from "./components/ui/label";
import { Progress } from "./components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./components/ui/select";
import { Skeleton } from "./components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";
import { Textarea } from "./components/ui/textarea";
import { Toaster } from "./components/ui/sonner";

const TERMINAL_PHASES = new Set(["cleaned_up", "failed"]);

function stateBadgeVariant(state: string) {
  if (state === "succeeded") return "success" as const;
  if (state === "failed" || state === "deleted") return "destructive" as const;
  if (state === "running" || state === "ready") return "default" as const;
  return "secondary" as const;
}

function StepIcon({ status }: { status: LabStep["status"] }) {
  if (status === "ok") return <CheckCircle2 className="text-success" />;
  if (status === "failed") return <XCircle className="text-destructive" />;
  if (status === "running") return <Loader2 className="animate-spin text-primary" />;
  if (status === "skipped") return <CircleDashed className="text-muted-foreground opacity-50" />;
  return <CircleDashed className="text-muted-foreground" />;
}

function ConfigBadges({ config }: { config: AppConfig | null }) {
  if (!config) return <Skeleton className="h-6 w-64" />;
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Badge variant="outline" className="gap-1">
        <Server className="h-3 w-3" /> Celesto: {config.celesto_provider}
      </Badge>
      <Badge variant="outline">LLM: {config.llm_provider}</Badge>
      <Badge variant="outline">{config.llm_model || "model unset"}</Badge>
      <Badge variant={config.valid ? "success" : "destructive"}>
        {config.valid ? "config ok" : "config invalid"}
      </Badge>
      {config.access_code_required && (
        <Badge variant="warning" className="gap-1">
          <Lock className="h-3 w-3" /> access code
        </Badge>
      )}
    </div>
  );
}

export default function App() {
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [tab, setTab] = useState("create");

  // Create form
  const [description, setDescription] = useState("");
  const [mode, setMode] = useState<VulnerabilityMode>("single");
  const [profile, setProfile] = useState<VulnerabilityId>("sql_injection");
  const [bundle, setBundle] = useState<VulnerabilityId[]>(["sql_injection", "reflected_xss"]);
  const [accessCode, setAccessCodeState] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Run tracking
  const [snapshot, setSnapshot] = useState<LabSnapshot | null>(null);
  const [approvalOpen, setApprovalOpen] = useState(false);
  const [approvedThisRun, setApprovedThisRun] = useState(false);
  const [flag, setFlag] = useState("");
  const [ttlLeft, setTtlLeft] = useState<number | null>(null);

  // Ledger + audit
  const [runs, setRuns] = useState<RunRow[] | null>(null);
  const [commands, setCommands] = useState<CommandRow[] | null>(null);

  const runId = snapshot?.run_id ?? null;
  const pollRef = useRef<number | null>(null);

  useEffect(() => {
    getConfig().then(setConfig).catch(() => setConfig(null));
  }, []);

  const refreshSnapshot = useCallback(async (id: string) => {
    try {
      setSnapshot(await getLab(id));
    } catch {
      /* transient; SSE or next poll recovers */
    }
  }, []);

  // SSE + polling fallback for the active run.
  useEffect(() => {
    if (!runId) return;
    const unsub = subscribeLab(runId, (snap) => setSnapshot(snap));
    pollRef.current = window.setInterval(() => refreshSnapshot(runId), 2500);
    return () => {
      unsub();
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, [runId, refreshSnapshot]);

  // Open the approval dialog when private verification passes.
  useEffect(() => {
    if (snapshot?.phase === "awaiting_publication" && !approvedThisRun) {
      setApprovalOpen(true);
    }
  }, [snapshot?.phase, approvedThisRun]);

  // TTL countdown once a lab is published.
  useEffect(() => {
    if (snapshot?.phase !== "published" || !config) {
      setTtlLeft(null);
      return;
    }
    setTtlLeft(config.sandbox_ttl_minutes * 60);
    const timer = window.setInterval(() => {
      setTtlLeft((prev) => (prev === null ? null : Math.max(0, prev - 1)));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [snapshot?.phase, config]);

  const selectedVulns = mode === "single" ? [profile] : bundle;

  async function handleCreate() {
    setFormError(null);
    if (!description.trim()) {
      setFormError("Describe the site you want the agent to build.");
      return;
    }
    if (mode === "bundle" && bundle.length < 2) {
      setFormError("Bundle mode needs at least two vulnerability profiles.");
      return;
    }
    if (config?.access_code_required && !accessCode.trim()) {
      setFormError("This server requires an access code to create labs.");
      return;
    }
    setAccessCode(accessCode);
    setBusy(true);
    setApprovedThisRun(false);
    try {
      const snap = await createLab(description.trim(), mode, selectedVulns);
      setSnapshot(snap);
      setTab("run");
      toast.success("Lab queued", { description: `Sandbox will be created for ${snap.run_id}.` });
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "Could not start the lab.";
      setFormError(message);
      toast.error("Could not start the lab", { description: message });
    } finally {
      setBusy(false);
    }
  }

  async function handleApprove() {
    if (!runId) return;
    setApprovedThisRun(true);
    setApprovalOpen(false);
    try {
      setSnapshot(await approvePublish(runId));
      toast.success("Publishing the verified lab.");
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "Publication failed.";
      toast.error("Publication failed", { description: message });
      refreshSnapshot(runId);
    }
  }

  async function handleDestroy() {
    if (!runId) return;
    try {
      setSnapshot(await destroyLab(runId));
      toast.success("Sandbox torn down.");
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "Teardown failed.";
      toast.error("Teardown failed", { description: message });
    }
  }

  async function handleSubmitFlag() {
    if (!runId || !flag.trim()) return;
    try {
      const result = await submitFlag(runId, flag.trim());
      if (result.correct) {
        toast.success("Correct flag — lab solved!");
        refreshSnapshot(runId);
      } else {
        toast.error("Incorrect flag", { description: `Attempt ${result.submissions}.` });
      }
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "Could not submit the flag.";
      toast.error(message);
    }
  }

  async function loadLedger() {
    try {
      setRuns(await getRuns());
    } catch {
      setRuns([]);
    }
  }
  async function loadCommands() {
    try {
      setCommands(await getCommands());
    } catch {
      setCommands([]);
    }
  }

  useEffect(() => {
    if (tab === "ledger") loadLedger();
    if (tab === "audit") loadCommands();
  }, [tab]);

  const progressValue = useMemo(() => {
    if (!snapshot?.steps?.length) return 0;
    const done = snapshot.steps.filter((s) => s.status === "ok").length;
    return Math.round((done / snapshot.steps.length) * 100);
  }, [snapshot]);

  return (
    <div className="min-h-screen">
      <Toaster position="top-right" richColors />
      <div className="container py-8">
        <header className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
              <ShieldCheck className="h-6 w-6 text-primary" /> VulnForge
            </h1>
            <p className="mt-1 max-w-xl text-sm text-muted-foreground">
              Generate short-lived, intentionally vulnerable CTF labs inside isolated Celesto
              sandboxes. Every exploit is verified privately before a lab is ever exposed.
            </p>
          </div>
          <ConfigBadges config={config} />
        </header>

        {config && !config.valid && (
          <Alert variant="warning" className="mb-6">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Configuration needs attention</AlertTitle>
            <AlertDescription>
              <ul className="list-disc pl-4">
                {config.errors.map((err) => (
                  <li key={err}>{err}</li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        )}

        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="create">Create Lab</TabsTrigger>
            <TabsTrigger value="run">Live Run</TabsTrigger>
            <TabsTrigger value="ledger">Ledger</TabsTrigger>
            <TabsTrigger value="audit">Command Audit</TabsTrigger>
          </TabsList>

          {/* --- Create Lab --- */}
          <TabsContent value="create">
            <Card>
              <CardHeader>
                <CardTitle>Create a lab</CardTitle>
                <CardDescription>
                  Describe the site, choose a vulnerability profile or a bundle, and the agent will
                  build and verify it in a fresh sandbox.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="space-y-2">
                  <Label htmlFor="description">Site description</Label>
                  <Textarea
                    id="description"
                    placeholder="e.g. A product search page for an online bookstore."
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                  />
                </div>

                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="mode">Mode</Label>
                    <Select value={mode} onValueChange={(v) => setMode(v as VulnerabilityMode)}>
                      <SelectTrigger id="mode" aria-label="vulnerability mode">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="single">Single profile</SelectItem>
                        <SelectItem value="bundle">Bundle (2+ profiles)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {mode === "single" ? (
                    <div className="space-y-2">
                      <Label htmlFor="profile">Vulnerability profile</Label>
                      <Select value={profile} onValueChange={(v) => setProfile(v as VulnerabilityId)}>
                        <SelectTrigger id="profile" aria-label="vulnerability profile">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {VULNERABILITIES.map((v) => (
                            <SelectItem key={v.id} value={v.id}>
                              {v.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <Label>Profiles in bundle</Label>
                      <div className="flex flex-wrap gap-2">
                        {VULNERABILITIES.map((v) => {
                          const on = bundle.includes(v.id);
                          return (
                            <button
                              key={v.id}
                              type="button"
                              aria-pressed={on}
                              aria-label={v.label}
                              onClick={() =>
                                setBundle((prev) =>
                                  prev.includes(v.id)
                                    ? prev.filter((x) => x !== v.id)
                                    : [...prev, v.id],
                                )
                              }
                              className={
                                "rounded-full border px-3 py-1 text-xs transition-colors " +
                                (on
                                  ? "border-primary bg-primary/15 text-primary"
                                  : "border-border text-muted-foreground hover:text-foreground")
                              }
                            >
                              {v.label}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>

                {config?.access_code_required && (
                  <div className="space-y-2">
                    <Label htmlFor="access">Access code</Label>
                    <Input
                      id="access"
                      type="password"
                      value={accessCode}
                      onChange={(e) => setAccessCodeState(e.target.value)}
                      placeholder="Required by this server"
                    />
                  </div>
                )}

                {formError && (
                  <Alert variant="destructive">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>{formError}</AlertDescription>
                  </Alert>
                )}

                <Button onClick={handleCreate} disabled={busy}>
                  {busy && <Loader2 className="animate-spin" />} Generate lab
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* --- Live Run --- */}
          <TabsContent value="run">
            {!snapshot ? (
              <Card>
                <CardContent className="py-10 text-center text-sm text-muted-foreground">
                  No active lab yet. Start one from the Create Lab tab.
                </CardContent>
              </Card>
            ) : (
              <div className="grid gap-4 lg:grid-cols-5">
                <Card className="lg:col-span-3">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle>Step timeline</CardTitle>
                      <Badge variant={stateBadgeVariant(snapshot.state)}>{snapshot.state}</Badge>
                    </div>
                    <CardDescription>{snapshot.message}</CardDescription>
                    <Progress value={progressValue} className="mt-2" />
                  </CardHeader>
                  <CardContent>
                    <ol className="space-y-2">
                      {snapshot.steps.map((step, i) => (
                        <li key={step.key} className="flex items-center gap-3 text-sm">
                          <span className="flex h-5 w-5 items-center justify-center">
                            <StepIcon status={step.status} />
                          </span>
                          <span className="w-5 text-xs text-muted-foreground">{i + 1}</span>
                          <span
                            className={
                              step.status === "failed"
                                ? "text-destructive"
                                : step.status === "ok"
                                ? "text-foreground"
                                : "text-muted-foreground"
                            }
                          >
                            {step.label}
                          </span>
                        </li>
                      ))}
                    </ol>
                  </CardContent>
                </Card>

                <div className="space-y-4 lg:col-span-2">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base">Sandbox</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2 text-sm">
                      <Detail label="Name" value={snapshot.sandbox_name ?? "—"} mono />
                      <Detail
                        label="Boot to ready"
                        value={snapshot.boot_to_ready_s != null ? `${snapshot.boot_to_ready_s.toFixed(1)}s` : "—"}
                      />
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Egress</span>
                        <Badge variant={snapshot.egress_status === "blocked" ? "success" : "secondary"}>
                          {snapshot.egress_status ?? "pending"}
                        </Badge>
                      </div>
                      <Detail label="Model" value={snapshot.model ?? "—"} mono />
                      {snapshot.llm_fallback_used && (
                        <Badge variant="warning" className="mt-1">LLM fallback used (vetted template)</Badge>
                      )}
                    </CardContent>
                  </Card>

                  {snapshot.phase === "published" && (
                    <LabReady
                      snapshot={snapshot}
                      ttlLeft={ttlLeft}
                      flag={flag}
                      setFlag={setFlag}
                      onSubmitFlag={handleSubmitFlag}
                      onDestroy={handleDestroy}
                    />
                  )}

                  {snapshot.can_stop && snapshot.phase !== "published" && (
                    <Button variant="outline" onClick={handleDestroy} className="w-full">
                      <Trash2 /> Destroy sandbox
                    </Button>
                  )}

                  {snapshot.phase === "failed" && (
                    <Alert variant="destructive">
                      <AlertTriangle className="h-4 w-4" />
                      <AlertTitle>Lab failed</AlertTitle>
                      <AlertDescription>
                        {snapshot.message}
                        {snapshot.cleanup_confirmed && " Cleanup confirmed."}
                      </AlertDescription>
                    </Alert>
                  )}
                  {snapshot.phase === "cleaned_up" && (
                    <Alert variant="success">
                      <CheckCircle2 className="h-4 w-4" />
                      <AlertTitle>Cleanup confirmed</AlertTitle>
                      <AlertDescription>The route was revoked and the sandbox deleted.</AlertDescription>
                    </Alert>
                  )}
                </div>
              </div>
            )}
          </TabsContent>

          {/* --- Ledger --- */}
          <TabsContent value="ledger">
            <Card>
              <CardHeader>
                <CardTitle>Run ledger</CardTitle>
                <CardDescription>Every run persisted to Postgres.</CardDescription>
              </CardHeader>
              <CardContent>
                {runs === null ? (
                  <Skeleton className="h-32 w-full" />
                ) : runs.length === 0 ? (
                  <p className="py-6 text-center text-sm text-muted-foreground">No runs yet.</p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Run</TableHead>
                        <TableHead>Sandbox</TableHead>
                        <TableHead>Problem</TableHead>
                        <TableHead>State</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {runs.map((row) => (
                        <TableRow key={row.run_id}>
                          <TableCell className="font-mono text-xs">{row.run_id}</TableCell>
                          <TableCell className="font-mono text-xs">{row.sandbox_name}</TableCell>
                          <TableCell className="text-xs">{row.problem_id ?? "—"}</TableCell>
                          <TableCell>
                            <Badge variant={stateBadgeVariant(row.state)}>{row.state}</Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* --- Command Audit --- */}
          <TabsContent value="audit">
            <Card>
              <CardHeader>
                <CardTitle>Command audit</CardTitle>
                <CardDescription>
                  Allow/block decisions from logs/commands.jsonl — every command targets the Celesto
                  sandbox, never the host.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {commands === null ? (
                  <Skeleton className="h-32 w-full" />
                ) : commands.length === 0 ? (
                  <p className="py-6 text-center text-sm text-muted-foreground">No commands logged yet.</p>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Decision</TableHead>
                        <TableHead>Target</TableHead>
                        <TableHead>Command</TableHead>
                        <TableHead>Reason</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {commands.slice(0, 200).map((row, i) => (
                        <TableRow key={i}>
                          <TableCell>
                            <Badge variant={row.decision === "allow" ? "success" : "destructive"}>
                              {row.decision}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs">{row.execution_target}</TableCell>
                          <TableCell className="max-w-[320px] truncate font-mono text-xs">
                            {row.command_summary ?? row.command ?? "—"}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {row.block_reason ?? "—"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>

      {/* --- Approval gate --- */}
      <Dialog open={approvalOpen} onOpenChange={setApprovalOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-success" /> Verified exploit passed
            </DialogTitle>
            <DialogDescription>
              Private verification confirmed the exploit works and benign requests stay clean.
              Publish the {snapshot?.local_preview ? "local preview" : "public"} port so students can
              attack it?
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setApprovalOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleApprove}>Approve &amp; publish</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-muted-foreground">{label}</span>
      <span className={mono ? "font-mono text-xs" : ""}>{value}</span>
    </div>
  );
}

function LabReady({
  snapshot,
  ttlLeft,
  flag,
  setFlag,
  onSubmitFlag,
  onDestroy,
}: {
  snapshot: LabSnapshot;
  ttlLeft: number | null;
  flag: string;
  setFlag: (v: string) => void;
  onSubmitFlag: () => void;
  onDestroy: () => void;
}) {
  const [showHints, setShowHints] = useState(false);
  const mins = ttlLeft != null ? Math.floor(ttlLeft / 60) : null;
  const secs = ttlLeft != null ? ttlLeft % 60 : null;
  return (
    <Card className="border-primary/40">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <CheckCircle2 className="h-5 w-5 text-success" /> Lab ready
        </CardTitle>
        <CardDescription>
          {snapshot.local_preview
            ? "Local preview — reachable only from this host."
            : "Public URL — anyone with the link can reach it."}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {snapshot.public_url && (
          <a
            href={snapshot.public_url}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 break-all rounded-md border border-primary/40 bg-primary/10 px-3 py-2 font-mono text-xs text-primary hover:bg-primary/20"
          >
            <ExternalLink className="h-4 w-4 shrink-0" />
            {snapshot.public_url}
          </a>
        )}
        {snapshot.public_access_warning && (
          <p className="text-xs text-warning">{snapshot.public_access_warning}</p>
        )}
        {ttlLeft != null && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Clock className="h-3.5 w-3.5" /> TTL: {mins}:{String(secs).padStart(2, "0")} remaining
          </div>
        )}

        {snapshot.hints.length > 0 && (
          <div>
            <button
              className="text-xs text-primary hover:underline"
              onClick={() => setShowHints((v) => !v)}
            >
              {showHints ? "Hide" : "Show"} hints
            </button>
            {showHints && (
              <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-muted-foreground">
                {snapshot.hints.map((h) => (
                  <li key={h}>{h}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        <div className="space-y-2 pt-1">
          <Label htmlFor="flag" className="flex items-center gap-1 text-xs">
            <Flag className="h-3.5 w-3.5" /> Submit the flag
          </Label>
          <div className="flex gap-2">
            <Input
              id="flag"
              value={flag}
              onChange={(e) => setFlag(e.target.value)}
              placeholder="VF{...}"
              className="font-mono"
            />
            <Button onClick={onSubmitFlag} disabled={!flag.trim()}>
              Submit
            </Button>
          </div>
          {snapshot.solved && (
            <Badge variant="success" className="gap-1">
              <CheckCircle2 className="h-3 w-3" /> Solved
            </Badge>
          )}
        </div>

        <Button variant="destructive" onClick={onDestroy} className="w-full">
          <Trash2 /> Destroy lab
        </Button>
      </CardContent>
    </Card>
  );
}

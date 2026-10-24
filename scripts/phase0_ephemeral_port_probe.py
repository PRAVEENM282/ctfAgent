"""Probe public ports and stop/resume on one disposable cloud computer."""

from __future__ import annotations

import json
import os
import secrets
import shlex
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

try:
    from scripts.reap_orphans import delete_guest, reap_orphans, record_guest
except ModuleNotFoundError as exc:
    if exc.name != "scripts":
        raise
    from reap_orphans import delete_guest, reap_orphans, record_guest

PORT = 8000
MARKER = b"phase0-publication-ok"
_SERVER_SOURCE = (
    'use POSIX qw(setsid); my $pid=fork(); die "fork failed" unless defined $pid; '
    'exit 0 if $pid; setsid() or die "setsid failed"; '
    'open STDIN, "<", "/dev/null"; open STDOUT, ">", "/dev/null"; '
    'open STDERR, ">", "/dev/null"; '
    f'my $server=IO::Socket::INET->new(LocalAddr=>"0.0.0.0",LocalPort=>{PORT},Listen=>5,ReuseAddr=>1) or die $!; '
    "while (my $client=$server->accept()) { $client->autoflush(1); my $request=<$client>; "
    "while (my $header=<$client>) { last if $header =~ /^\\r?\\n$/; } "
    'print $client "HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\nConnection: close\\r\\n\\r\\nphase0-publication-ok"; '
    "close($client); }"
)
_SERVER_COMMAND = "perl -MIO::Socket::INET -e " + shlex.quote(_SERVER_SOURCE)
_PYTHON_SERVER_SOURCE = (
    "import http.server,socketserver; "
    "Handler=type('Handler',(http.server.BaseHTTPRequestHandler,),{"
    "'do_GET':lambda self:(self.send_response(200),"
    "self.send_header('Content-Type','text/plain'),"
    "self.end_headers(),self.wfile.write(b'phase0-publication-ok')),"
    "'log_message':lambda self,*args:None}); "
    "Server=type('Server',(socketserver.TCPServer,),{'allow_reuse_address':True}); "
    f"Server(('0.0.0.0',{PORT}),Handler).serve_forever()"
)
_PYTHON_SERVER_COMMAND = (
    "setsid python3 -c "
    + shlex.quote(_PYTHON_SERVER_SOURCE)
    + " >/dev/null 2>&1 </dev/null &"
)
_RUNTIME_INVENTORY = (
    "for tool in python3 python pip pip3 setsid busybox nc ncat socat php ruby perl curl wget apt-get apk; "
    'do command -v "$tool" 2>/dev/null || true; done; '
    'printf "UID=%s\\n" "$(id -u)"; '
    "if command -v python3 >/dev/null 2>&1; then python3 --version; "
    'python3 -m pip --version 2>&1 || printf "PIP_RESULT unavailable\\n"; '
    "python3 -c \"import sqlite3; print('SQLITE_VERSION='+sqlite3.sqlite_version)\"; "
    'else printf "PYTHON3_RESULT unavailable\\n"; fi; '
    'printf "ROOT_DISK_BYTES="; df -B1 --output=size / | tail -n1; '
    'printf "CPU_COUNT="; nproc; awk \'/MemTotal/ {print "MEMORY_KB=" $2}\' /proc/meminfo'
)


def _redact(value: str) -> str:
    for name in ("CELESTO_API_KEY", "LLM_API_KEY"):
        secret = os.environ.get(name)
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return value


def _guarded_run(computer: Any, step: str, command: str, timeout: int = 30) -> Any:
    allowed = {
        "start_http_server": _SERVER_COMMAND,
        "start_python_http_server": _PYTHON_SERVER_COMMAND,
        "runtime_inventory": _RUNTIME_INVENTORY,
    }
    if command != allowed.get(step) or computer.provider != "cloud":
        raise ValueError(
            f"guest command guard rejected step={step!r} or execution target"
        )
    print(
        "COMMAND_LOG "
        + json.dumps(
            {
                "execution_target": "celesto_sandbox",
                "step": step,
                "command": command,
                "dispatched": True,
            },
            sort_keys=True,
        )
    )
    result = computer.run(command, timeout=timeout)
    if result.exit_code != 0:
        raise RuntimeError(
            f"guest command step={step} exit_code={result.exit_code}; "
            f"stderr={_redact(result.stderr[:500])!r}"
        )
    print(f"GUEST_COMMAND_RESULT step={step} exit_code=0")
    if step == "runtime_inventory":
        print(f"GUEST_RUNTIME_INVENTORY {result.stdout.strip().replace(chr(10), ',')}")
    return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _http_probe(url: str) -> tuple[int | None, bool, str | None]:
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": "phase0-probe/1"})
    try:
        with opener.open(request, timeout=20) as response:
            body = response.read(4096)
            return response.status, MARKER in body, None
    except urllib.error.HTTPError as exc:
        body = exc.read(4096)
        return exc.code, MARKER in body, None
    except urllib.error.URLError as exc:
        return None, False, type(exc.reason).__name__
    except TimeoutError:
        return None, False, "TimeoutError"


def _unauthenticated_candidate(url: str) -> tuple[str | None, str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.query:
        return urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, "", "")
        ), "query_removed"
    if parsed.username is not None or parsed.password is not None:
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return urllib.parse.urlunsplit(
            (parsed.scheme, host, parsed.path, "", "")
        ), "userinfo_removed"
    if parsed.path not in ("", "/"):
        return urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, "/", "", "")
        ), "path_removed"
    labels = (parsed.hostname or "").split(".")
    if len(labels) > 2:
        host = ".".join(labels[1:])
        return urllib.parse.urlunsplit(
            (parsed.scheme, host, "/", "", "")
        ), "route_host_removed"
    return None, "no_separate_token_component"


def _record_http_result(
    label: str, url: str, *, retries: int = 1
) -> tuple[int | None, bool, str | None]:
    status: int | None = None
    marker_found = False
    transport_error: str | None = None
    for attempt in range(1, retries + 1):
        status, marker_found, transport_error = _http_probe(url)
        if (status == 200 and marker_found) or attempt == retries:
            break
        time.sleep(2)
    print(
        f"HTTP_PROBE label={label} status={status if status is not None else 'none'} "
        f"marker_visible={str(marker_found).lower()} "
        f"transport_error={transport_error or 'none'} attempts={attempt}"
    )
    return status, marker_found, transport_error


def _is_inaccessible(status: int | None, transport_error: str | None) -> bool:
    return (
        transport_error is not None
        or status in (401, 403, 404, 410)
        or (status is not None and status >= 500)
    )


def _record_revoked_probe(
    url: str, *, retries: int = 6
) -> tuple[int | None, bool, str | None]:
    status: int | None = None
    marker_found = False
    transport_error: str | None = None
    for attempt in range(1, retries + 1):
        status, marker_found, transport_error = _http_probe(url)
        if (
            _is_inaccessible(status, transport_error)
            or not marker_found
            or attempt == retries
        ):
            break
        time.sleep(2)
    print(
        f"HTTP_PROBE label=after_revoke status={status if status is not None else 'none'} "
        f"marker_visible={str(marker_found).lower()} "
        f"transport_error={transport_error or 'none'} attempts={attempt}"
    )
    return status, marker_found, transport_error


def run(
    *,
    lifetime: str = "ephemeral",
    template_id: str | None = None,
    restart_server_after_resume: bool = False,
) -> int:
    from celesto import Computer

    reap_orphans()
    computer = Computer(
        provider="cloud",
        lifetime=lifetime,
        **({"template_id": template_id} if template_id else {}),
    )
    logical_name = f"sbx-{secrets.token_hex(8)}"
    computer_id: str | None = None
    public_url: str | None = None
    primary_error: Exception | None = None
    cleanup_error: Exception | None = None
    port_published = False
    server_command = _SERVER_COMMAND
    server_step = "start_http_server"

    try:
        boot_started = time.monotonic()
        computer.start()
        boot_to_ready_s = time.monotonic() - boot_started
        computer_id = computer.id
        if not computer_id:
            raise RuntimeError("ephemeral cloud create returned without a computer ID")
        record_guest(computer_id, logical_name)
        print(
            f"PHASE0_COMPUTER_CREATED logical_name={logical_name} computer_id={computer_id} "
            f"requested_lifetime={lifetime} template_id={template_id or 'default'} "
            f"boot_to_ready_s={boot_to_ready_s:.3f}"
        )

        runtime = _guarded_run(computer, "runtime_inventory", _RUNTIME_INVENTORY)
        available = set(runtime.stdout.splitlines())
        python_ready = any(path.endswith("/python3") for path in available) and any(
            path.endswith("/setsid") for path in available
        )
        perl_ready = any(path.endswith("/perl") or path == "perl" for path in available)
        server_ready = python_ready or perl_ready
        if server_ready:
            try:
                if python_ready:
                    server_command = _PYTHON_SERVER_COMMAND
                    server_step = "start_python_http_server"
                _guarded_run(computer, server_step, server_command)
                print("SERVER_SETUP_RESULT ready=true")
            except Exception as exc:  # noqa: BLE001 - continue probing provider lifecycle.
                primary_error = primary_error or exc
                server_ready = False
                print(f"SERVER_SETUP_RESULT ready=false error={_redact(repr(exc))}")
        else:
            primary_error = RuntimeError(
                "guest has neither Python plus setsid nor Perl for the fixed HTTP probe"
            )
            print("SERVER_SETUP_RESULT ready=false reason=server_runtime_unavailable")

        published = None
        try:
            published = computer.publish_port(PORT)
            port_published = True
            public_url = published.url
            print(
                f"PUBLISH_RESULT port={published.port} status={published.status} "
                f"url_present={str(bool(public_url)).lower()}"
            )
        except Exception as exc:  # noqa: BLE001 - still test stop/resume on the same guest.
            primary_error = primary_error or exc
            print(f"PUBLISH_FAILURE error={_redact(repr(exc))}")

        if published is not None:
            try:
                listed = computer.published_ports()
                listed_port = next((item for item in listed if item.port == PORT), None)
                print(
                    f"PUBLISHED_PORTS_RESULT count={len(listed)} requested_port_listed="
                    f"{str(listed_port is not None).lower()} status={listed_port.status if listed_port else 'absent'} "
                    f"url_matches={str(listed_port is not None and listed_port.url == public_url).lower()}"
                )
            except Exception as exc:  # noqa: BLE001 - continue to stop/resume and cleanup.
                primary_error = primary_error or exc
                print(f"PUBLISHED_PORTS_FAILURE error={_redact(repr(exc))}")

            if public_url and server_ready:
                status, marker_visible, _ = _record_http_result(
                    "published_url", public_url, retries=6
                )
                if status != 200 or not marker_visible:
                    primary_error = primary_error or RuntimeError(
                        "published URL did not serve the expected test marker"
                    )
                unauth_url, shape = _unauthenticated_candidate(public_url)
                if unauth_url is None:
                    print(f"ACCESS_CONTROL_RESULT status=not_testable reason={shape}")
                else:
                    unauth_status, marker_without_auth, unauth_error = (
                        _record_http_result(
                            f"without_url_component:{shape}", unauth_url
                        )
                    )
                    host_routing_observed = unauth_status == 301
                    print(
                        "HOST_ROUTING_RESULT "
                        f"host_routing_observed={str(host_routing_observed).lower()} "
                        f"method={shape} "
                        f"status={unauth_status if unauth_status is not None else 'none'} "
                        f"marker_visible={str(marker_without_auth).lower()} "
                        f"transport_error={unauth_error or 'none'}"
                    )
            elif public_url:
                print("HTTP_PROBE status=not_run reason=guest_http_server_unavailable")

        stop_ok = False
        try:
            computer.stop()
            stop_ok = True
            print(f"COMPUTER_STOP_RESULT ok=true computer_id={computer_id}")
        except Exception as exc:  # noqa: BLE001 - still try resume and cleanup.
            primary_error = primary_error or exc
            print(f"COMPUTER_STOP_RESULT ok=false error={_redact(repr(exc))}")
        try:
            computer.resume()
            print(
                f"COMPUTER_RESUME_RESULT ok=true same_id="
                f"{str(computer.id == computer_id).lower()} stop_succeeded={str(stop_ok).lower()}"
            )
            if restart_server_after_resume and server_ready:
                _guarded_run(computer, server_step, server_command)
                print("APP_RESTART_AFTER_RESUME_RESULT ready=true")
            if port_published:
                resumed_ports = computer.published_ports()
                resumed_port = next(
                    (item for item in resumed_ports if item.port == PORT), None
                )
                url_matches = (
                    resumed_port is not None and resumed_port.url == public_url
                )
                print(
                    f"COMPUTER_RESUME_PORT_RESULT listed={str(resumed_port is not None).lower()} "
                    f"url_matches={str(url_matches).lower()}"
                )
                if resumed_port is not None and resumed_port.url and server_ready:
                    status, marker_after_resume, _ = _record_http_result(
                        "after_computer_resume", resumed_port.url, retries=6
                    )
                    if restart_server_after_resume and (
                        status != 200 or not marker_after_resume
                    ):
                        primary_error = primary_error or RuntimeError(
                            "published URL did not serve the test marker after app restart"
                        )
        except Exception as exc:  # noqa: BLE001 - report but continue with cleanup/revoke.
            primary_error = primary_error or exc
            print(f"COMPUTER_RESUME_RESULT ok=false error={_redact(repr(exc))}")

        if port_published:
            try:
                revoked_port = computer.unpublish_port(PORT)
                port_published = False
                print(
                    f"UNPUBLISH_RESULT port={PORT} status={revoked_port.status} requested=true"
                )
                still_listed = True
                for attempt in range(1, 11):
                    after_revoke = computer.published_ports()
                    still_listed = any(item.port == PORT for item in after_revoke)
                    if not still_listed:
                        break
                    time.sleep(2)
                print(
                    f"UNPUBLISH_LIST_RESULT port_listed={str(still_listed).lower()} "
                    f"attempts={attempt}"
                )
                if public_url and server_ready:
                    status, marker_after_revoke, transport_error = (
                        _record_revoked_probe(public_url)
                    )
                    revoked = (
                        _is_inaccessible(status, transport_error)
                        or not marker_after_revoke
                    )
                    print(
                        f"POST_REVOKE_RESULT inaccessible={str(revoked).lower()} "
                        f"marker_visible={str(marker_after_revoke).lower()}"
                    )
            except Exception as exc:  # noqa: BLE001 - cleanup below still deletes the guest.
                primary_error = primary_error or exc
                print(f"UNPUBLISH_FAILURE error={_redact(repr(exc))}")
    except Exception as exc:  # noqa: BLE001 - cleanup must run for every provider failure.
        primary_error = exc
        frames = traceback.extract_tb(exc.__traceback__)
        last = frames[-1] if frames else None
        location = f"{last.filename}:{last.lineno}" if last else "unavailable"
        print(
            f"FAIL step=ephemeral_ports error={_redact(repr(exc))} last_frame={location}"
        )
    finally:
        if computer_id:
            if port_published:
                try:
                    computer.unpublish_port(PORT)
                    print(f"CLEANUP_UNPUBLISH_REQUESTED port={PORT}")
                except Exception as exc:  # noqa: BLE001 - preserve cleanup failure.
                    cleanup_error = exc
            try:
                delete_guest(computer_id, computer=computer, name=logical_name)
            except Exception as exc:  # noqa: BLE001 - report cleanup failure explicitly.
                cleanup_error = cleanup_error or exc
        else:
            computer.close()

    if cleanup_error:
        print(f"CLEANUP_FAILURE error={_redact(repr(cleanup_error))}")
        return 1
    if primary_error:
        return 1
    print("PASS published_ports_stop_resume_probe")
    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lifetime", choices=("ephemeral", "persistent"), default="ephemeral"
    )
    parser.add_argument("--template", dest="template_id")
    parser.add_argument("--restart-server-after-resume", action="store_true")
    options = parser.parse_args()
    raise SystemExit(
        run(
            lifetime=options.lifetime,
            template_id=options.template_id,
            restart_server_after_resume=options.restart_server_after_resume,
        )
    )

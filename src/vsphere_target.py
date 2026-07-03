"""
LUCENT — vSphere target orchestration wrapper.

A thin, *safety-first* control layer over a single disposable target VM, used by
the harness to: revert to a clean snapshot, push an input/binary into the guest,
run a program under the oracle, and pull artifacts back out.

Design rules:
  * The target VM is resolved *strictly by UUID* (never by name), and the
    resolved VM's instanceUuid/uuid is asserted against the configured UUID
    before any destructive operation runs. This is the guardrail that makes it
    impossible to accidentally revert/snapshot/exec against the dev box.
  * All secrets come from the environment; nothing is hardcoded.
  * Guest file transfer tunnels through VMware Tools (no datastore access).

Dependencies:
    pip install pyvmomi requests

Environment:
    VC_HOST              vCenter / ESXi hostname (required)
    VC_USER              vCenter SSO user, e.g. serviceaccount@vsphere.local (required)
    VC_PASSWORD          vCenter password (required)
    VC_INSECURE          "1"/"true" to skip TLS verification (default: false)
    TARGET_VM_UUID       overrides the UUID read from <repo>/vm-uuid.txt
    TARGET_GUEST_USER    in-guest account for guest operations (required for guest ops)
    TARGET_GUEST_PASSWORD in-guest password (required for guest ops)
"""

from __future__ import annotations

import os
import ssl
import time
from pathlib import Path
from typing import Optional, Tuple

import requests

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import atexit


# --- UUID default -----------------------------------------------------------
# The canonical target UUID lives in vm-uuid.txt at the repo root. We read it at
# runtime rather than baking the literal into source, so re-imaging the lab only
# touches that one file. This module is src/vsphere_target.py, so the repo root
# is its parent's parent.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_UUID_FILE = _REPO_ROOT / "vm-uuid.txt"


def _read_default_uuid() -> Optional[str]:
    """Read the default target UUID from <repo>/vm-uuid.txt, if present."""
    try:
        value = _UUID_FILE.read_text(encoding="utf-8").strip()
        return value or None
    except OSError:
        return None


def _truthy(value: Optional[str]) -> bool:
    """Interpret common truthy strings from the environment."""
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


class VSphereTarget:
    """Orchestration wrapper around a single, UUID-pinned target VM.

    Use as a context manager:

        with VSphereTarget() as t:
            t.revert("clean")
            t.push("trigger.bin", r"C:\\lucent\\sandbox\\trigger.bin")
            rc, out, err = t.run(r"C:\\lucent\\sandbox\\target.exe",
                                 args=r"C:\\lucent\\sandbox\\trigger.bin")
    """

    def __init__(
        self,
        host: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        insecure: Optional[bool] = None,
        vm_uuid: Optional[str] = None,
        guest_user: Optional[str] = None,
        guest_password: Optional[str] = None,
    ) -> None:
        self.host: str = host or os.environ.get("VC_HOST", "")
        self.user: str = user or os.environ.get("VC_USER", "")
        self.password: str = password or os.environ.get("VC_PASSWORD", "")
        self.insecure: bool = (
            insecure if insecure is not None else _truthy(os.environ.get("VC_INSECURE"))
        )
        self.vm_uuid: str = (
            vm_uuid
            or os.environ.get("TARGET_VM_UUID")
            or (_read_default_uuid() or "")
        )

        self._guest_user: str = guest_user or os.environ.get("TARGET_GUEST_USER", "")
        self._guest_password: str = (
            guest_password or os.environ.get("TARGET_GUEST_PASSWORD", "")
        )

        if not self.host or not self.user or not self.password:
            raise ValueError(
                "VC_HOST, VC_USER and VC_PASSWORD must be set (env or constructor)."
            )
        if not self.vm_uuid:
            raise ValueError(
                "No target VM UUID: set TARGET_VM_UUID or populate vm-uuid.txt."
            )

        self._si: Optional[vim.ServiceInstance] = None
        self._content: Optional[vim.ServiceContent] = None
        self._vm: Optional[vim.VirtualMachine] = None

    # --- connection / lifecycle --------------------------------------------
    def connect(self) -> "VSphereTarget":
        """Connect to vCenter, resolve + verify the target VM."""
        ssl_context = None
        if self.insecure:
            # Self-signed lab cert: build an unverified context explicitly rather
            # than disabling verification globally.
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        self._si = SmartConnect(
            host=self.host,
            user=self.user,
            pwd=self.password,
            sslContext=ssl_context,
        )
        atexit.register(self._safe_disconnect)
        self._content = self._si.RetrieveContent()
        self._vm = self._resolve_and_verify_vm()
        return self

    def _safe_disconnect(self) -> None:
        if self._si is not None:
            try:
                Disconnect(self._si)
            except Exception:
                pass
            finally:
                self._si = None

    def __enter__(self) -> "VSphereTarget":
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._safe_disconnect()

    # --- resolution + safety ------------------------------------------------
    def _resolve_and_verify_vm(self) -> vim.VirtualMachine:
        """Resolve the VM strictly by UUID and assert it matches before use.

        Tries instance UUID first (globally unique within a vCenter), then the
        BIOS UUID. Never resolves by name. Raises if not found or if the
        resolved VM's UUID does not match the configured UUID.
        """
        assert self._content is not None
        search = self._content.searchIndex

        vm = search.FindByUuid(uuid=self.vm_uuid, vmSearch=True, instanceUuid=True)
        if vm is None:
            # Fall back to BIOS uuid (instanceUuid=False) for older/migrated VMs.
            vm = search.FindByUuid(uuid=self.vm_uuid, vmSearch=True, instanceUuid=False)
        if vm is None:
            raise LookupError(
                f"No VM found for UUID {self.vm_uuid!r} (instance or BIOS)."
            )

        # SAFETY GATE: confirm identity before ANY destructive call can run.
        instance_uuid = getattr(vm.config, "instanceUuid", None)
        bios_uuid = getattr(vm.config, "uuid", None)
        if self.vm_uuid not in {instance_uuid, bios_uuid}:
            raise RuntimeError(
                "Refusing to operate: resolved VM UUID mismatch. "
                f"configured={self.vm_uuid!r} instanceUuid={instance_uuid!r} "
                f"uuid={bios_uuid!r}"
            )
        return vm

    @property
    def vm(self) -> vim.VirtualMachine:
        if self._vm is None:
            raise RuntimeError("Not connected; call connect() or use as context manager.")
        return self._vm

    def _guest_auth(self) -> vim.vm.guest.NamePasswordAuthentication:
        if not self._guest_user or not self._guest_password:
            raise ValueError(
                "Guest operations require TARGET_GUEST_USER and TARGET_GUEST_PASSWORD."
            )
        return vim.vm.guest.NamePasswordAuthentication(
            username=self._guest_user,
            password=self._guest_password,
            interactiveSession=False,
        )

    # --- task helper --------------------------------------------------------
    @staticmethod
    def _wait_for_task(task: vim.Task, timeout: int = 600) -> object:
        """Block until a vSphere task completes; return its result or raise."""
        deadline = time.time() + timeout
        while task.info.state in (vim.TaskInfo.State.queued, vim.TaskInfo.State.running):
            if time.time() > deadline:
                raise TimeoutError(f"Task {task!r} did not complete within {timeout}s.")
            time.sleep(1)
        if task.info.state == vim.TaskInfo.State.error:
            raise RuntimeError(f"Task failed: {task.info.error}")
        return task.info.result

    # --- snapshot tree helpers ---------------------------------------------
    @staticmethod
    def _find_snapshot(
        nodes: list, name: str
    ) -> Optional[vim.vm.Snapshot]:
        """Depth-first search of the snapshot tree for a snapshot by name."""
        for node in nodes:
            if node.name == name:
                return node.snapshot
            found = VSphereTarget._find_snapshot(node.childSnapshotList, name)
            if found is not None:
                return found
        return None

    # --- public operations --------------------------------------------------
    def revert(self, snapshot_name: Optional[str] = None) -> None:
        """Revert the VM to a named snapshot, or to current if no name given.

        Power-on state follows whatever was captured in the snapshot.
        """
        if snapshot_name is None:
            if self.vm.snapshot is None or self.vm.snapshot.currentSnapshot is None:
                raise RuntimeError("VM has no current snapshot to revert to.")
            task = self.vm.snapshot.currentSnapshot.RevertToSnapshot_Task()
        else:
            if self.vm.snapshot is None:
                raise RuntimeError("VM has no snapshots.")
            snap = self._find_snapshot(self.vm.snapshot.rootSnapshotList, snapshot_name)
            if snap is None:
                raise LookupError(f"Snapshot {snapshot_name!r} not found.")
            task = snap.RevertToSnapshot_Task()
        self._wait_for_task(task)

    def create_snapshot(
        self,
        name: str,
        description: str = "",
        memory: bool = True,
        quiesce: bool = False,
    ) -> vim.vm.Snapshot:
        """Create a snapshot and return the resulting snapshot reference."""
        task = self.vm.CreateSnapshot_Task(
            name=name,
            description=description,
            memory=memory,
            quiesce=quiesce,
        )
        result = self._wait_for_task(task)
        return result  # type: ignore[return-value]

    # --- guest file transfer (tunnels through VMware Tools) -----------------
    def _fix_transfer_url(self, url: str) -> str:
        """vCenter may return a URL with a wildcard '*' host; pin it to VC_HOST."""
        return url.replace("https://*", f"https://{self.host}", 1)

    def push(self, local_path: str, guest_path: str) -> None:
        """Upload a local file into the guest at guest_path (overwrites)."""
        assert self._content is not None
        auth = self._guest_auth()
        data = Path(local_path).read_bytes()

        file_mgr = self._content.guestOperationsManager.fileManager
        file_attrs = vim.vm.guest.FileManager.FileAttributes()
        url = file_mgr.InitiateFileTransferToGuest(
            vm=self.vm,
            auth=auth,
            guestFilePath=guest_path,
            fileAttributes=file_attrs,
            fileSize=len(data),
            overwrite=True,
        )
        url = self._fix_transfer_url(url)
        resp = requests.put(url, data=data, verify=not self.insecure, timeout=300)
        resp.raise_for_status()

    def pull(self, guest_path: str, local_path: str) -> None:
        """Download a file from the guest to local_path."""
        assert self._content is not None
        auth = self._guest_auth()

        file_mgr = self._content.guestOperationsManager.fileManager
        info = file_mgr.InitiateFileTransferFromGuest(
            vm=self.vm, auth=auth, guestFilePath=guest_path
        )
        url = self._fix_transfer_url(info.url)
        resp = requests.get(url, verify=not self.insecure, timeout=300)
        resp.raise_for_status()
        Path(local_path).write_bytes(resp.content)

    # --- guest process execution -------------------------------------------
    def run(
        self,
        program_path: str,
        args: str = "",
        cwd: Optional[str] = None,
        env: Optional[list] = None,
        capture: bool = True,
        timeout: int = 300,
    ) -> Tuple[int, str, str]:
        """Run a program in the guest and return (exit_code, stdout, stderr).

        When capture is True, stdout/stderr are redirected to temp files in the
        guest via cmd.exe, then pulled back after the process exits. When False,
        stdout/stderr are returned empty.
        """
        assert self._content is not None
        auth = self._guest_auth()
        pm = self._content.guestOperationsManager.processManager

        out_guest = err_guest = None
        if capture:
            # Stamp temp names with the launch time to avoid collisions across runs.
            stamp = int(time.time() * 1000)
            out_guest = rf"C:\Windows\Temp\lucent_{stamp}_out.txt"
            err_guest = rf"C:\Windows\Temp\lucent_{stamp}_err.txt"
            # cmd.exe wrapper so we can redirect; ^ is not needed since we pass
            # the whole thing as the arguments string to cmd /c.
            full_program = r"C:\Windows\System32\cmd.exe"
            full_args = (
                f'/c ""{program_path}" {args} > "{out_guest}" 2> "{err_guest}""'
            )
        else:
            full_program = program_path
            full_args = args

        spec = vim.vm.guest.ProcessManager.ProgramSpec(
            programPath=full_program,
            arguments=full_args,
            workingDirectory=cwd or "",
            envVariables=env or None,
        )
        pid = pm.StartProgramInGuest(vm=self.vm, auth=auth, spec=spec)

        # Poll until the pid leaves the process table (or has an exitTime).
        exit_code = self._poll_for_exit(pm, auth, pid, timeout)

        stdout, stderr = "", ""
        if capture:
            stdout = self._pull_text(out_guest)  # type: ignore[arg-type]
            stderr = self._pull_text(err_guest)  # type: ignore[arg-type]
        return exit_code, stdout, stderr

    def _poll_for_exit(
        self,
        pm: vim.vm.guest.ProcessManager,
        auth: vim.vm.guest.NamePasswordAuthentication,
        pid: int,
        timeout: int,
    ) -> int:
        """Poll ListProcessesInGuest until pid exits; return its exit code."""
        deadline = time.time() + timeout
        while True:
            procs = pm.ListProcessesInGuest(vm=self.vm, auth=auth, pids=[pid])
            if procs:
                info = procs[0]
                if info.endTime is not None:
                    return info.exitCode if info.exitCode is not None else -1
            if time.time() > deadline:
                raise TimeoutError(f"Guest pid {pid} did not exit within {timeout}s.")
            time.sleep(2)

    def _pull_text(self, guest_path: str) -> str:
        """Pull a guest text file and return its decoded contents (best effort)."""
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            self.pull(guest_path, tmp_path)
            return Path(tmp_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# --- non-destructive smoke section -----------------------------------------
if __name__ == "__main__":
    # Connects, prints identity + snapshots, and does nothing destructive.
    with VSphereTarget() as target:
        vm = target.vm
        print(f"Resolved VM name : {vm.name}")
        print(f"  instanceUuid   : {getattr(vm.config, 'instanceUuid', None)}")
        print(f"  bios uuid      : {getattr(vm.config, 'uuid', None)}")
        print(f"  configured uuid: {target.vm_uuid}")
        print(f"  power state    : {vm.runtime.powerState}")

        if vm.snapshot is None:
            print("  snapshots      : (none)")
        else:
            def _walk(nodes, depth=0):
                for node in nodes:
                    marker = " *current" if (
                        vm.snapshot.currentSnapshot == node.snapshot
                    ) else ""
                    print(f"  {'  ' * depth}- {node.name}{marker}")
                    _walk(node.childSnapshotList, depth + 1)

            print("  snapshots      :")
            _walk(vm.snapshot.rootSnapshotList)

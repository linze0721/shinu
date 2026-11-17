#!/usr/bin/env python3
"""Opt-in C2 regression at the daemon HTTP/CLI seam on an isolated KVM host.

Requires root, KVM, btrfs, cgroup v2, approved assets and a prebuilt Void base.
Never uses the source daemon/database; only clones immutable host assets.
"""
import argparse
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import struct
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(self.host)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def expected_identity(space_id, base="172.29"):
    """Mirror of `shinu_vm::net::net_spec`: every value derives from the UUID."""
    raw = uuid.UUID(space_id).bytes
    index = ((raw[0] << 8) | raw[1]) & 0x3FFF
    third = ((index >> 8) << 2) | ((index & 0xFF) >> 6)
    fourth = ((index & 0xFF) & 0x3F) << 2
    return {
        "cidr": [f"{base}.{third}.{fourth + 2}/30"],
        "mac": "aa:fc:" + ":".join(f"{byte:02x}" for byte in raw[:4]),
        "gateway": [f"{base}.{third}.{fourth + 1}"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets-root", type=Path, required=True)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--root-parent", type=Path, required=True)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="sfr-", dir=args.root_parent))
    os.chmod(root, 0o700)
    daemon = None
    spaces = set()
    log = (root / "daemon.log").open("wb")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("SHINU_"):
            del env[key]
    env.update(SHINU_ROOT=str(root), SHINU_LISTEN=f"127.0.0.1:{port}",
               SHINU_ENDPOINT=f"http://127.0.0.1:{port}", SHINU_NET_ENABLE="1", SHINU_NET_BASE="172.29",
               SHINU_IDLE_RECLAIM="0", SHINU_MEM_MIB="256", SHINU_VCPUS="1",
               SHINU_LIMIT_SPACES="1", SHINU_LIMIT_RUNNING="1", SHINU_LIMIT_DISK_MIB="1",
               SHINU_SPACE_WRITE_CAP_MIB="20480", SHINU_JAIL_UID="31003", SHINU_JAIL_GID="32007")
    cli = str(args.bin_dir.resolve() / "shinu")

    def request(method, path, body=None, expected=200):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(env["SHINU_ENDPOINT"] + path, data=data, method=method,
                                     headers={"Authorization": "Bearer " + env["SHINU_TOKEN"],
                                              "Content-Type": "application/json"})
        try:
            response = urllib.request.urlopen(req, timeout=180)
        except urllib.error.HTTPError as error:
            response = error
        payload = response.read()
        assert response.code == expected, (method, path, response.code, payload.decode())
        value = json.loads(payload)
        return value.get("data", value)

    def start_daemon():
        process = subprocess.Popen([str(args.bin_dir.resolve() / "shinud"), "--root", str(root)],
                                   env=env, stdout=log, stderr=log)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("isolated daemon exited; see " + str(root / "daemon.log"))
            try:
                request("GET", "/v1/spaces")
                return process
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        raise TimeoutError("isolated daemon startup")

    def fc(space, route="/"):
        listing = request("GET", "/v1/spaces")
        entry = next(value for value in listing["spaces"] if value["name"] == space)
        connection = UnixHTTP(str(root / "jail/firecracker" / entry["id"] / "root/fc.sock"))
        connection.request("GET", route)
        response = connection.getresponse()
        body = response.read()
        connection.close()
        assert response.status == 200, body
        return json.loads(body)

    def run_cli(*argv):
        result = subprocess.run([cli, *argv], env=env, capture_output=True, text=True, timeout=180)
        assert result.returncode == 0, (argv, result.stdout, result.stderr)
        return result.stdout

    def guest_identity(space):
        """The guest's actual eth0 identity: every IPv4 CIDR, MAC, default gateways."""
        lines = run_cli("exec", space, "--", "sh", "-c",
                        "ip -4 -o addr show dev eth0; echo mac $(cat /sys/class/net/eth0/address); ip -4 route show default").splitlines()
        return {
            "cidr": [line.split()[3] for line in lines if " inet " in line],
            "mac": next(line.split()[1].lower() for line in lines if line.startswith("mac ")),
            "gateway": [line.split()[2] for line in lines if line.startswith("default via ")],
        }

    try:
        for name in ["assets", "cache"]:
            subprocess.run(["cp", "-a", "--reflink=always", str(args.assets_root / name), str(root / name)], check=True)
        subprocess.run(["cp", "--reflink=always", str(args.base), str(root / "base-void.ext4")], check=True)
        minted = subprocess.run([cli, "--root", str(root), "token", "new", "--project", "fast-ready-smoke"],
                                capture_output=True, text=True, check=True)
        env["SHINU_TOKEN"] = next(line.removeprefix("token: ") for line in minted.stdout.splitlines() if line.startswith("token: "))
        daemon = start_daemon()
        source = request("POST", "/v1/spaces", {"name": "source", "readiness": {"command": ["/bin/sh", "-c", "printf '%s' \"$SHINU_RESTORE_ID\" > /tmp/shinu-ready-id"], "timeout_seconds": 30}}, 201)
        assert source["write_cap_mib"] == 0
        spaces.add("source")
        tap = "shinu" + source["id"].replace("-", "")[:10]
        sys_tap = Path("/sys/class/net") / tap
        # Intentionally model a pre-upgrade TAP; production creation must always
        # specify the configured jail user AND group.
        subprocess.run(["ip", "tuntap", "add", "dev", tap, "mode", "tap"], check=True)
        old_index = (sys_tap / "ifindex").read_text()
        holder = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)
        try:
            fcntl.ioctl(holder, 0x400454CA, struct.pack("16sH", tap.encode(), 0x1002))
            busy = request("POST", "/v1/spaces/source/start", expected=409)
            assert busy["code"] == "tap_busy"
            rejected = subprocess.run([cli, "start", "source"], env=env, capture_output=True, text=True, timeout=30)
            assert rejected.returncode == 73, rejected.returncode
            assert rejected.stderr == "shinu: tap_busy\n"
            assert (sys_tap / "ifindex").read_text() == old_index
            assert (sys_tap / "owner").read_text().strip() == "-1"
            assert (sys_tap / "group").read_text().strip() == "-1"
        finally:
            os.close(holder)
        lock_path = Path("/run/shinu-tap-locks") / (tap + ".lock")
        lock_inode = lock_path.stat().st_ino
        with lock_path.open("r+b") as claim:
            fcntl.flock(claim, fcntl.LOCK_EX | fcntl.LOCK_NB)
            busy = request("POST", "/v1/spaces/source/start", expected=409)
            assert busy["code"] == "tap_busy"
            assert (sys_tap / "ifindex").read_text() == old_index
        assert lock_path.stat().st_ino == lock_inode
        assert lock_path.stat().st_size == 0
        run_cli("start", "source")
        assert (sys_tap / "ifindex").read_text() != old_index, "legacy TAP must be rebuilt"
        assert (sys_tap / "owner").read_text().strip() == env["SHINU_JAIL_UID"]
        assert (sys_tap / "group").read_text().strip() == env["SHINU_JAIL_GID"]
        source_ready_id = run_cli("exec", "source", "--", "cat", "/tmp/shinu-ready-id").strip()
        assert source_ready_id
        # The identity captured in guest RAM. It also checks the UUID derivation.
        source_identity = guest_identity("source")
        assert source_identity == expected_identity(source["id"]), source_identity
        checkpoint = request("POST", "/v1/spaces/source/commits", {"note": "fast-ready-full", "hot": True, "snapshot": "full"}, 201)
        checkpoint_id = checkpoint["id"]
        run_cli("stop", "source")
        run_cli("rm", "source")
        spaces.remove("source")
        memory = root / "ckpts" / (checkpoint_id + ".mem")
        assert memory.stat().st_mode & 0o777 == 0o440
        original_digest = digest(memory)
        run_cli("ckpt", "warm", checkpoint_id)
        cache_stat = dict(line.split() for line in Path("/sys/fs/cgroup/shinu-ckpt-cache/memory.stat").read_text().splitlines())
        assert int(cache_stat["file"]) > 0, cache_stat
        readiness_requests = (root / "daemon.log").read_text().count("stage=requested")
        for name in ["pooled", "recover"]:
            value = request("POST", f"/v1/commits/{checkpoint_id}/fork", {"name": name}, 201)
            spaces.add(name)
            if name == "pooled":
                pooled_entry = value
            fork_memory = root / "spaces" / (value["id"] + ".mem")
            assert fork_memory.stat().st_ino == memory.stat().st_ino
            run_cli("start", "--load-only", "--track-dirty", "false", name)
            assert fc(name)["state"] == "Paused"
            assert fc(name, "/machine-config")["track_dirty_pages"] is False
        listing = request("GET", "/v1/spaces")
        assert all(value["state"] == "loaded" and not value["running"] for value in listing["spaces"])
        # Auto-start must never silently resume a pooled guest.
        request("POST", "/v1/spaces/pooled/exec", {"cmd": ["true"]}, 400)
        assert (root / "daemon.log").read_text().count("stage=requested") == readiness_requests
        request("POST", f"/v1/commits/{checkpoint_id}/fork", {"name": "tracked"}, 201)
        spaces.add("tracked")
        run_cli("start", "tracked")
        assert fc("tracked", "/machine-config")["track_dirty_pages"] is True
        run_cli("resume", "pooled")
        assert fc("pooled")["state"] == "Running"
        run_cli("exec", "pooled", "--", "true")
        assert digest(memory) == original_digest
        request("DELETE", f"/v1/commits/{checkpoint_id}", expected=400)
        # A Full capture from track_dirty=false still works, without overwriting
        # the source shared inode. A later Diff must degrade to Full safely.
        restored_ready_id = run_cli("exec", "pooled", "--", "cat", "/tmp/shinu-ready-id").strip()
        assert restored_ready_id and restored_ready_id != source_ready_id
        guest_time = int(run_cli("exec", "pooled", "--", "date", "+%s").strip())
        assert abs(time.time() - guest_time) < 5
        # Exact pooled identity, and every field differs from the captured
        # source: a skipped or partial guest reconfiguration cannot pass.
        pooled_identity = guest_identity("pooled")
        pooled_expected = expected_identity(pooled_entry["id"])
        for field in ["cidr", "mac", "gateway"]:
            assert pooled_expected[field] != source_identity[field], (field, pooled_expected, source_identity)
        assert pooled_identity == pooled_expected, (pooled_identity, pooled_expected, source_identity)
        child = request("POST", "/v1/spaces/pooled/commits", {"note": "pool-capture", "hot": True, "snapshot": "full"}, 201)
        assert child["snapshot"] == "full"
        child2 = request("POST", "/v1/spaces/pooled/commits", {"note": "pool-diff", "hot": True, "snapshot": "diff"}, 201)
        assert child2["snapshot"] == "full"
        assert digest(memory) == original_digest
        interrupted = request("POST", f"/v1/commits/{checkpoint_id}/fork", {"name": "interrupted", "readiness": {"command": ["/bin/sh", "-c", "touch /tmp/resuming-write; sleep 30"], "timeout_seconds": 60}}, 201)
        spaces.add("interrupted")
        run_cli("start", "--load-only", "interrupted")

        def resume_interrupted():
            try:
                request("POST", "/v1/spaces/interrupted/resume")
            except (OSError, urllib.error.URLError, http.client.HTTPException):
                pass

        worker = threading.Thread(target=resume_interrupted)
        worker.start()
        deadline = time.monotonic() + 10
        while fc("interrupted")["state"] != "Running":
            assert time.monotonic() < deadline, "resume never started vCPUs"
            time.sleep(0.01)
        daemon.terminate()
        daemon.wait(timeout=15)
        worker.join(timeout=5)
        assert not worker.is_alive()
        daemon = start_daemon()
        listing = request("GET", "/v1/spaces")
        by_name = {entry["name"]: entry for entry in listing["spaces"]}
        assert by_name["recover"]["state"] == "stopped"
        assert by_name["pooled"]["state"] == "running"
        # Loaded never executed vCPUs, so pending memory still matches its disk.
        run_cli("start", "--load-only", "--track-dirty", "false", "recover")
        assert fc("recover")["state"] == "Paused"
        assert fc("recover", "/machine-config")["track_dirty_pages"] is False
        # Interrupted resume may have written disk; its stale memory is consumed.
        assert by_name["interrupted"]["state"] == "stopped"
        assert not (root / "spaces" / (interrupted["id"] + ".mem")).exists()
        request("POST", "/v1/spaces/interrupted/start", {"load_only": True}, 400)
        for name in sorted(spaces):
            run_cli("stop", name)
            run_cli("rm", name)
        spaces.clear()
        assert not list((root / "spaces").iterdir()), "rm must remove pending memory/state too"
        daemon.terminate()
        daemon.wait(timeout=15)
        env["SHINU_MIN_STORE_FREE_MIB"] = str(2**64 - 1)
        daemon = start_daemon()
        rejected = subprocess.run([cli, "fork", checkpoint_id, "capacity-denied"], env=env, capture_output=True, text=True, timeout=30)
        assert rejected.returncode == 75, rejected.returncode
        assert rejected.stderr == "shinu: capacity_watermark\n"
        for identifier in [child2["id"], child["id"], checkpoint_id]:
            run_cli("rmckpt", identifier)
        print("PASS: TAP jail uid/gid, legacy rebuild, occupied/locked TAP rejection, retained lock inode, Full sharing, cache cgroup, load/resume, exact restored CIDR/MAC/gateway distinct from source, READY, dirty flags, capture and recovery")
    finally:
        if daemon is not None and daemon.poll() is None:
            for name in sorted(spaces):
                for action in ["stop", "rm"]:
                    subprocess.run([cli, action, name], env=env, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=60, check=False)
            daemon.terminate()
            daemon.wait(timeout=15)
        log.close()
        # Preserve only bounded diagnostic output; tokens and credentials never
        # leave this root, and cleanup removes its source/private guest keys.
        if not spaces:
            shutil.rmtree(root)
        else:
            print("isolated diagnostic root retained:", root)


if __name__ == "__main__":
    main()

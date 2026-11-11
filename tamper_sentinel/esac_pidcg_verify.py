#!/usr/bin/env python3
"""Read-only host PID+cgroup identity gate for an isolated eSAC pilot."""
import json
import os
import select
import sys
from pathlib import Path


def snapshot(pid: int, expected_dir: Path):
    stat = Path(f'/proc/{pid}/stat').read_text()
    tail = stat.rsplit(')', 1)[1].split()
    state = tail[0]
    starttime = int(tail[19])
    lines = Path(f'/proc/{pid}/cgroup').read_text().splitlines()
    paths = [x.split('::', 1)[1] for x in lines if x.startswith('0::')]
    if len(paths) != 1:
        raise RuntimeError(f'expected one cgroup v2 entry, got {paths!r}')
    actual = Path('/sys/fs/cgroup') / paths[0].lstrip('/')
    if actual.resolve() != expected_dir.resolve():
        raise RuntimeError(f'wrong cgroup: {actual} != {expected_dir}')
    pidfd = os.pidfd_open(pid)
    try:
        if select.select([pidfd], [], [], 0)[0]:
            raise RuntimeError('target exited')
    finally:
        os.close(pidfd)
    return {
        'host_pid': pid,
        'starttime_ticks': starttime,
        'cgroup_v2_path': paths[0],
        'cgroup_inode': actual.stat().st_ino,
        'cgroup_namespace_inode': Path(f'/proc/{pid}/ns/cgroup').stat().st_ino,
        'state_at_check': state,
        'pidfd_open': True,
    }


def main():
    mode, pid_text, cg_text, outfile_text = sys.argv[1:]
    pid, cg_dir, outfile = int(pid_text), Path(cg_text), Path(outfile_text)
    ident = snapshot(pid, cg_dir)
    stable = {k: v for k, v in ident.items() if k != 'state_at_check'}
    if mode == 'init':
        outfile.write_text(json.dumps(stable, sort_keys=True, indent=2) + '\n')
    elif mode == 'check':
        saved = json.loads(outfile.read_text())
        if saved != stable:
            raise RuntimeError(f'identity changed: saved={saved}, now={stable}')
    else:
        raise ValueError(mode)
    print(json.dumps(ident, sort_keys=True))


if __name__ == '__main__':
    main()

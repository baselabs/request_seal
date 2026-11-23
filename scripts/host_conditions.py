"""Replay Linux CPU interference from host and workload process counters."""
from collections import defaultdict
import json
import math
from typing import NamedTuple


class HostConditionExhausted(ValueError):
    """Every permitted sample window failed admission."""


class ProcessTimes(NamedTuple):
    pid: int
    parent: int
    started: int
    own: int
    waited: int


def cpu_counters(text):
    """Parse Linux's aggregate CPU counters; guest time is already in user/nice."""
    fields = text.splitlines()[0].split()
    if fields[0] != "cpu" or len(fields) < 9:
        raise ValueError("missing aggregate /proc/stat CPU counters")
    values = [int(value) for value in fields[1:9]]
    if any(value < 0 for value in values):
        raise ValueError("negative CPU counter")
    return values


def process_times(text):
    """Parse process identity and CPU fields, skipping the parenthesized comm."""
    prefix, end, tail = text.rpartition(")")
    pid, start, _ = prefix.partition(" (")
    fields = tail.split()
    if not (start and end and len(fields) >= 20 and int(pid) > 0):
        raise ValueError("missing /proc process CPU counters")
    user, system, child_user, child_system = map(int, fields[11:15])
    if min(user, system, child_user, child_system) < 0:
        raise ValueError("negative process CPU counter")
    return ProcessTimes(int(pid), int(fields[1]), int(fields[19]), user + system,
                        child_user + child_system)


def process_tree(lines):
    if not isinstance(lines, list) or not lines or not all(isinstance(line, str) for line in lines):
        raise ValueError("missing /proc process tree")
    root, *descendants = map(process_times, lines)
    children = defaultdict(list)
    for process in descendants:
        children[process.parent].append(process)
    pending, visited, by_identity = [root], set(), {}
    while pending:
        process = pending.pop()
        if process.pid in visited:
            raise ValueError("duplicate process in /proc tree")
        visited.add(process.pid)
        by_identity[process.pid, process.started] = process
        pending.extend(children.get(process.pid, ()))
    if len(visited) != len(lines):
        raise ValueError("observation must contain a rooted process tree")
    return root, by_identity


def workload_times(before, after):
    """Credit matched live processes and CPU accounted for by the BEAM's waits.

    An end-only live descendant lacks a baseline, so it earns no direct credit.
    The BEAM's cutime/cstime delta covers reaped descendants, including children
    born and reaped between snapshots. Discount the pre-window own and waited
    time of every start-only descendant before crediting any of that wait delta.
    """
    root_before, started = process_tree(before)
    root_after, ended = process_tree(after)
    if (root_before.pid, root_before.started) != (root_after.pid, root_after.started):
        raise ValueError("different /proc workload roots")
    retained = [ended[key].own - started[key].own for key in started.keys() & ended.keys()]
    waited = root_after.waited - root_before.waited
    if waited < 0 or any(delta < 0 for delta in retained):
        raise ValueError("regressing /proc process CPU counters")
    baseline = sum(started[key].own + started[key].waited for key in started.keys() - ended.keys())
    return sum(retained) + max(0, waited - baseline)


def load_average(text):
    value = float(text.split()[0])
    if not math.isfinite(value) or value < 0:
        raise ValueError("invalid /proc/loadavg")
    return value


def metrics(observation):
    before = cpu_counters(observation["cpu_before"])
    after = cpu_counters(observation["cpu_after"])
    workload = workload_times(observation["process_before"], observation["process_after"])
    user, nice, system, idle, iowait, irq, softirq, stolen = (b - a for a, b in zip(before, after))
    elapsed = user + nice + system + idle + iowait + irq + softirq + stolen
    foreign = user + nice + system + irq + softirq - workload
    return {
        "load": load_average(observation["loadavg"]),
        "steal": 100 * stolen / elapsed if elapsed > 0 and 0 <= stolen <= elapsed else None,
        "foreign_cpu": 100 * foreign / elapsed if elapsed > 0 else None,
    }


def admitted(metrics):
    steal, foreign = metrics["steal"], metrics["foreign_cpu"]
    return steal is not None and 0 <= steal <= 5 and foreign is not None and 0 <= foreign <= 10


def admit(observations, attempts):
    """Replay the retry budget from retained /proc samples."""
    seen = []
    for observation in observations[:attempts]:
        measured = metrics(observation)
        seen.append(measured)
        if any(observation[key] != value for key, value in measured.items()):
            raise ValueError("host observation disagrees with /proc counters")
        if admitted(measured):
            return observation
    raise HostConditionExhausted("host condition exhausted: " + json.dumps(seen))

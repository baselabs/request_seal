"""Parse Linux host observations and apply the shared load and CPU steal rule."""
import json
import math


class HostConditionExhausted(ValueError):
    """Every permitted sample window failed admission."""


def cpu_times(text):
    """Parse Linux's aggregate CPU counters; guest time is already in user/nice."""
    fields = text.splitlines()[0].split()
    if fields[0] != "cpu" or len(fields) < 9:
        raise ValueError("missing aggregate /proc/stat CPU counters")
    values = [int(value) for value in fields[1:9]]
    if any(value < 0 for value in values):
        raise ValueError("negative CPU counter")
    return sum(values), values[7]


def load_average(text):
    value = float(text.split()[0])
    if not math.isfinite(value) or value < 0:
        raise ValueError("invalid /proc/loadavg")
    return value


def steal_percent(before, after):
    total_before, steal_before = cpu_times(before)
    total_after, steal_after = cpu_times(after)
    elapsed, stolen = total_after - total_before, steal_after - steal_before
    if elapsed <= 0 or stolen < 0 or stolen > elapsed:
        return None
    return 100 * stolen / elapsed


def admit(observations, cpus, attempts):
    """Replay the shared load/steal retry budget from retained /proc samples."""
    seen = []
    for observation in observations[:attempts]:
        load = load_average(observation["loadavg"])
        steal = steal_percent(observation["cpu_before"], observation["cpu_after"])
        seen.append({"load": load, "steal": steal})
        if observation["load"] != load or observation["steal"] != steal:
            raise ValueError("host observation disagrees with /proc counters")
        if load <= cpus and steal is not None and 0 <= steal <= 5:
            return observation
    raise HostConditionExhausted("host condition exhausted: " + json.dumps(seen))

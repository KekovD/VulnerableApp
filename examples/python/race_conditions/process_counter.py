"""CWE-362: multiprocessing.Value locks property access, not the whole update."""


def increment_vulnerable(shared_value, after_read=None):
    previous = shared_value.value
    if after_read is not None:
        after_read()
    shared_value.value = previous + 1  # RACE: PY-RACE-008


def increment_safe(shared_value):
    with shared_value.get_lock():
        shared_value.value = shared_value.value + 1  # SAFE: PY-RACE-008

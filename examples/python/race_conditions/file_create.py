"""CWE-367: checking for absence before opening in write mode permits overwrite."""


def create_vulnerable(path, contents, after_check=None):
    if path.exists():
        return False
    if after_check is not None:
        after_check()
    with path.open("w", encoding="utf-8") as stream:  # RACE: PY-RACE-006
        stream.write(contents)
    return True


def create_safe(path, contents):
    try:
        # Exclusive creation combines the absence check and creation atomically.
        with path.open("x", encoding="utf-8") as stream:  # SAFE: PY-RACE-006
            stream.write(contents)
        return True
    except FileExistsError:
        return False

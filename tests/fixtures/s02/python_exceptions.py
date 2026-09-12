def convert(value):
    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError("bad value") from exc
    except TypeError:
        raise

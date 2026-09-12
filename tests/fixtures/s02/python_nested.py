def outer(flag):
    if flag:
        def inner(value):
            if value:
                return 1
            return 0
        return inner(flag)
    return 0

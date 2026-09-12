def branchy(x):
    total = 0
    if x:
        for i in range(3):
            if i % 2:
                total += i
    while total < x:
        total += 1
    return total if x else 0

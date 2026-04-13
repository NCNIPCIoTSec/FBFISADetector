def align_down(x, a=0x1000):
    return x & ~(a - 1)

def align_up(x, a=0x1000):
    return (x + (a - 1)) & ~(a - 1)

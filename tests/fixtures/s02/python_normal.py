import math

class Sample:
    """Example."""

    def area(self, radius: float) -> float:
        if radius < 0:
            raise ValueError("radius")
        return math.pi * radius ** 2

# module note
def clamp(value, lower=0, upper=10):
    return lower if value < lower else upper if value > upper else value

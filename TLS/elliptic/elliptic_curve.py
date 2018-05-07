from collections import namedtuple


Point = namedtuple('Point', ['x', 'y', 'z'])


class EllipticCurve:
    def __init__(self, curve_id):
        pass

    def summ(self, point_a, point_b):
        pass

    def double(self, point):
        pass

    def get_multiplicity(self, point):
        pass

    def is_on_curve(self, point):
        right_part = point.x ** 3 + self.a * point.x * point.z ** 2 + self.b * point.z ** 3
        return point.y ** 2 * point.z == right_part

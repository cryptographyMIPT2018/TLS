from collections import namedtuple


Point = namedtuple('Point', ['x', 'y', 'z'])


class EllipticCurve:
    def __init__(self, curve_id):
        pass

    def summ(self, point_a, point_b):
        pass

    def double(self, point):
        pass

    def multiply_by_number(self, point, number):
        result = self.P
        point_power = self.point
        number = number % self.m

        while True:
            if number % 2 == 1:
                result = self.summ(point_power, result)
            if number < 2:
                break
            point_power = self.double(point_power)
            number = number // 2

        return result

    def is_on_curve(self, point):
        right_part = point.x ** 3 + self.a * point.x * point.z ** 2 + self.b * point.z ** 3
        return point.y ** 2 * point.z == right_part

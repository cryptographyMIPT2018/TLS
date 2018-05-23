def gcd(a, b):
    if a == 0:
        x = 0
        y = 1
        return b, x, y
    g, tmp_x, tmp_y = gcd(b % a, a)
    x = tmp_y - int(b / a) * tmp_x
    y = tmp_x
    return g, x, y


def get_inversed(a, p):
    g, x, y = gcd(a, p)
    return (x % p + p) % p


class Point:
    def __init__(self, x, y, z=1):
        self.x = x
        self.y = y
        self.z = z

    def __eq__(self, point):
        if self.z * point.z:
            return self.x * point.z == point.x * self.z and self.y * point.z == point.y * self.z
        else:
            if not self.z == point.z:
                return False
            if ((self.x == 0) and (point.x != 0)) or ((self.y == 0) and (point.y != 0)):
                return False
            return self.x * point.y == self.y * point.x

    def __str__(self):
        if self.z == 1:
            cords = str((self.x, self.y))
        else:
            cords = str((self.x, self.y, self.z))
        return 'Point: ' + cords

    def to_bytes(self):
        return int.to_bytes(self.x, 64, 'little') + int.to_bytes(self.y, 64, 'little')

    @staticmethod
    def from_bytes(byte_data):
        assert(len(byte_data) == 128)
        x = int.from_bytes(byte_data[:64], 'big')
        y = int.from_bytes(byte_data[64:], 'big')
        return Point(x,y)




class NotOnTheCurve(Exception):
    pass


class EllipticCurve:

    PARAMETERS = {
        "A": {
            'a': 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006083524,
            'b': 12190580024266230156189424758340094075514844064736231252208772337825397464478540423418981074322718899427039088997221609947354520590448683948135300824418144,
            'm': 13407807929942597099574024998205846127479365820592393377723561443721764030073449232318290585817636498049628612556596899500625279906416653993875474742293109,
            'p': 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006083527,
            'q': 13407807929942597099574024998205846127479365820592393377723561443721764030073449232318290585817636498049628612556596899500625279906416653993875474742293109,
            'x': 3,
            'y': 6128567132159368375550676650534153371826708807906353132296049546866464545472607119134529221703336921516405107369028606191097747738367571924466694236795556
        },
        "B": {
            'a': 6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042156,
            'b': 5472517130514047254760433071281657274171034389553769779747941603125796549693907036696237273952702637857580071293254240945079496484373854264998452887027990,
            'm': 6703903964971298549787012499102923063739682910296196688861780721860882015036922585419853748190383615062910947743405567510148398820717100282856877776119229,
            'p': 6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042159,
            'q': 6703903964971298549787012499102923063739682910296196688861780721860882015036922585419853748190383615062910947743405567510148398820717100282856877776119229,
            'x': 2,
            'y': 1391087797795557258711735874750463328666729297647553860794340434982072762491277963324668489993185089365703033494204180568181905548968011075910357787492797
        },
        "test": {
            'a': 2,
            'b': 3,
            'm': 97,
            'p': 97,
            'q': 97,
            'x': 17,
            'y': 10
        }
    }

    def __init__(self, curve_id=None, curve=None):
        if curve_id is not None and curve is not None:
            raise ValueError('curve_id and curve must not be set simultaneously')

        if curve_id is not None:
            assert(curve_id in self.PARAMETERS)
            self.__dict__.update(self.PARAMETERS[curve_id])
        elif curve is not None:
            assert(set(curve.keys()) == set(self.PARAMETERS['A']))
            self.__dict__.update(curve)
        else:
            raise ValueError('curve_id or curve must be set')

    def get_forming(self):
        return Point(self.x, self.y)

    def get_zero(self):
        return Point(0, 1, 0)

    def is_zero(self, point):
        if point.z != 0:
            return False
        else:
            if (point.x == 0) and (point.y != 0):
                return True
            else:
                raise NotOnTheCurve()

    def check_point(self, point):
        assert point.z == 0 or point.z == 1

    def check_points(self, *points):
        for point in points:
            self.check_point(point)

    def _mod_p(self, a):
        return (a % self.p + self.p) % self.p

    def summ(self, point_p, point_q):
        self.check_points(point_p, point_q)
        if self.is_zero(point_p):
            return point_q
        if self.is_zero(point_q):
            return point_p
        if point_p != point_q:
            if point_p.x == point_q.x:
                return self.get_zero()

            inversed = get_inversed(self._mod_p(point_p.x - point_q.x), self.p)
            lam = self._mod_p((point_p.y - point_q.y) * inversed)
        else:
            inversed = get_inversed(self._mod_p(2 * point_p.y), self.p)
            lam = self._mod_p((3 * point_p.x ** 2 + self.a) * inversed)

        x_ab = self._mod_p(lam ** 2 - point_p.x - point_q.x)
        return Point(
            x_ab,
            self._mod_p(lam * (point_q.x - x_ab) - point_q.y)
        )

    def double(self, point):
        return self.summ(point, point)

    def multiply_by_number(self, point, number):
        result = self.get_zero()
        point_power = point
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
        left_part = point.y ** 2 * point.z
        return (right_part - left_part) % self.p == 0

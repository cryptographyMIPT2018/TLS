import abc


class Structure(abc.ABC):
    @abc.abstractmethod
    def parse_bytes(self, bytes_str):
        """
        Returns: dict
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def to_bytes(self, data):
        """
        data: dict of bytes
            if it is leaf node - bytes, otherwise - dict
        """
        raise NotImplementedError()


class NoLengthStructure(Structure):
    def __init__(self, children, name=""):
        self._children = children
        self.name = name

    def parse_bytes(self, bytes_str):
        result_data = {}
        total_len = 0
        for child in self._children:
            child_data, child_length = child.parse_bytes(bytes_str)
            total_len += child_length
            bytes_str = bytes_str[child_length:]
            result_data.update(child_data)

        if self.name:
            result_data = {self.name: result_data}

        return result_data, total_len

    def to_bytes(self, data):
        result_bytes = b''
        for child in self._children:
            result_bytes += child.to_bytes(data[child.name])

        return result_bytes


class VariableLenStructure(Structure):
    def __init__(self, name, length_of_length, children=[]):
        self.name = name
        self._length_of_length = length_of_length
        self._children = children

    def parse_bytes(self, bytes_str):
        length = int.from_bytes(bytes_str[:self._length_of_length], byteorder='big')
        total_length = self._length_of_length + length
        check_length = 0

        cutted_str = bytes_str[self._length_of_length:total_length]
        if len(self._children):
            result_data = {}
            for child in self._children:
                child_data, child_length = child.parse_bytes(cutted_str)
                check_length += child_length
                cutted_str = cutted_str[child_length:]
                result_data.update(child_data)

            assert check_length == length
            return {self.name: result_data}, total_length
        else:
            return {self.name: cutted_str}, total_length

    def to_bytes(self, data):
        if len(self._children):
            bytes_str = b''
            for child in self._children:
                bytes_str += child.to_bytes(data[child.name])
        else:
            bytes_str = data

        len_bytes = int.to_bytes(len(bytes_str), self._length_of_length, byteorder='big')
        return len_bytes + bytes_str


class FixedLenStructure(Structure):
    def __init__(self, name, length):
        self.name = name
        self._length = length

    def parse_bytes(self, bytes_str):
        return {self.name: bytes_str[:self._length]}, self._length

    def to_bytes(self, data):
        return data


class ListStructure(Structure):
    def __init__(self, name, length_of_length, children, list_length=None):
        self.name = name
        self._length_of_length = length_of_length
        if list_length is not None:
            assert isinstance(children, Structure)
            self._children = [children] * list_length
        else:
            self._children = children

    def parse_bytes(self, bytes_str):
        length = int.from_bytes(bytes_str[:self._length_of_length], byteorder='big')
        total_length = length + self._length_of_length
        check_length = 0
        result = []
        cutted_str = bytes_str[self._length_of_length:]

        for child in self._children:
            child_data, child_length = child.parse_bytes(cutted_str)
            check_length += child_length
            cutted_str = cutted_str[child_length:]
            result.append(child_data)

        assert length == check_length, "length {} should be equal to sum child length {}".format(length, check_length)
        return {self.name: result}, total_length

    def to_bytes(self, data):
        result = b''

        for child, child_data in zip(self._children, data):
            result += child.to_bytes(child_data[child.name])

        result = int.to_bytes(len(result), self._length_of_length, byteorder='big') + result
        return result

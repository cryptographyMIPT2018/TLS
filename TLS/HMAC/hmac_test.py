import unittest

from TLS.HMAC.hmac import *


# PROBLEMS WITH DOCUMENTATION TESTS. TEST FROM https://ru.wikipedia.org/wiki/HMAC
class HmacTest1(unittest.TestCase):
    def test_hash_256(self):
        key = bytes.fromhex("707172737475767778797a7b7c7d7e7f80818283")
        data = bytes.fromhex("48656c6c 6f20576f 726c64")
        self.assertEqual(hmac_sha(key, data),
                         bytes.fromhex("2e492768 aa339e32 a9280569 c5d02626 2b912431"))


if __name__ == '__main__':
    unittest.main()

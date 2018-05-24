import sys
import os

cert_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(cert_dir, '../../'))

from .public_keys import public_keys
from .private_key import private_key
from TLS.elliptic.elliptic_curve import Point


def get_certificate_bytes(user_id):
    """
    Args:
        user_id: int
    Returns: bytes
    """
    public_key = public_keys[str(user_id)]
    id_bytes = int.to_bytes(user_id, 1, 'big')
    public_key_bytes = Point(public_key[0], public_key[1]).to_bytes()
    return id_bytes + public_key_bytes


def get_public_key(certificate_bytes):
    """
    Args:
        certificate_bytes: bytes
    Returns: Point
    """
    return Point.from_bytes(certificate_bytes[1:])


def get_id(certificate_bytes):
    """
    Args:
        certificate_bytes: bytes
    Returns: int
    """
    return int.from_bytes(certificate_bytes[:1], 'big')


def verify_certificate(certificate_bytes):
    """
    Args:
        certificate_bytes: bytes
    Returns: bool
        True if valid, False otherwise
    Raise:
        AssertionError
            then len(certificate_bytes) != 129
    """
    assert len(certificate_bytes) == 129, "certificate len should be 129, got {}".format(len(certificate_bytes))

    user_id = get_id(certificate_bytes)
    user_public_key = public_keys[str(user_id)]
    user_public_key = Point(user_public_key[0], user_public_key[1])
    cert_public_key = get_public_key(certificate_bytes)

    return user_public_key == cert_public_key


def get_private_key_bytes():
    return int.to_bytes(private_key, 64, 'big')

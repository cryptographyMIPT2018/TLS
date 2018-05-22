import sys
import os

certs_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(certs_dir, '../../'))

from TLS.elliptic.elliptic_curve import EllipticCurve
import random
import argparse
import json


def generate_key_pair(user_id, secret_key):
    if user_id < 0 or user_id > 255:
        raise ValueError('user_id should be from 0 to 255')

    if secret_key is None:
        secret_key = random.randint(0, EllipticCurve.PARAMETERS["B"]['q'] - 1)

    path_to_private_key_file = os.path.join(certs_dir, 'private_key.py')
    path_to_public_key_file = os.path.join(certs_dir, 'public_keys.py')

    if os.path.exists(path_to_public_key_file):
        with open(path_to_public_key_file, 'r') as public_key_file:
            json_str = public_key_file.readlines()[0].split('=')[-1].strip()
            public_keys = json.loads(json_str)
    else:
        public_keys = {}

    if str(user_id) in public_keys:
        raise ValueError('user_id {} is already used'.format(user_id))

    curve = EllipticCurve(curve_id="B")
    public_key = curve.multiply_by_number(curve.get_forming(), secret_key)
    public_key = (public_key.x, public_key.y)

    with open(path_to_private_key_file, 'w') as private_key_file:
        private_key_file.write('secret_key = {}\n'.format(secret_key))

    with open(path_to_public_key_file, 'w') as public_key_file:
        public_keys[str(user_id)] = public_key
        json_str = json.dumps(public_keys)
        public_key_file.write('public_keys = ' + json_str)


def parse_args():
    parser = argparse.ArgumentParser(description='script for generating key pair')
    parser.add_argument('--id', type=int, required=True, help='your id, should be from 0 to 255')
    parser.add_argument('--secret_key', type=int, help='if not specifeid generated randomly')

    return parser.parse_args()



def main():
    args = parse_args()
    generate_key_pair(args.id, args.secret_key)


if __name__ == '__main__':
    main()

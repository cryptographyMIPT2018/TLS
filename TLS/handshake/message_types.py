class MessageTypes:
    hello_request = b'\x00'
    client_hello = b'\x01'
    server_hello = b'\x02'
    certificate = b'\x11'
    certificate_request = b'\x13'
    server_hello_done = b'\x14'
    certificate_verify = b'\x15'
    client_key_exchange = b'\x16'
    finished = b'\x20'
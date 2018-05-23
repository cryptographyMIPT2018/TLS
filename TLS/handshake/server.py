import json import dumps, loads

class Server:
    def __init__(self):
        pass

    def receive_message(self, message):
    """
    message: bytes
    """
        message_type = (message[0])
        header = message[:3]
        json = loads(message)

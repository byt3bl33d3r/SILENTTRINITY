import functools
import zlib
import base64
from silenttrinity.core.teamserver import ipc_server

def subscribe(event):
    def inner_function(function):
        function._event_subscription = event
        @functools.wraps(function)
        def wrapper(self, *args, **kwargs):
            function(self, *args, **kwargs)
        return wrapper
    return inner_function

def register_subscriptions(cls):
    for methodname in dir(cls):
        method = getattr(cls, methodname)
        if hasattr(method, '_event_subscription'):
            ipc_server.attach(method._event_subscription, method)
    return cls

def dotnet_decode_and_inflate(data):
    """
    https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
    """

    decoded_data = base64.b64decode(data)
    return zlib.decompress(decoded_data, -15)

def dotnet_deflate_and_encode(data):
    """
    https://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
    """

    zlibbed_data = zlib.compress(data, 9)
    compressed_data = zlibbed_data[2:-4]
    return base64.b64encode(compressed_data).decode()

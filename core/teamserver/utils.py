import functools
from core.teamserver import ipc_server

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

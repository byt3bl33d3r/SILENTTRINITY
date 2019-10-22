from functools import wraps
from typing import get_type_hints, List
from silenttrinity.core.utils import CmdError

def command(func):
    func._command = True

    @wraps(func)
    def wrapper(*args, **kwargs):
        cmd_args = kwargs["args"]
        validated_args = {}
        for name, hint in get_type_hints(func).items():
            if name == 'response': continue
            try:
                value = cmd_args[f'<{name}>']
            except KeyError:
                try:
                    value = cmd_args[f'--{name}']
                except KeyError:
                    raise CmdError(f"Unable to find '{name}' argument in command definition")

            try:
                validated_args[name] = hint(value)
            except TypeError:
                # I'm still not sure if there's a way to dynamically cast Lists and Dicts using type hints
                if hint == List[int]:
                    validated_args[name] = [int(x) for x in value]
                elif hint == List[str]:
                    validated_args[name] = [str(x) for x in value]
                else:
                    raise NotImplementedError(f"Casting for type '{hint}' has not been implemented")

        return func(args[0], **validated_args, response=kwargs["response"]) if args[0].__class__._remote is True else func(args[0], **validated_args)
    return wrapper

def register_cli_commands(cls):
    cls._cmd_registry = []
    for methodname in dir(cls):
        method = getattr(cls, methodname)
        if hasattr(method, '_command'):
            cls._cmd_registry.append(methodname)
    return cls

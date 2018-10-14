import os


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def parse_internal_helpers(command):
    local_functions = globals()
    if command in local_functions:
        local_functions[command]()
        return True
    return False

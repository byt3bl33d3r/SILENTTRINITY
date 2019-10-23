import logging
import os
from io import StringIO
from silenttrinity.core.utils import get_path_in_package

assemblyresolve_event_handler = """public static def MyResolveEventHandler(sender as object, args as ResolveEventArgs) as Assembly:
    #print("Trying to resolve $(args.Name).dll")
    result = [asm for asm in AppDomain.CurrentDomain.GetAssemblies()].Find() do (item as Assembly):
        return @/,/.Split(item.ToString())[0] == args.Name
    return result"""

assemblyresolve_event_hook = "AppDomain.CurrentDomain.AssemblyResolve += ResolveEventHandler(MyResolveEventHandler)"

def get_comms(comms):
    comms_section = StringIO()
    comm_classes = []
    for channel in comms:
        for comm_file in os.listdir(get_path_in_package("core/teamserver/comms/")):
            if comm_file.endswith('.boo') and channel.strip().lower() == comm_file[:-4].lower():
                comm_classes.append(f"{channel.strip().upper()}()")
                with open(os.path.join(get_path_in_package("core/teamserver/comms/"), comm_file)) as channel_code:
                    comms_section.write(channel_code.read())

    return ", ".join(comm_classes), comms_section.getvalue()

def gen_stager_code(comms, hook_assemblyresolve_event=False):
    with open(get_path_in_package("core/teamserver/data/stage.boo")) as stage:
        comm_classes, comms_section = get_comms(comms)
        stage = stage.read()
        stage = stage.replace("PUT_COMMS_HERE", comms_section)
        stage = stage.replace("PUT_COMM_CLASSES_HERE", comm_classes)
        stage = stage.replace("ASSEMBLY_RESOLVE_HOOK_GOES_HERE", assemblyresolve_event_hook if hook_assemblyresolve_event else '')
        stage = stage.replace("ASSEMBLY_RESOLVE_EVENT_HANDLER_GOES_HERE", assemblyresolve_event_handler if hook_assemblyresolve_event else '')
        return stage

import logging
import os
from io import StringIO

def get_comms(comms):
    comms_section = StringIO()
    comm_classes = []
    for channel in comms:
        for comm_file in os.listdir('./core/teamserver/comms/'):
            if comm_file.endswith('.boo') and channel.strip().lower() == comm_file[:-4].lower():
                comm_classes.append(f"{channel.strip().upper()}()")
                with open(os.path.join('./core/teamserver/comms/', comm_file)) as channel_code:
                    comms_section.write(channel_code.read())

    return ", ".join(comm_classes), comms_section.getvalue()

#@subscribe(events.ENCRYPT_STAGE)
def gen_stager_code(comms):
    with open('./core/teamserver/data/stage.boo') as stage:
        comm_classes, comms_section = get_comms(comms)
        stage = stage.read()
        stage = stage.replace("PUT_COMMS_HERE", comms_section)
        stage = stage.replace("PUT_COMM_CLASSES_HERE", comm_classes)
        return stage

import logging
import multiprocessing
from silenttrinity.core.ipcserver import IPCServer
logging.basicConfig(
    format="[%(levelname)s] %(message)s",
    level=logging.INFO
)

# disable all loggers from different files
#logging.getLogger('asyncio').setLevel(logging.ERROR)
#logging.getLogger('asyncio.coroutines').setLevel(logging.ERROR)
logging.getLogger('websockets.server').setLevel(logging.ERROR)
logging.getLogger('websockets.protocol').setLevel(logging.ERROR)

multiprocessing.set_start_method("fork")

ipc_server = IPCServer()
ipc_server.start()

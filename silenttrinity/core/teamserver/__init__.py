import logging
from silenttrinity.core.ipcserver import IPCServer
logging.basicConfig(
    format="%(asctime)s %(process)d %(threadName)s - [%(levelname)s] %(filename)s: %(funcName)s - %(message)s",
    level=logging.DEBUG
)

# disable all loggers from different files
#logging.getLogger('asyncio').setLevel(logging.ERROR)
#logging.getLogger('asyncio.coroutines').setLevel(logging.ERROR)
logging.getLogger('websockets.server').setLevel(logging.ERROR)
logging.getLogger('websockets.protocol').setLevel(logging.ERROR)

ipc_server = IPCServer()
ipc_server.start()
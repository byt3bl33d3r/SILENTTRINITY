import logging
from core.ipcserver import IPCServer
logging.basicConfig(
    format="%(asctime)s %(process)d %(threadName)s - [%(levelname)s] %(filename)s: %(funcName)s - %(message)s",
    level=logging.DEBUG
)

ipc_server = IPCServer()
ipc_server.start()
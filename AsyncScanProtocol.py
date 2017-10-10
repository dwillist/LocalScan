import asyncio
import logging


class AsyncScanProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.loop = loop

    # so we can easily close after a connection is established... but can we get any info form this obj
    # such as ip/ or port?
    def connection_made(self, transport):
        connection_info = transport.get_extra_info('peername')
        # logging.debug("connection made with " + str(connection_info))
        return connection_info

    def connection_lost(self, exc):
        logging.debug("connection lost")
        pass

from platform import system as sys_name
from subprocess import DEVNULL
from AsyncScanProtocol import AsyncScanProtocol
from ipaddress import ip_address
import asyncio


class NetworkScanner:
    def __init__(self, network):
        """ expects an iterable network object that will yield valid IP addresses to be scanned
        a good choice would be an object returned from ipaddress.network.hosts"""
        self.network = network
        self.asyncloop = asyncio.get_event_loop()

    def __del__(self):
        self.asyncloop.close()

    async def _run_tasks(self, task_function, task_args):
        """
        runs all tasks on the self.pending tasks queue
        :return: a copy of self.pending_tasks to the user, these should have a task.result() value
        """
        if not task_args:
            raise ValueError("empty task_args")
        current_tasks = [task_function(*args) for args in task_args]
        return await asyncio.wait(current_tasks)

    async def _ping_host_async(self, hostname, packet_count, ttl):
        """
        Returns error code when attempting to ping hostname
        packet_count is number of packets we should send.
        ttl or 'time to live' is milliseconds that each packet should live
        Some hosts may not respond to a ping request even if the host name is valid.
        """
        # Ping parameters as function of OS
        parameters = "-c {}".format(packet_count) + " -W {}".format(ttl)
        if sys_name().lower() == 'windows':
            parameters = "-n {}".format(packet_count) + " -w {}".format(ttl)
        cmd = '{} {} {}'.format('ping', parameters, hostname)
        proc = await asyncio.create_subprocess_shell(cmd, stdin=DEVNULL, stderr=DEVNULL, stdout=DEVNULL)
        return await proc.wait(), hostname

    def ping_sweep(self, packet_count=2, ttl=1000):
        args_tups = [(ip, packet_count, ttl) for ip in self.network]
        completed_tasks = self.asyncloop.run_until_complete(self._run_tasks(self._ping_host_async, args_tups))
        return [done_task.result()[1] for done_task in completed_tasks[0] if done_task.result()[0]==0]

    async def _tcp_scan_async(self, host_ip, port, timeout=3):
        trans, _ = None, None
        try:
            # need to add a timeout
            trans, _ = await asyncio.wait_for(
                self.asyncloop.create_connection(lambda: AsyncScanProtocol(self.asyncloop), str(host_ip), port),
                timeout)
        except ConnectionRefusedError:
            pass
        finally:
            if trans:
                trans.close()
            return trans

    def tcp_sweep(self, ports=[21, 22, 23, 25, 53, 443, 110, 135, 137, 138, 139, 1433]):
        args_tup = [(ip_addr,port) for ip_addr in self.network.hosts() for port in ports]
        results = self.asyncloop.run_until_complete(self._run_tasks(self._tcp_scan_async, args_tup))
        ip_port_tuples = [task.result().get_extra_info('peername') for task in results[0] if task.result()]
        return list(map(lambda x : (ip_address(x[0]),x[1]),ip_port_tuples))

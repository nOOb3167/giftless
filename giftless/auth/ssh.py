from __future__ import annotations
import abc
import asyncio
import asyncio.subprocess
import contextlib
import collections.abc
import functools
import giftless.auth.ssh_util as util
import logging
import paramiko
import paramiko.common
import paramiko.pipe
import select
import socket
import typing


server_private_key = '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACDI9vLirefGYftjW2TwMvHs03vE1Ja6z82m/tNfmbk8sQAA
AKAsaDjeLGg43gAAAAtzc2gtZWQyNTUxOQAAACDI9vLirefGYftjW2TwMvHs03vE
1Ja6z82m/tNfmbk8sQAAAEByvVNWu+C19TiL6NvLle+rAzRPeLNmlJ4iRKVu28UQ
ccj28uKt58Zh+2NbZPAy8ezTe8TUlrrPzab+01+ZuTyxAAAADmVkMjU1MTkta2V5
LTAwAQIDBAUGBwgJCgsMDQ4P
-----END OPENSSH PRIVATE KEY-----
'''


READ_BUF_SIZE = 1024


log = util.ConIdLogAdapter(logging.getLogger(__name__), extra={})


class ResurrectableAccept(util.ResurrectableTask):
    def __init__(self):
        super().__init__()


class ChannelReadWaiter:
    chan: paramiko.Channel
    fileno: int
    _rsock: socket.socket
    _wsock: socket.socket

    def __init__(self, chan: paramiko.Channel):
        self.chan = chan
        self.fileno = chan.fileno() # causes _pipe instantiation
        with chan.lock:
            assert isinstance(chan._pipe, paramiko.pipe.WindowsPipe) # FIXME:
            self._rsock = chan._pipe._rsock
            self._wsock = chan._pipe._wsock

    def wait_read(self):
        rl, wl, xl = select.select([self.fileno], [], [])
        assert len(rl) and rl[0] == self.fileno

    async def wait_read_a(self):
        # FIXME: maybe need to acquire chan.in_buffer.lock
        await loop().sock_recv(self._rsock, 1)
        await loop().sock_sendall(self._wsock, b"*")


class AsyncServ:
    CHANNEL_ACCEPT_TIMEOUT = 120
    loop: asyncio.AbstractEventLoop
    sock: socket.socket
    server_key: paramiko.PKey

    def __init__(self, sock: socket.socket, server_key: paramiko.PKey):
        self.loop = asyncio.new_event_loop()
        self.sock = sock
        self.server_key = server_key

    def run_until_complete(self):
        self.loop.run_until_complete(self.start_())

    async def start_(self):
        conid: int = 0
        log.info(f'Starting to accept connections')
        accept = ResurrectableAccept()
        waiter = util.ResurrectableWaiter[ResurrectableAccept](accept)
        while True:
            with waiter.needing_resurrect() as nr:
                with accept.with_try_take(nr) as a:
                    if a is not None:
                        with a.with_resurrect_check():
                            a.task = loop().create_task(loop().sock_accept(self.sock))
                async with waiter.wait() as done:
                    async with util.task_awaiter(done.tasks):
                        with accept.with_try_take(done.resus) as a:
                            if a is not None:
                                nsock, addr = await a.task
                                with util.ctx_conid((conid := conid + 1)):
                                    waiter.add_task(loop().create_task(self.start_con(set_nodelay(nsock))))

    async def start_con(self, nsock: socket.socket):
        with paramiko.Transport(nsock) as t:
            protocol_negotiation_future = loop().create_future()
            command_future = loop().create_future()
            server = ParamikoServerCb(
                loop=loop(),
                coro_auth_publickey=self._cb_auth_publickey,
                coro_exec_request_pre=functools.partial(self._cb_exec_request_pre, command_future))
            t.add_server_key(key=self.server_key)
            t.start_server(event=util.FutureEvent(loop(), protocol_negotiation_future), server=server)
            log.info(f'waiting for protocol negotiation')
            await protocol_negotiation_future
            log.info(f'after_negotiation')
            command = await command_future
            log.info(f'command {command}')

            await asyncio.sleep(0)

            with util.ctx_channel(t, self.CHANNEL_ACCEPT_TIMEOUT) as chan:
                crw = ChannelReadWaiter(chan)

                comOq, comEq, comIq = [asyncio.Queue[util.DataT]() for x in range(3)]

                proc = await asyncio.create_subprocess_exec(command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                rds = [loop().create_task(self._command_reader_stdout(proc, comOq), name='_command_reader_stdout'),
                    loop().create_task(self._command_reader_stderr(proc, comEq), name='_command_reader_stderr'),
                    loop().create_task(self._command_writer_stdin(proc, comIq), name='_command_writer_stdin'),
                    loop().create_task(self._channel_reader(crw, chan, comIq), name='_channel_reader'),
                    loop().create_task(self._channel_writer_stdout(chan, comOq), name='_channel_writer_stdout'),
                    #self._channel_writer_stderr(chan, comEq),
                    loop().create_task(proc.wait(), name='proc.wait')]
                async for rd in util.as_completed(rds):
                    res = await rd
                    log.info(f'rds finished | {rd.get_name()} | {res}')

            return

    async def _cb_auth_publickey(self, username: str, key: paramiko.PKey) -> bool:
        log.info(f'auth_publickey')
        return True

    async def _cb_exec_request_pre(self, command_future: asyncio.Future, channel: paramiko.Channel, command: str) -> bool:
        command_future.set_result(command)
        log.info(f'exec_request_pre')
        return True

    async def _command_reader_stdout(self, proc: asyncio.subprocess.Process, b: asyncio.Queue[util.DataT]):
        sr: asyncio.StreamReader = proc.stdout
        while True:
            if len(data := await sr.read(READ_BUF_SIZE)):
                log.info(f'sod {data}')
                b.put_nowait(data)
            else:
                log.info(f'sod {data}')
                b.put_nowait(util.Eof())
                break

    async def _command_reader_stderr(self, proc: asyncio.subprocess.Process, b: asyncio.Queue[util.DataT]):
        sr: asyncio.StreamReader = proc.stderr
        while True:
            if len(data := await sr.read(READ_BUF_SIZE)):
                b.put_nowait(data)
            else:
                b.put_nowait(util.Eof())
                break

    async def _command_writer_stdin(self, proc: asyncio.subprocess.Process, b: asyncio.Queue[util.DataT]):
        sw: asyncio.StreamWriter = proc.stdin
        while True:
            async with util.queue_get(b) as data:
                log.info(f'sid {data}')
                if len(data):
                    sw.write(data)
                    await sw.drain()
                else:
                    sw.write_eof()
                    await sw.wait_closed()
                    break

    async def _channel_reader(self, crw: ChannelReadWaiter, chan: paramiko.Channel, b: asyncio.Queue[util.DataT]):
        while True:
            await crw.wait_read_a()
            assert not chan.recv_stderr_ready(), 'Channel sent input data over stderr? (SSH_EXTENDED_DATA_STDERR)'
            data = chan.recv(READ_BUF_SIZE)
            log.info(f'cr {data}')
            if len(data):
                b.put_nowait(data)
            else:
                b.put_nowait(util.Eof())
                break

    async def _channel_writer_stdout(self, chan: paramiko.Channel, b: asyncio.Queue[util.DataT]):
        def writer_func(data: util.DataT):
            assert isinstance(data, bytes)
            chan.sendall(data)
        while True:
            async with util.queue_get(b) as data:
                if len(data):
                    await asyncio.to_thread(writer_func, data)
                else:
                    chan.shutdown_write()
                    break


class ParamikoServerCb(paramiko.ServerInterface, metaclass=abc.ABCMeta):
    con_have_chan_request: bool
    loop: asyncio.AbstractEventLoop
    coro_auth_publickey: typing.Callable[[str, paramiko.PKey], collections.abc.Coroutine[typing.Any, typing.Any, bool]]
    coro_exec_request_pre: typing.Callable[[paramiko.Channel, str], collections.abc.Coroutine[typing.Any, typing.Any, bool]]

    def __init__(self, loop: asyncio.AbstractEventLoop,
                 coro_auth_publickey: typing.Callable[[str, paramiko.PKey], collections.abc.Coroutine[typing.Any, typing.Any, bool]],
                 coro_exec_request_pre: typing.Callable[[paramiko.Channel, str], collections.abc.Coroutine[typing.Any, typing.Any, bool]]):

        self.con_have_chan_request = False
        self.loop = loop
        self.coro_auth_publickey = coro_auth_publickey
        self.coro_exec_request_pre = coro_exec_request_pre

    def check_channel_request(self, kind: str, chanid: int):
        try:
            if not self.con_have_chan_request and kind == "session":
                return paramiko.common.OPEN_SUCCEEDED
            return paramiko.common.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        finally:
            self.con_have_chan_request = True

    def get_allowed_auths(self, username: str):
        return "publickey"

    def check_auth_publickey(self, username: str, key: paramiko.PKey):
        with suppress_and_log():
            if asyncio.run_coroutine_threadsafe(self.coro_auth_publickey(username, key), loop=self.loop).result():
                return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_channel_exec_request(self, channel: paramiko.Channel, command: str):
        with suppress_and_log():
            if asyncio.run_coroutine_threadsafe(self.coro_exec_request_pre(channel, command), loop=self.loop).result():
                return True
        return False


@contextlib.contextmanager
def suppress_and_log(exc_type: typing.Type[BaseException] = Exception):
    try:
        yield
    except exc_type as exc:
        log.info('', exc_info=exc)

def loop():
    return asyncio.get_running_loop()


def set_nodelay(sock: socket.socket) -> socket.socket:
    """https://docs.python.org/3/library/asyncio-eventloop.html#:~:text=The%20socket%20option%20TCP_NODELAY%20is%20set%20by%20default
    FIXME: is this public API ? asyncio documentation hints on TCP_NODELAY being set by default"""
    from asyncio.base_events import _set_nodelay # type: ignore
    _set_nodelay(sock) # FIXME: is this public API ?
    return sock


def sock_for_port_serv(port: int):
    for family, typ, proto, canonname, sockaddr in socket.getaddrinfo(None, port, family=socket.AF_INET6, type=socket.SOCK_STREAM, proto=0, flags=socket.AI_PASSIVE | socket.AI_V4MAPPED | socket.AI_ADDRCONFIG):
        with contextlib.suppress(Exception), \
                contextlib.ExitStack() as es:
            es.enter_context(contextlib.closing(s := socket.socket(family, typ | util.SOCK_NONBLOCK | util.SOCK_CLOEXEC, proto)))
            s.bind(sockaddr)
            s.listen(100)
            es.pop_all()
            return s
    raise RuntimeError(f'Listening on port {port}')


def start_server(sock: socket.socket):
    server_key: paramiko.Ed25519Key = util.pkey_from_str(server_private_key)
    serv = AsyncServ(sock, server_key)
    serv.run_until_complete()

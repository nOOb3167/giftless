import abc
from asyncio import AbstractEventLoop, create_subprocess_exec, Future, gather, get_running_loop, new_event_loop, run_coroutine_threadsafe, StreamReader, StreamWriter
import asyncio
from asyncio.subprocess import PIPE
from asyncio.tasks import FIRST_COMPLETED, sleep
from collections.abc import Coroutine
import contextlib
import concurrent.futures
import dataclasses
from functools import partial
import io
import logging
import socket
from socket import AF_INET6, AF_UNSPEC, AI_ADDRCONFIG, AI_PASSIVE, AI_V4MAPPED, SOCK_STREAM, getaddrinfo
from typing import Callable, Optional
from paramiko.pipe import WindowsPipe
import pytest
import threading
import time
from binascii import hexlify
import paramiko
import paramiko.hostkeys
import paramiko.pkey

# grrrr only defined in module on linux
try:
    from socket import SOCK_CLOEXEC, SOCK_NONBLOCK
except Exception:
    SOCK_CLOEXEC = 0
    SOCK_NONBLOCK = 0

# FIXME:
X_BIG_ENUF = 1000 * 1000

server_private_key = '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACDI9vLirefGYftjW2TwMvHs03vE1Ja6z82m/tNfmbk8sQAA
AKAsaDjeLGg43gAAAAtzc2gtZWQyNTUxOQAAACDI9vLirefGYftjW2TwMvHs03vE
1Ja6z82m/tNfmbk8sQAAAEByvVNWu+C19TiL6NvLle+rAzRPeLNmlJ4iRKVu28UQ
ccj28uKt58Zh+2NbZPAy8ezTe8TUlrrPzab+01+ZuTyxAAAADmVkMjU1MTkta2V5
LTAwAQIDBAUGBwgJCgsMDQ4P
-----END OPENSSH PRIVATE KEY-----
'''
server_public_key = '[localhost]:5001 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMj28uKt58Zh+2NbZPAy8ezTe8TUlrrPzab+01+ZuTyx'
server_auth_keys = '[localhost]:5001 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEnlZ8NXIUgkvm5RrYukkyIpSLIrkSbOv+KxUD0rh6r8'

client_private_key = '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACBJ5WfDVyFIJL5uUa2LpJMiKUiyK5Emzr/isVA9K4eq/AAA
AKALQ1EOC0NRDgAAAAtzc2gtZWQyNTUxOQAAACBJ5WfDVyFIJL5uUa2LpJMiKUiy
K5Emzr/isVA9K4eq/AAAAEBOj/PCiT5gzkhFcSqCr5F2d20AkU1G8D8vyaQUb00h
DEnlZ8NXIUgkvm5RrYukkyIpSLIrkSbOv+KxUD0rh6r8AAAADmVkMjU1MTkta2V5
LTAxAQIDBAUGBwgJCgsMDQ4P
-----END OPENSSH PRIVATE KEY-----
'''


def hostkeys_add_from_line(hostkeys: paramiko.HostKeys, line: str):
    prevlen = len(hostkeys)
    hke = paramiko.hostkeys.HostKeyEntry.from_line(line)
    hostkeys.add(hke.hostnames[0], hke.key.get_name(), hke.key)
    assert len(hke.hostnames) == 1 and len(hostkeys) == prevlen + 1


def hostkeys_add_from_lines(hostkeys: paramiko.HostKeys, lines: str):
    with io.StringIO(lines) as f:
        for line in f.readlines():
            hostkeys_add_from_line(hostkeys, line)


def pkey_from_str(s: str):
    with io.StringIO(s) as f:
        return paramiko.Ed25519Key(file_obj=f)


@dataclasses.dataclass
class Addr:
    host: str
    port: int


class ThreadedClnt(threading.Thread, metaclass=abc.ABCMeta):
    JOIN_TIMEOUT: float = 3

    con_begin: threading.Event
    con_exit: threading.Event

    def __init__(self):
        super().__init__(name=self.__class__.__qualname__, daemon=False)
        self.con_begin = threading.Event()
        self.con_exit = threading.Event()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.con_exit.set()
        self.join(timeout=self.JOIN_TIMEOUT)
        if self.is_alive():
            raise TimeoutError('Thread join failed (by timeout)') from exc_value
        return False

    @abc.abstractmethod
    def run(self):
        pass


class ThreadedClnt1(ThreadedClnt):
    CLNT_TIMEOUT: float = 120
    addr: Addr

    def __init__(self, addr: Addr):
        super().__init__()
        self.addr = addr

    def run(self):
        client = paramiko.SSHClient()

        hostkeys_add_from_line(client.get_host_keys(), server_public_key)

        key: paramiko.pkey.PKey = pkey_from_str(client_private_key)

        logging.info(f"Client key: {hexlify(key.get_fingerprint())}")

        self.con_begin.wait()

        client.connect(
            hostname=self.addr.host,
            username='robey',
            port=self.addr.port,
            pkey=key,
            timeout=self.CLNT_TIMEOUT,
            banner_timeout=self.CLNT_TIMEOUT,
            auth_timeout=self.CLNT_TIMEOUT
            )

        csif, csof, csef = client.exec_command('blah blah')
        if csif.channel is not csof.channel or csif.channel is not csef.channel:
            raise RuntimeError()
        chan = csif.channel
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            def wi():
                chan.sendall(b'hello world 1')
                time.sleep(1)
                chan.sendall(b'hello world 2')
                chan.shutdown_write()
            def ro():
                bio = io.BytesIO()
                while True:
                    if len(m := chan.recv(X_BIG_ENUF)) == 0:
                        return bio.getvalue()
                    bio.write(m)
            def re():
                return chan.recv_stderr(X_BIG_ENUF)
            subs = [executor.submit(x) for x in [wi, ro, re]]
            for fut in concurrent.futures.as_completed(subs):
                logging.info(f'clnt result {fut.result()}')


@contextlib.contextmanager
def channel_ctx(t: paramiko.Transport, accept_timeout: Optional[float]):
    with t.accept(accept_timeout) or contextlib.nullcontext() as chan:
        if chan is None:
            raise RuntimeError('Channel Accept Timeout')
        yield chan


class AsyncServ:
    CHANNEL_ACCEPT_TIMEOUT = 120
    loop: AbstractEventLoop
    s: socket.socket
    server_key: paramiko.PKey

    def __init__(self, s: socket.socket, server_key: paramiko.PKey):
        self.loop = new_event_loop()
        self.s = s
        self.server_key = server_key
    def __enter__(self):
        return self
    def run_until_complete(self):
        self.loop.run_until_complete(self.start_())
    async def auth_publickey(self, username: str, key: paramiko.PKey):
        logging.info(f'auth_publickey')
    async def exec_request_pre(self, con_have_exec_future: Future, channel: paramiko.Channel, command: str):
        con_have_exec_future.set_result(None)
        logging.info(f'exec_request_pre')
    async def start_(self):
        cons: set = set()
        while True:
            accept_task = get_running_loop().create_task(get_running_loop().sock_accept(self.s))
            wait_list = cons | {accept_task}
            done, pending = await asyncio.wait(wait_list, return_when=FIRST_COMPLETED)
            if accept_task in done:
                nsock, addr = accept_task.result()
                set_nodelay(nsock)
                logging.info(f'got {str(nsock)[:50]} | {addr}')
                cons |= {get_running_loop().create_task(self.start_con(nsock))}
    async def start_con(self, nsock: socket.socket):
        with paramiko.Transport(nsock) as t:
            protocol_negotiation_future = get_running_loop().create_future()
            con_have_exec_future = get_running_loop().create_future()
            server = ServerX(
                loop=get_running_loop(),
                coro_auth_publickey=self.auth_publickey,
                coro_exec_request_pre=partial(self.exec_request_pre, con_have_exec_future))
            t.add_server_key(key=self.server_key)
            t.start_server(event=FutureEvent(get_running_loop(), protocol_negotiation_future), server=server)
            logging.info(f'after_start')
            await protocol_negotiation_future
            logging.info(f'after_negotiation')
            await con_have_exec_future
            logging.info(f'after_have_exec')

            await sleep(0)

            with channel_ctx(t, self.CHANNEL_ACCEPT_TIMEOUT) as chan:
                crw = ChannelReadWaiter(chan)

                def wr_thr_fn():
                    for x in range(3):
                        chan.sendall(b'fromserv')
                        time.sleep(1)
                    chan.shutdown_write()

                wr_thr = threading.Thread(target=wr_thr_fn)
                wr_thr.start()

                while True:
                    await crw.wait_read_a()
                    z = chan.recv(X_BIG_ENUF)
                    logging.info(f'serv recv {z}')
                    if len(z) == 0:
                        break
                await sleep(3)
                wr_thr.join()

            return


class ChannelReadWaiter:
    chan: paramiko.channel

    def __init__(self, chan: paramiko.channel):
        self.chan = chan
        chan.fileno() # causes _pipe instantiation
        with chan.lock:
            assert isinstance(chan._pipe, WindowsPipe) # FIXME:
            self._rsock = chan._pipe._rsock
            self._wsock = chan._pipe._wsock

    async def wait_read_a(self):
        await get_running_loop().sock_recv(self._rsock, 1)
        await get_running_loop().sock_sendall(self._wsock, b"*")

class FutureEvent:
    loop: AbstractEventLoop
    future: Future

    def __init__(self, loop: AbstractEventLoop, future: Future):
        self.loop = loop
        self.future = future
    
    def set(self):
        self.loop.call_soon_threadsafe(self.future.set_result, None)


class ServerX(paramiko.ServerInterface, metaclass=abc.ABCMeta):
    con_have_chan_request: bool
    loop: AbstractEventLoop
    coro_auth_publickey: Callable[[str, paramiko.PKey], Coroutine[None]]
    coro_exec_request_pre: Callable[[paramiko.Channel, str], Coroutine[None]]

    def __init__(self, loop: AbstractEventLoop, coro_auth_publickey: Callable[[str, paramiko.PKey], Coroutine[None]], coro_exec_request_pre: Callable[[paramiko.Channel, str], Coroutine[None]]):
        self.con_have_chan_request = False
        self.loop = loop
        self.coro_auth_publickey = coro_auth_publickey
        self.coro_exec_request_pre = coro_exec_request_pre

    def check_channel_request(self, kind: str, chanid: int):
        try:
            return paramiko.OPEN_SUCCEEDED if not self.con_have_chan_request and kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        finally:
            self.con_have_chan_request = True

    def get_allowed_auths(self, username: str):
        return "publickey"

    def check_auth_publickey(self, username: str, key: paramiko.PKey):
        try:
            run_coroutine_threadsafe(self.coro_auth_publickey(username, key), loop=self.loop).result()
            return paramiko.AUTH_SUCCESSFUL
        except Exception:
            return paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel: paramiko.Channel, command: str):
        try:
            run_coroutine_threadsafe(self.coro_exec_request_pre(channel, command), loop=self.loop).result()
            return True
        except Exception:
            return False


def set_nodelay(s: socket.socket):
    """https://docs.python.org/3/library/asyncio-eventloop.html#:~:text=The%20socket%20option%20TCP_NODELAY%20is%20set%20by%20default
    FIXME: is this public API ? asyncio documentation hints on TCP_NODELAY being set by default"""
    from asyncio.base_events import _set_nodelay
    _set_nodelay(s) # FIXME: is this public API ?


def sock_for_port_serv(port: int):
    for family, typ, proto, canonname, sockaddr in getaddrinfo(None, port, family=AF_INET6, type=SOCK_STREAM, proto=0, flags=AI_PASSIVE | AI_V4MAPPED | AI_ADDRCONFIG):
        with contextlib.suppress(Exception), \
                contextlib.ExitStack() as es:
            es.enter_context(contextlib.closing(s := socket.socket(family, typ | SOCK_NONBLOCK | SOCK_CLOEXEC, proto)))
            s.bind(sockaddr)
            s.listen(100)
            es.pop_all()
            return s
    raise RuntimeError(f'Listening on port {port}')


@pytest.mark.timeout(5)
def test_ssh_2(caplog):
    caplog.set_level(logging.INFO)
    addr = Addr(host="localhost", port=5001)
    with contextlib.closing(sock_for_port_serv(addr.port)) as sock:
        with ThreadedClnt1(addr) as clnt:
            clnt.con_begin.set()
            server_key: paramiko.Ed25519Key = pkey_from_str(server_private_key)
            serv = AsyncServ(sock, server_key)
            serv.run_until_complete()
    assert 0


def test_cancel():
    async def b():
        q = get_running_loop().create_task(sleep(100), name='bsleep')
        await q
    async def c():
        z0 = b()
        z1 = get_running_loop().create_task(sleep(100))
        await z0
        await z1
    async def c2():
        z0 = b()
        z1 = get_running_loop().create_task(sleep(100))
        asyncio.gather(z0, z1)
    async def a():
        z0 = get_running_loop().create_task(c())
        await sleep(0)
        await sleep(0)
        await sleep(0)
        await sleep(0)
        await sleep(0)
        await sleep(0)
        await sleep(0)
        z0.cancel()
        await z0
    loop = new_event_loop()
    try:
        loop.run_until_complete(a())
    except BaseException as e:
        print('zzz')
        for t in asyncio.all_tasks(loop):
            print(f'ttt {t}')
        raise


@pytest.mark.timeout(5)
def test_cb():
    def sock_for_conn(port: int):
        for family, typ, proto, canonname, sockaddr in getaddrinfo(None, port, family=AF_UNSPEC, type=SOCK_STREAM, proto=0, flags=AI_V4MAPPED | AI_ADDRCONFIG):
            with contextlib.suppress(Exception), \
                 contextlib.ExitStack() as es:
                s = socket.socket(family, typ | SOCK_NONBLOCK | SOCK_CLOEXEC, proto)
                es.enter_context(contextlib.closing(s))
                s.connect(sockaddr)
                es.pop_all()
                return s
        raise RuntimeError(f'Connecting on port {port}')
    def sock_for_port(port: int):
        for family, typ, proto, canonname, sockaddr in getaddrinfo(None, port, family=AF_INET6, type=SOCK_STREAM, proto=0, flags=AI_PASSIVE | AI_V4MAPPED | AI_ADDRCONFIG):
            with contextlib.suppress(Exception), \
                 contextlib.ExitStack() as es:
                s = socket.socket(family, typ | SOCK_NONBLOCK | SOCK_CLOEXEC, proto)
                es.enter_context(contextlib.closing(s))
                s.bind(sockaddr)
                s.listen(100)
                es.pop_all()
                return s
        raise RuntimeError(f'Listening on port {port}')
    async def stuff(s):
        with contextlib.closing(s):
            while True:
                nsock, addr = await get_running_loop().sock_accept(s)
                print(f'got {nsock} | {addr}')
    async def wr(s, sw: StreamWriter, b: bytes):
        print(f'{s}: {b}')
        sw.write(b)
        sw.write_eof()
        await sw.wait_closed()
    async def rd(s, sr: StreamReader):
        while not sr.at_eof():
            q = await sr.read(10240)
            print(f'{s}: {q[:20]}')
    async def q():
        zz = sock_for_port(4444)
        z = stuff(zz)
        ss = sock_for_conn(4444)
        await get_running_loop().sock_sendall(ss, b'helloworld')
        await z

        coro = create_subprocess_exec(R'C:\Program Files\Git\cmd\git.exe', 'log', '--', stdin=PIPE, stdout=PIPE, stderr=PIPE)
        m = await coro
        rds = gather(rd('out', m.stdout), rd('err', m.stderr), wr('in_', m.stdin, b'mypy.ini'))
        print(type(coro))
        print(coro)
        print(m)
        await rds
    loop = new_event_loop()
    loop.run_until_complete(loop.create_task(q()))
    assert 0

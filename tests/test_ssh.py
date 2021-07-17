import abc
from asyncio import AbstractEventLoop, create_subprocess_exec, Future, gather, get_running_loop, new_event_loop, run_coroutine_threadsafe, StreamReader, StreamWriter
from asyncio.subprocess import PIPE
from asyncio.tasks import sleep
from collections.abc import Coroutine
import contextlib
import concurrent.futures
import dataclasses
import errno
from functools import partial
import io
import logging
import socket
from socket import AF_INET6, AF_UNSPEC, AI_ADDRCONFIG, AI_PASSIVE, AI_V4MAPPED, SOCK_STREAM, getaddrinfo
from typing import Callable, Optional
from paramiko.pipe import WindowsPipe
import pytest
import threading
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

        print(f"Client key: {hexlify(key.get_fingerprint())}")

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

        lestdin = b'hello world'
        csif, csof, csef = client.exec_command('blah blah')
        if csif.channel is not csof.channel or csif.channel is not csef.channel:
            raise RuntimeError()
        chan = csif.channel
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            def wi():
                chan.sendall(lestdin)
                chan.shutdown_write()
            def ro():
                return chan.recv(X_BIG_ENUF)
            def re():
                return chan.recv_stderr(X_BIG_ENUF)
            subs = [executor.submit(x) for x in [wi, ro, re]]
            for fut in concurrent.futures.as_completed(subs):
                print(f'clnt result {fut.result()}')


class ServerCb(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def listen_started(self):
        pass

    @abc.abstractmethod
    def auth_publickey(self, username, key):
        pass

    @abc.abstractmethod
    def exec_request_pre(self, channel: paramiko.Channel, command):
        pass

    @abc.abstractmethod
    def wait_exec(self, con_have_exec: threading.Event):
        pass

    @abc.abstractmethod
    def communicate(self, chan: paramiko.Channel):
        pass


class Server(paramiko.ServerInterface, metaclass=abc.ABCMeta):
    server_cb: ServerCb
    con_have_chan_request: bool
    con_have_exec: threading.Event

    def __init__(self, server_cb: ServerCb):
        self.server_cb = server_cb
        self.con_have_chan_request = False
        self.con_have_exec = threading.Event()

    def check_channel_request(self, kind: str, chanid: int):
        first_request = self.con_have_chan_request == False
        self.con_have_chan_request = True
        return paramiko.OPEN_SUCCEEDED if first_request and kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username: str):
        return "publickey"

    def check_auth_publickey(self, username: str, key: paramiko.PKey):
        try:
            self.server_cb.auth_publickey(username, key)
            return paramiko.AUTH_SUCCESSFUL
        except Exception:
            return paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel: paramiko.Channel, command):
        try:
            self.server_cb.exec_request_pre(channel, command)
            return True
        except Exception:
            return False
        finally:
            self.con_have_exec.set()


def stuff(server_cb: ServerCb, server_key: paramiko.PKey, addr: Addr, accept_timeout=5):
    server = Server(server_cb)

    sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", addr.port))

    sock.listen(100)
    sock.settimeout(5)

    server_cb.listen_started()

    client, addr = sock.accept()

    with paramiko.Transport(client) as t:
        t.add_server_key(key=server_key)
        t.start_server(server=server)

        with t.accept(accept_timeout) or contextlib.nullcontext() as chan:
            if chan is None:
                raise RuntimeError('Timeout or failed authentication')

            server_cb.wait_exec(server.con_have_exec)

            server_cb.communicate(chan)


class ServerCb1(ServerCb):
    def __init__(self, clnt):
        self.clnt = clnt

    def listen_started(self):
        print('setting')
        self.clnt.con_begin.set()

    def auth_publickey(self, username, key):
        print('AUPK')

    def exec_request_pre(self, channel: paramiko.Channel, command):
        print('EXRQ')

    def wait_exec(self, con_have_exec: threading.Event):
        print('WEX')

    def communicate(self, chan: paramiko.Channel):
        print('COM')


def test_ssh(caplog):
    caplog.set_level(logging.INFO)
    addr = Addr(host="localhost", port=5001)
    with ThreadedClnt1(addr) as clnt:
        server_key: paramiko.Ed25519Key = pkey_from_str(server_private_key)
        auth_keys = paramiko.HostKeys()
        hostkeys_add_from_lines(auth_keys, server_auth_keys)
        assert "Not enough fields found" not in caplog.text
        server_cb = ServerCb1(clnt)
        stuff(server_cb=server_cb, server_key=server_key, addr=addr)
    assert 0


@contextlib.contextmanager
def channel_ctx(t: paramiko.Transport, accept_timeout: Optional[float]):
    with t.accept(accept_timeout) or contextlib.nullcontext() as chan:
        if chan is None:
            raise RuntimeError('Channel Accept Timeout')
        yield chan


class PipeV2(object):
    def __init__(self):
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as serv:
            serv.bind(("127.0.0.1", 0))
            serv.listen(1)
            with contextlib.ExitStack() as es:
                es.enter_context(contextlib.closing(rsock := socket.socket(socket.AF_INET, socket.SOCK_STREAM)))
                rsock.connect(("127.0.0.1", serv.getsockname()[1]))
                es.enter_context(contextlib.closing(wsock_addr := serv.accept()))
                rsock.setblocking(False)
                es.pop_all()
                self._wsock = wsock_addr[0]
                self._rsock = rsock
        self._set = False
        self._forever = False
        self._closed = False

    def close(self):
        self._rsock.close()
        self._wsock.close()
        self._closed = True

    def fileno(self):
        return self._rsock.fileno()

    def clear(self):
        if not self._set or self._forever:
            return
        self._readall()
        self._set = False

    def set(self):
        if self._set or self._closed:
            return
        self._set = True
        self._wsock.send(b"*")

    def set_forever(self):
        self._forever = True
        self.set()

    def _readall(self):
        while True:
            try:
                if len(self._rsock.recv(1024)) == 0:
                    break
            except socket.error as e:
                if e.args[0] == errno.EAGAIN or e.args[0] == errno.EWOULDBLOCK:
                    break
                else:
                    raise


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
        print(f'auth_publickey')
    async def exec_request_pre(self, con_have_exec_future: Future, channel: paramiko.Channel, command: str):
        con_have_exec_future.set_result(None)
        print(f'exec_request_pre')
    def q2(self, a): pass
    async def start_(self):
        while True:
            nsock, addr = await get_running_loop().sock_accept(self.s)
            set_nodelay(nsock)
            print(f'got {nsock} | {addr}')
            with paramiko.Transport(nsock) as t:
                protocol_negotiation_future = get_running_loop().create_future()
                con_have_exec_future = get_running_loop().create_future()
                server = ServerX(
                    loop=get_running_loop(),
                    coro_auth_publickey=self.auth_publickey,
                    coro_exec_request_pre=partial(self.exec_request_pre, con_have_exec_future))
                t.add_server_key(key=self.server_key)
                t.start_server(event=FutureEvent(protocol_negotiation_future), server=server)
                print(f'after_start')
                await protocol_negotiation_future
                print(f'after_negotiation')
                await con_have_exec_future
                print(f'after_have_exec')

                # con_have_exec_future is 'set' from a coroutine
                # which is queued up by asyncio.run_coroutine_threadsafe (RCT)
                # sequence flow:
                # 1 RCT side: call RCT, passing coroutine
                # 2 RCT side:   queue callback on event loop
                # 3 RCT side: wait for RCT Future
                # 4 ths side: call callback on event loop
                # 5 ths side:   queue coroutine on event loop
                # 6 ths side:   enable coroutine Future done-callback (2nd callback)
                # 7 ths side: Future being done, queue 2nd callback on event loop
                # 8 ths side: call 2nd callback on event loop
                # 9 ths side:   set RCT Future
                # con_have_exec_future is set in step 5
                # RCT Future is set in step 9
                # event loop has to iterate between step 5 and 9
                # iterate it by awaiting a sleep(0)
                await sleep(0)

                with channel_ctx(t, self.CHANNEL_ACCEPT_TIMEOUT) as chan:
                    f = chan.fileno()
                    # get_running_loop().add_reader(f, lambda x: x) # FIXME: add_reader not implemented on windows proactor event loop (asyncio limitation)
                    with chan.lock:
                        assert isinstance(chan._pipe, WindowsPipe) # FIXME:
                        pipe = chan._pipe
                    chan.sendall(b'fromserv')
                    chan.shutdown_write()

                    await get_running_loop().sock_recv(pipe._rsock, 1)
                    await get_running_loop().sock_sendall(pipe._wsock, b"*")
                    z = chan.recv(X_BIG_ENUF)
                    print(f'serv recv {z}')
                    await sleep(3)

                return


class FutureEvent:
    future: Future

    def __init__(self, future: Future):
        self.future = future
    
    def set(self):
        # loop.call_soon_threadsafe?
        self.future.set_result(None)


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
            q = self.coro_auth_publickey(username, key)
            w = type(q)
        except:
            pass
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

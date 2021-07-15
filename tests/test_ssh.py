import abc
from asyncio import create_subprocess_exec, gather, new_event_loop, StreamReader, StreamWriter
from asyncio.events import get_event_loop
from asyncio.subprocess import PIPE
import contextlib
import dataclasses
import io
import logging
import socket
from socket import AF_UNSPEC, AI_ADDRCONFIG, AI_PASSIVE, AI_V4MAPPED, SOCK_STREAM, getaddrinfo
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
            timeout=5,
            banner_timeout=5,
            auth_timeout=5
            )

        client.exec_command('blah blah')


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

    def communicate(self, chan: paramiko.Channel):
        pass


class Server(paramiko.ServerInterface, metaclass=abc.ABCMeta):
    server_cb: ServerCb
    con_have_exec: threading.Event

    def __init__(self, server_cb: ServerCb):
        self.server_cb = server_cb
        self.con_have_exec = threading.Event()

    def check_channel_request(self, kind: str, chanid: int):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

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
        for family, typ, proto, canonname, sockaddr in getaddrinfo(None, port, family=AF_UNSPEC, type=SOCK_STREAM, proto=0, flags=AI_PASSIVE | AI_V4MAPPED | AI_ADDRCONFIG):
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
                nsock, addr = await get_event_loop().sock_accept(s)
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
        await get_event_loop().sock_sendall(ss, b'helloworld')
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

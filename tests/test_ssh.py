import abc
import contextlib
import dataclasses
import io
import logging
import socket
import threading
from binascii import hexlify

import paramiko
import paramiko.hostkeys
import paramiko.pkey

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


def test_cb():
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.create_subprocess_exec(program=R'C:\Program Files\Git\cmd\git.exe', '--version')
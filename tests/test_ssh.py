import abc
import contextlib
import dataclasses
import importlib.resources
import logging
import socket
import threading
from binascii import hexlify

import paramiko
import paramiko.pkey


with importlib.resources.path("tests", "ed25519_00.key") as keypath:
    host_key = paramiko.Ed25519Key(filename=str(keypath))


@dataclasses.dataclass
class Addr:
    host: str
    port: int


class ThreadedClnt(metaclass=abc.ABCMeta):
    thr: threading.Thread
    con_begin: threading.Event
    con_exit: threading.Event

    def __init__(self):
        self.thr = threading.Thread(target=self._run, args=(self,), daemon=False)
        self.con_begin = threading.Event()
        self.con_exit = threading.Event()

    def __enter__(self):
        self.thr.start()
        return self

    def __exit__(self, *args):
        self.con_exit.set()
        self.thr.join()
        return False

    @staticmethod
    def _run(self: 'ThreadedClnt'):
        self.run()

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
        hostkeys: paramiko.HostKeys = client.get_host_keys()

        with importlib.resources.path("tests", "ed25519_00.hk") as keypath:
            hostkeys.load(filename=str(keypath))
            assert len(hostkeys) == 1

        with importlib.resources.path("tests", "ed25519_01.key") as keypath:
            key: paramiko.pkey.PKey = paramiko.Ed25519Key(filename=str(keypath))

        print(f"Read key2: {hexlify(key.get_fingerprint())}")

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

        return


class Server(paramiko.ServerInterface):
    known_hosts: paramiko.HostKeys
    addr: Addr

    def __init__(self, known_hosts: paramiko.HostKeys, addr: Addr):
        self.known_hosts = known_hosts
        self.addr = addr
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_publickey(self, username, key):
        def addr2kh(addr: Addr):
            return f'[{addr.host}]:{addr.port}' if addr.port else f'{addr.host}'

        print(f"Auth attempt with key: {hexlify(key.get_fingerprint())}")
        print(f"  {username=} at {addr2kh(self.addr)}")
        if (username == "robey") and self.known_hosts.check(addr2kh(self.addr), key):
            print(f'AUTH_OK')
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "publickey"

    def check_channel_exec_request(self, channel, command):
        print(f'exec {channel} @ {command}')
        return False

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


def stuff(known_hosts: paramiko.HostKeys, clnt: ThreadedClnt1):
    sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", clnt.addr.port))

    sock.listen(100)
    sock.settimeout(5)

    print("Listening for connection")

    clnt.con_begin.set()

    client, addr = sock.accept()

    print("Got connection")

    with paramiko.Transport(client) as t:
        t.add_server_key(host_key)
        server = Server(known_hosts=known_hosts, addr=clnt.addr)
        t.start_server(server=server)

        with t.accept(5) or contextlib.nullcontext() as chan:
            if chan is None:
                print("*** Timeout or failed authentication ***")
                raise RuntimeError()

            print("Authenticated!")

            server.event.wait(5)
            if not server.event.is_set():
                print("*** Client never asked for a shell.")
                raise RuntimeError()

            chan.send("Username: ")
            f = chan.makefile("rU")
            username = f.readline().strip("\r\n")
            chan.send(f"\r\nReceived: {username}\r\n")

def test_ssh(caplog):
    caplog.set_level(logging.INFO)
    addr = Addr(host="localhost", port=5001)
    with ThreadedClnt1(addr) as clnt:
        print(f"Read key: {hexlify(host_key.get_fingerprint())}")
        with importlib.resources.path("tests", "ed25519_au_ke") as keypath:
            known_hosts = paramiko.HostKeys(filename=str(keypath))
        assert "Not enough fields found" not in caplog.text
        stuff(known_hosts=known_hosts, clnt=clnt)
    assert 0

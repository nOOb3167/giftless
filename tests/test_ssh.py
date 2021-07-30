import abc
import asyncio
import concurrent.futures
import contextlib
import io
import logging
import threading
import time
import traceback
from asyncio import get_running_loop, new_event_loop
from asyncio.tasks import sleep
from binascii import hexlify

import paramiko
import paramiko.hostkeys
import paramiko.pkey
import pytest

import giftless.auth.ssh_util as util

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


def exclog(fn):
    def call(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except BaseException:
            logging.info('ExcLog From')
            logging.info(f'{traceback.format_exc()}')
            raise
    return call


def chan_sendall(chan: paramiko.Channel, b: bytes):
    # paramiko source channel.py about raising OSError : 'this doesn't seem useful, but it is the documented behavior'
    with contextlib.suppress(OSError):
        chan.sendall(b)


def chanfile_write(chanfile, b: bytes):
    with contextlib.suppress(OSError):
        chanfile.write(b)


def test_chain(caplog):
    caplog.set_level(logging.INFO)
    async def b(x):
        raise RuntimeError(x)
    async def a():
        t = [get_running_loop().create_task(b(x)) for x in range(3)]
        with util.ExcChain().thrower() as ec:
            for a in t:
                with ec.chainer():
                    await a
    loop = new_event_loop()
    loop.run_until_complete(a())


def test_chain_2(caplog):
    caplog.set_level(logging.INFO)
    async def b(x):
        raise RuntimeError(x)
    async def a():
        t = [get_running_loop().create_task(b(x)) for x in range(3)]
        with util.ExcChain().thrower() as ec:
            for a in t:
                with ec.chainer():
                    await a
    loop = new_event_loop()
    loop.run_until_complete(a())


def test_chain_9(caplog):
    caplog.set_level(logging.INFO)
    def doawait(tasks):
        eah = util.ExcMeta(frame_kind=util.FrameKind.CALLER)
        with eah.format():
            for task in tasks:
                with eah.suppress():
                    task()
        return eah.r
    @contextlib.contextmanager
    def cm(tasks):
        try:
            yield
        finally:
            if (f := doawait(tasks)):
                raise f
    def task0():
        raise RuntimeError('_r')
    def ba():
        raise RuntimeError('ba')
    def b():
        with cm([task0]) as _:
            ba()
    def a():
        b()
    a()


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
    addr: util.Addr

    def __init__(self, addr: util.Addr):
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

        csif, csof, csef = client.exec_command(R'C:\Users\Andrej\source\repos\printhelper\x64\Release\printhelper.exe')

        if csif.channel is not csof.channel or csif.channel is not csef.channel:
            raise RuntimeError()

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            def wi():
                chanfile_write(csif, b'hello world 1')
                csif.flush()
                chanfile_write(csif, b'hello world 2')
                csif.flush()
                time.sleep(0.2)
                chanfile_write(csif, b'hello world 3')
                csif.flush()
                csif.close()

            def ro():
                bio = io.BytesIO()
                while True:
                    data = csof.read(X_BIG_ENUF)
                    bio.write(data)
                    if not len(data):
                        return bio.getvalue()

            def re():
                bio = io.BytesIO()
                while True:
                    data = csef.read(X_BIG_ENUF)
                    bio.write(data)
                    if not len(data):
                        return bio.getvalue()
            nams = {executor.submit(exclog(x)): x.__name__ for x in [wi, ro, re]}
            for fut in concurrent.futures.as_completed(nams):
                logging.info(f'clnt result: {nams[fut]} | {fut.result()}')


@pytest.mark.timeout(7)
def test_ssh(caplog):
    caplog.set_level(logging.INFO)
    addr = util.Addr(host="localhost", port=5001)
    with contextlib.closing(util.sock_for_port_serv(addr.port)) as sock:
        with ThreadedClnt1(addr) as clnt:
            clnt.con_begin.set()
            import giftless.auth.ssh
            giftless.auth.ssh.start_server(sock)


def test_cancel():
    async def b():
        q = get_running_loop().create_task(sleep(100), name='bsleep')
        for z in asyncio.all_tasks():
            import sys
            print('stack', file=sys.stderr)
            z.print_stack()
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

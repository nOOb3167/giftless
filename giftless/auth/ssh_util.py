from __future__ import annotations
import asyncio
from asyncio.events import get_running_loop
import asyncio.futures
import collections.abc
import contextlib
import contextvars
import dataclasses
import io
import logging
import paramiko
import socket
import sys
import traceback
import typing

if sys.platform == 'linux':
    from socket import SOCK_CLOEXEC, SOCK_NONBLOCK
else:
    SOCK_CLOEXEC = 0
    SOCK_NONBLOCK = 0


T = typing.TypeVar('T')
ResuT = typing.TypeVar('ResuT', bound='ResurrectableTask')
DataT = typing.Union[bytes, 'Eof']

ctx_conid_var: contextvars.ContextVar[int] = contextvars.ContextVar('conid', default=-1)


class Eof:
    def __len__(self):
        return 0


class FutureEvent:
    loop: asyncio.AbstractEventLoop
    future: asyncio.Future

    def __init__(self, loop: asyncio.AbstractEventLoop, future: asyncio.Future):
        self.loop = loop
        self.future = future
    
    def set(self):
        self.loop.call_soon_threadsafe(self.future.set_result, None)


@dataclasses.dataclass
class Addr:
    host: str
    port: int


@dataclasses.dataclass
class ExcChainCause:
    e: typing.Optional[Exception]

    @contextlib.contextmanager        
    def thrower(self):
        try:
            yield self
        finally:
            if self.e is not None:
                a = RuntimeError('Exception Chain')
                a.__context__ = self.e
                raise a
    
    @contextlib.contextmanager
    def chainer(self):
        try:
            yield
        except Exception as e:
            self._cut_bottom_tb(e)
            self._set_cause_warn(e, self.e)
            self.e = e

    def _cut_bottom_tb(self, e: Exception):
        if e.__traceback__ is not None:
            e.__traceback__ = e.__traceback__.tb_next

    def _set_cause_warn(self, e: Exception, to: typing.Optional[Exception]):
        if e.__cause__ is not None:
            logging.warning(f'Overwriting __cause__ attribute of exception: {type(e)}: {e}')
        e.__cause__ = to


class ExcChain:
    e: list[Exception]

    def __init__(self):
        self.e = []

    @contextlib.contextmanager        
    def thrower(self):
        try:
            yield self
        finally:
            if len(self.e):
                all = []
                for i, v in enumerate(self.e):
                    # self._cut_bottom_tb(e)
                        sl = traceback.format_exception(type(v), v, v.__traceback__)
                        sl_ = (y for x in sl for y in x.split('\n'))
                        all += [f'\ne[{i}] {x}' for x in sl_]
                a = RuntimeError(''.join(x for x in all))
                raise a
    
    @contextlib.contextmanager
    def chainer(self):
        try:
            yield
        except Exception as e:
            self.e.append(e)

    def _cut_bottom_tb(self, e: Exception):
        if e.__traceback__ is not None:
            e.__traceback__ = e.__traceback__.tb_next


def sock_for_port_serv(port: int):
    for family, typ, proto, canonname, sockaddr in socket.getaddrinfo(None, port, family=socket.AF_INET6, type=socket.SOCK_STREAM, proto=0, flags=socket.AI_PASSIVE | socket.AI_V4MAPPED | socket.AI_ADDRCONFIG):
        with contextlib.suppress(Exception), \
                contextlib.ExitStack() as es:
            es.enter_context(contextlib.closing(s := socket.socket(family, typ | SOCK_NONBLOCK | SOCK_CLOEXEC, proto)))
            s.bind(sockaddr)
            s.listen(100)
            es.pop_all()
            return s
    raise RuntimeError(f'Listening on port {port}')


async def as_completed(fs):
    assert all([asyncio.futures.isfuture(x) for x in fs])
    pending = fs
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for d in done:
            yield d


@contextlib.asynccontextmanager
async def task_awaiter(a: typing.Iterable[asyncio.Task]):
    try:
        yield
    finally:
        with ExcChain().thrower() as ec:
            for i in a:
                with ec.chainer():
                    await i


@contextlib.asynccontextmanager
async def queue_get(b: asyncio.Queue[T]) -> typing.AsyncIterator[T]:
    i = await b.get()
    try:
        yield i
    finally:
        b.task_done()


@contextlib.contextmanager
def ctx_conid(conid: int) -> typing.Iterator[None]:
    token = ctx_conid_var.set(conid)
    try:
        yield
    finally:
        ctx_conid_var.reset(token)


@contextlib.contextmanager
def ctx_channel(t: paramiko.Transport, accept_timeout: typing.Optional[float]) -> typing.Iterator[paramiko.Channel]:
    with t.accept(accept_timeout) or contextlib.nullcontext() as chan:
        if chan is None:
            raise RuntimeError('Channel Accept Timeout')
        yield chan


class ConIdLogAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        return f'''[conid={ctx_conid_var.get()}] {msg}''', kwargs


class ResurrectableTask:
    task: asyncio.Task

    def __init__(self):
        self.task = typing.cast(asyncio.Task, None)

    def done(self) -> bool:
        return self.task is None or self.task.done()

    def ensure_done(self) -> ResurrectableTask:
        if not self.done():
            raise RuntimeError()
        return self

    @contextlib.contextmanager
    def with_resurrect_check(self):
        if not self.done():
            raise RuntimeError()
        try:
            yield
        finally:
            if self.done():
                raise RuntimeError()

    @contextlib.contextmanager
    def with_try_take(self: typing.Optional[T], s: set[ResuT]) -> typing.Iterator[typing.Optional[T]]:
        if self in s:
            try:
                yield self
            finally:
                s.remove(typing.cast(ResuT, self))
        else:
            yield None


@dataclasses.dataclass
class Done(typing.Generic[ResuT]):
    tasks: set[asyncio.Task]
    resus: set[ResuT]


class ResurrectableWaiter(typing.Generic[ResuT]):
    tasks: set[asyncio.Task]
    resus: set[ResuT]

    def __init__(self, *resus: ResuT):
        self.tasks = set[asyncio.Task]()
        self.resus = {x for x in resus}

    def add_task(self, task: asyncio.Task):
        self.tasks.add(task)

    @contextlib.contextmanager
    def needing_resurrect(self) -> typing.Iterator[set[ResuT]]:
        nr = {x for x in self.resus if x.done()}
        try:
            yield nr
        finally:
            if len(nr):
                raise RuntimeError()

    @contextlib.asynccontextmanager
    async def wait(self) -> typing.AsyncIterator[Done[ResuT]]:
        resus_dict = {x.task: x for x in self.resus}
        wait = [x for x in self.tasks] + [x.task for x in self.resus]
        done, pending = await asyncio.wait(wait, return_when=asyncio.FIRST_COMPLETED)
        resus_done = set()
        tasks_done = set()
        for x in done:
            if x in resus_dict:
                resus_done.add(resus_dict[x].ensure_done())
            else:
                tasks_done.add(x)
        yield Done[ResuT](tasks=tasks_done, resus=resus_done)


class Waiter():
    tasks: set[asyncio.Task]

    def __init__(self):
        self.tasks = set[asyncio.Task]()

    async def add_task_new(self, coro: collections.abc.Awaitable[T], **opt_name: str) -> asyncio.Task[T]:
        t = get_running_loop().create_task(coro, **opt_name)
        self.tasks.add(t)
        return t

    @contextlib.asynccontextmanager
    async def wait(self) -> typing.AsyncIterator[set[asyncio.Task]]:
        done, pending = await asyncio.wait(self.tasks, return_when=asyncio.FIRST_COMPLETED)
        yield done
    
    @contextlib.asynccontextmanager
    async def canceller(self):
        try:
            yield
        finally:
            gf = asyncio.gather(*self.tasks, return_exceptions=True)
            gf.cancel()
            async with task_awaiter((tasks := await gf)):
                pass


def pkey_from_str(s: str):
    with io.StringIO(s) as f:
        return paramiko.Ed25519Key(file_obj=f)

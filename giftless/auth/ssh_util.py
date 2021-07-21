from __future__ import annotations
import asyncio
import contextlib
import contextvars
import dataclasses
import logging
import paramiko
import typing

# grrrr module only defines these flags on linux
try:
    from socket import SOCK_CLOEXEC, SOCK_NONBLOCK
except Exception:
    SOCK_CLOEXEC = 0
    SOCK_NONBLOCK = 0


T = typing.TypeVar('T')
ResuT = typing.TypeVar('ResuT', bound='ResurrectableTask')
DataT = typing.Union[bytes, 'Eof']

ctx_conid_var: contextvars.ContextVar[int] = contextvars.ContextVar('conid', default=-1)


class Eof:
    def __len__(self):
        return 0


@dataclasses.dataclass
class Addr:
    host: str
    port: int


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

    def done(self) -> bool:
        return self.task.done()

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


class Waiter(typing.Generic[ResuT]):
    @dataclasses.dataclass
    class Done:
        tasks: set[asyncio.Task]
        resus: set[ResurrectableTask]

    tasks: set[asyncio.Task]
    resus: set[ResuT]

    def __init__(self):
        self.tasks = set[asyncio.Task]()
        self.resus = set[ResuT]()

    @contextlib.contextmanager
    def needing_resurrect(self) -> typing.Iterator[set[ResuT]]:
        nr = {x for x in self.resus if x.done()}
        try:
            yield nr
        finally:
            if len(nr):
                raise RuntimeError()

    @contextlib.asynccontextmanager
    async def wait(self) -> typing.AsyncIterator['Waiter.Done']:
        resus_dict = {x.task: x for x in self.resus}
        assert not any([x for x in resus_dict if x.done()])
        wait = [x for x in self.tasks] + [x.task for x in self.resus]
        done, pending = await asyncio.wait(wait, return_when=asyncio.FIRST_COMPLETED)
        resus_done = set()
        tasks_done = set()
        for x in done:
            if x in resus_dict:
                resus_done.add(resus_dict[x].ensure_done())
            else:
                tasks_done.add(x)
        yield Waiter.Done(tasks=tasks_done, resus=resus_done)

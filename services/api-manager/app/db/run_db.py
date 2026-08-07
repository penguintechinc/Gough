"""``run_db()`` -- the house idiom for running a blocking penguin-dal unit off
the event loop.

Regression: gh-22 (event-loop-unblocking sweep). Quart route handlers are
``async def``, but penguin-dal is a synchronous SQLAlchemy wrapper -- every
``db(...).select()``/``.insert()``/``.update()`` call blocks the calling
thread on network I/O. ``app.grpc_server``'s servicers already worked around
this for gRPC (see that module's docstring): define a local closure
containing the WHOLE database unit of work -- every statement of one logical
transaction, never split across separate ``to_thread`` calls, since a
penguin-dal transaction/connection checkout is not safe to resume from a
different thread hop -- then hand that closure to ``run_db()``. This service
runs single-process, single-loop (``run.py``'s ``app.run_task``) with gRPC
sharing the same loop, so a handler that blocks synchronously stalls every
other request and every gRPC call until it returns; ``run_db()`` is the fix.

``app.db.rls``'s tenant ``ContextVar`` propagates through
``asyncio.to_thread()`` automatically (it copies the current
``contextvars.Context`` onto the worker thread -- see that module's
docstring), so RLS/tenant scoping set by the tenant middleware before a
handler calls ``run_db()`` is still in effect inside the closure.

Usage::

    def _do_update() -> tuple[bool, str]:
        # ALL statements of one transaction go here -- never split a unit
        # of work across two run_db()/to_thread() calls.
        row = db(db.nodes.id == node_id).select().first()
        db(db.nodes.id == node_id).update(state="ready")
        db.commit()
        return True, str(row.id)

    updated, node_id = await run_db(_do_update)
"""

from __future__ import annotations

import asyncio
from typing import Callable, TypeVar

T = TypeVar("T")


async def run_db(fn: Callable[[], T]) -> T:
    """Run a blocking penguin-dal unit of work off the event loop.

    ``fn`` must be a zero-argument closure wrapping the WHOLE DB unit (every
    statement of one logical transaction) -- never split a single transaction
    across multiple ``run_db()``/``to_thread()`` calls, since the thread a
    penguin-dal connection is checked out on cannot be resumed later.
    """
    return await asyncio.to_thread(fn)


__all__ = ["run_db"]

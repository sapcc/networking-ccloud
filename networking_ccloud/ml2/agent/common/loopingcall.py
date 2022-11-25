# Copyright 2022 SAP SE
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import threading

from oslo_service import loopingcall


class LoopingCallThread(threading.Thread):
    """Thread class used in ThreadedLoopingCallBase

    Extends Thread to have a callback called when the Thread is done running.
    """
    def __init__(self, *args, done_cb=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._done_cb = done_cb

    def run(self):
        try:
            super().run()
        finally:
            if self._done_cb:
                self._done_cb()


class ThreadedLoopingCallBase(loopingcall.LoopingCallBase):
    """Make LoopingCallBase run with Thread

    Overwrites _start() and _abort to use threading instead of
    eventlet/greenthread.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._abort = threading.Event()

    def _on_done(self, *args, **kwargs):
        self._thread = None

    def _start(self, idle_for, initial_delay=None, stop_on_exception=True):
        """Start the looping

        :param idle_for: Callable that takes two positional arguments, returns
                         how long to idle for. The first positional argument is
                         the last result from the function being looped and the
                         second positional argument is the time it took to
                         calculate that result.
        :param initial_delay: How long to delay before starting the looping.
                              Value is in seconds.
        :param stop_on_exception: Whether to stop if an exception occurs.
        :returns: eventlet event instance
        """
        if self._thread is not None:
            raise RuntimeError(self._RUN_ONLY_ONE_MESSAGE)
        self.done = threading.Event()
        self._abort.clear()
        target_args = (idle_for, )
        target_kwargs = dict(initial_delay=initial_delay,
                             stop_on_exception=stop_on_exception)
        self._thread = LoopingCallThread(
            target=self._run_loop, args=target_args, kwargs=target_kwargs,
            done_cb=self._on_done, daemon=True)
        self._thread.start()
        return self.done


def monkeypatch_loopingcall():
    """Inserts ThreadedLoopingCallBase into all children of LoopingCallBase

    To make all children of LoopingCallBase run with threading.Thread instead
    of greenthread, we have to insert ThreadedLoopingCallBase into their
    __bases__ before LoopingCallBase.
    """
    for cls in loopingcall.LoopingCallBase.__subclasses__():
        # we don't want to create a loop in the resolution order
        if cls == ThreadedLoopingCallBase:
            continue

        # if our class is already in there, we expect that to be a custom
        # LoopingCall class of our own and don't patch it. This also makes the
        # function idempotent.
        if ThreadedLoopingCallBase in cls.__bases__:
            continue

        i = cls.__bases__.index(loopingcall.LoopingCallBase)
        bases = cls.__bases__[:i] + (ThreadedLoopingCallBase, ) + cls.__bases__[i:]
        cls.__bases__ = bases

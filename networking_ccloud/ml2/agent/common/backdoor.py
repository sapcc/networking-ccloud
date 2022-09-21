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
from collections import Counter
import gc
import sys
import time
import traceback


def _find_objects(cls):
    """Find all objects of the given class"""
    return [o for o in gc.get_objects() if hasattr(o, "__class__") and isinstance(o, cls)]


def _get_nativethreads():
    """Return tracebacks of all native threads as string"""
    lines = []
    for thread_id, stack in sys._current_frames().items():
        lines.append(str(thread_id))
        lines.extend(l.rstrip() for l in traceback.format_stack(stack))
        lines.append('')
    return '\n'.join(lines)


def _print_nativethreads():
    """Print tracebacks of all native threads"""
    print(_get_nativethreads())


def _print_semaphores():
    """Print all Semaphore objects used by oslo_concurrency.lockutils and their waiter count"""
    # local import as we don't want to keep that local variable in global scope
    from oslo_concurrency.lockutils import _semaphores

    print('\n'.join(sorted([f"{name} - {len(s._Semaphore__cond._Condition__waiters)}"
                            for name, s in _semaphores._semaphores.items()])))


def _time_it(fn, *args, **kwargs):
    """Call fn, measuring the time it takes with time.time()"""
    start = time.time()
    fn(*args, **kwargs)
    print(time.time() - start)


def _profile_it(fn, *args, return_stats=False, **kwargs):
    """Call fn with profiling enabled

    Optionally returns the pstats.Stats created while profiling.
    """
    # local imports as these are most likely never used anywhere
    import cProfile
    import pstats

    pr = cProfile.Profile()
    pr.runcall(fn, *args, **kwargs)
    pr.create_stats()
    ps = pstats.Stats(pr)

    if return_stats:
        return ps

    ps.sort_stats('tottime').print_stats(30)


def _count_object_types():
    """Return a collections.Counter containing class to count mapping of objects in gc"""
    return Counter(o.__class__ for o in gc.get_objects() if hasattr(o, '__class__'))


BACKDOOR_LOCALS = {
    'fo': _find_objects,
    'pnt': _print_nativethreads,
    'gnt': _get_nativethreads,
    'print_semaphores': _print_semaphores,
    'time_it': _time_it,
    'profile_it': _profile_it,
    'count_object_types': _count_object_types
}

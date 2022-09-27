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
from functools import partial

from oslo_reports import guru_meditation_report as gmr
from oslo_reports.models import with_default_views as mwdv
from oslo_reports.views.text import generic as text_views


class ThreadPoolStatsView(object):
    FORMAT_STR = (
        "------{header: ^60}------\n"
        "Executed: {stats.executed}\n"
        "Failures: {stats.failures}\n"
        "Cancelled: {stats.cancelled}\n"
        "Runtime: {stats.runtime}\n"
        "Avg Runtime: {stats.average_runtime}\n"
        "Queue Size: {queue_size}\n"
    )

    def __call__(self, model):
        return self.FORMAT_STR.format(
            header=f" ThreadPool for {model.switch_name} ",
            stats=model.stats,
            queue_size=model.queue_size
        )


def thread_pool_stats_generator(agent):
    thread_pool_stats_models = [
        mwdv.ModelWithDefaultViews(dict(switch_name=switch.name, stats=switch._executor.statistics,
                                        queue_size=switch._executor._work_queue.qsize()),
                                   text_view=ThreadPoolStatsView())
        for switch in agent._switches
    ]
    return mwdv.ModelWithDefaultViews(thread_pool_stats_models,
                                      text_view=text_views.MultiView())


def register_thread_pool_stats(agent):
    """Enable exposing the ThreadPool statistics of agent's switches"""
    gmr.TextGuruMeditation.register_section('Switches ThreadPool Stats',
                                            partial(thread_pool_stats_generator, agent))

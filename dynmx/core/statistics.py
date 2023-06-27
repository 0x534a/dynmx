# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from __future__ import annotations
import operator

from dynmx.core.function_log import FunctionLog


class Statistics:
    """
    Represents statistics of function logs
    """

    def __init__(self, flog: FunctionLog):
        """
        Constructor
        :param flog: flog object to create statistics from
        """
        self.flog = flog
        self.num_of_processes = 0
        self.num_of_api_calls = 0
        self.num_of_unique_api_calls = 0
        self.flop_api_calls = {}
        self.top_api_calls = {}
        self.api_call_stats = {}

    def calculate(self) -> None:
        """
        Calculates the statistics
        """
        self._prepare_data()

    def _prepare_data(self, flop_limit: int = 10) -> None:
        """
        Prepares the data for statistics
        :param flop_limit: Limit for top and flop system call count
        """
        self.num_of_processes = len(self.flog.processes)
        for p in self.flog.processes:
            for api_call in p.api_calls:
                if api_call.function_name not in self.api_call_stats.keys():
                    self.api_call_stats[api_call.function_name] = 1
                    self.num_of_unique_api_calls += 1
                else:
                    self.api_call_stats[api_call.function_name] += 1
                self.num_of_api_calls += 1
        sorted_api_calls = sorted(self.api_call_stats.items(),
                                  key=operator.itemgetter(1))
        index = 0
        while index < flop_limit and index < len(sorted_api_calls):
            self.flop_api_calls[sorted_api_calls[index][0]] = sorted_api_calls[index][1]
            self.top_api_calls[sorted_api_calls[::-1][index][0]] = sorted_api_calls[::-1][index][1]
            index += 1

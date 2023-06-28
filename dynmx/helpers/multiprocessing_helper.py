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
from typing import Optional, Tuple
from multiprocessing import Pool, cpu_count, set_start_method, Queue

from dynmx.helpers.logging_helper import LoggingHelper


class MultiprocessingHelper:
    """
    Represents a helper for setting up multiprocessing
    """

    @staticmethod
    def set_up() -> None:
        # Spawn new processes instead of forking them to be platform-independent
        set_start_method("spawn", force=True)

    @staticmethod
    def get_pool(num_of_workers: Optional[int] = None, log_level: Optional[int] = None,
                 queue: Optional[Queue] = None) -> Tuple[int, Pool]:
        if not num_of_workers:
            num_of_workers = cpu_count() - 2
        # We need to initialize the logging in each process since we spawn processes instead of forking them
        proc_pool = Pool(
            processes=num_of_workers,
            maxtasksperchild=1000,
            initializer=LoggingHelper.set_up_process_logging,
            initargs=(log_level, queue)
        )
        return num_of_workers, proc_pool

    @staticmethod
    def get_cpu_count() -> int:
        """
        Returns the CPU count
        :return: CPU count
        """
        return cpu_count()

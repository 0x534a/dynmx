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
from typing import TYPE_CHECKING
from abc import ABC, abstractmethod

if TYPE_CHECKING:
    from dynmx.core.function_log import FunctionLog


class Parser(ABC):
    """
    Abstract base class for an input file parser
    """

    _content = None
    processes = None

    def __init__(self):
        self.processes = list()
        super().__init__()

    @abstractmethod
    def parse(self, file_path: str) -> FunctionLog:
        """
        Abstract parse function. Has to be overwritten in the specialized
        class.
        :param file_path: Path to the file to parse
        """
        pass

    @abstractmethod
    def probe(file_path: str) -> bool:
        """
        Abstract probe function. has to be overwritten in the specialized
        class.
        :param file_path: Path to the file to probe
        """
        pass

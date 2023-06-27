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
from typing import Optional, Dict, Any, TYPE_CHECKING
from datetime import datetime
from enum import Flag, auto

if TYPE_CHECKING:
    from dynmx.core.process import Process


class FunctionLog:
    """
    Representation of a function log
    """

    def __init__(self, flog_type: FunctionLogType, name: Optional[str] = None, file_path: Optional[str] = None,
                 version: Optional[str] = None, sandbox: Optional[str] = None, sandbox_version: Optional[str] = None,
                 analysis_ts: Optional[datetime] = None):
        """
        Constructor
        :param name: Name of function log
        :param file_path: Path to function log file
        """
        self.flog_type = flog_type
        self.name = name
        self.file_path = file_path
        self.version = version
        self.sandbox = sandbox
        self.sandbox_version = sandbox_version
        self.analysis_ts = analysis_ts
        self.processes = []

    def add_process(self, process: Process) -> None:
        process.flog_path = self.file_path
        self.processes.append(process)

    def get_as_dict(self, include_processes: bool = False, include_api_calls: bool = False) -> Dict[str, Any]:
        """
        Returns the function log object as dict
        :param include_processes: Decides whether to include the processes
        :param include_api_calls: Decides whether to include the system calls
        :return: Function log object as dict
        """
        result_dict = {
            "flog_name": self.name,
            "flog_file_path": self.file_path,
        }
        if include_processes:
            result_dict["flog_processes"] = []
            for p in self.processes:
                p_dict = p.get_as_dict(include_api_calls)
                result_dict["flog_processes"].append(p_dict)
        return result_dict

    def convert(self) -> Dict[str, Any]:
        """
        Converts the function log object and inherited objects to the dynmx
        function log format
        :return: Function log object in the dynmx flog format
        """
        convert_result = {
            "flog": {
                "version": "1.0",
                "sandbox": self.sandbox,
                "sandbox_version": self.sandbox_version,
                "analysis_ts": datetime.strftime(self.analysis_ts, "%d.%m.%Y %H:%M:%S.%f"),
                "processes": []
            }
        }
        for p in self.processes:
            converted_p = p.convert()
            convert_result["flog"]["processes"].append(converted_p)
        return convert_result

    def extract_resources(self):
        for p in self.processes:
            p.extract_resources(self.flog_type)

    def __eq__(self, other: FunctionLog) -> bool:
        if not isinstance(other, FunctionLog):
            return NotImplemented
        is_equal = True
        attributes = self.__dict__.keys()
        for attr in attributes:
            if attr == "processes":
                if len(self.processes) != len(other.processes):
                    is_equal = False
                    break
                for ix, proc in enumerate(self.processes):
                    is_equal &= (proc == other.processes[ix])
            is_equal &= (getattr(self, attr) == getattr(other, attr))
        return is_equal


class FunctionLogType(Flag):
    VMRAY = auto()
    CUCKOO = auto()
    CAPE = auto()
    DYNMX = auto()

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
from typing import Optional, List, Dict, Set, Any, TYPE_CHECKING

from dynmx.helpers.regex_helper import RegexHelper
from dynmx.detection.access_activity_model import AccessActivityModel

if TYPE_CHECKING:
    from dynmx.core.api_call import APICall
    from dynmx.core.function_log import FunctionLogType


class Process:
    """
    Representation of a process
    """

    def __init__(self, flog_path: Optional[str] = None, os_id: Optional[int] = None, name: Optional[str] = None,
                 file_path: Optional[str] = None, cmd_line: Optional[str] = None, owner: Optional[str] = None):
        """
        Constructor
        :param os_id: OS given PID of process
        :param name: Name of process
        :param file_path: Path to executable of process
        :param cmd_line: Command line the process was started with
        :param owner: Owner of process
        """
        self.flog_path = flog_path
        self.os_id = os_id
        self.name = name
        self.file_path = file_path
        self.cmd_line = cmd_line
        self.owner = owner
        self.api_calls = list()
        self.api_call_lookup_table = dict()
        self.aam = None

    def get_as_dict(self, include_api_calls: bool = False) -> Dict[str, Any]:
        """
        Returns the process object as dict
        :param include_api_calls: Decides whether to include API calls
        :return: Process object as dict
        """
        result_dict = {
            "proc_os_id": self.os_id,
            "proc_name": self.name,
            "proc_file_path": self.file_path,
            "proc_cmd_line": self.cmd_line,
            "proc_owner": self.owner,
        }
        if include_api_calls:
            result_dict["api_calls"] = []
            for api_call in self.api_calls:
                s_dict = api_call.get_as_dict()
                result_dict["api_calls"].append(s_dict)
        return result_dict

    def convert(self) -> Dict[str, Any]:
        """
        Converts the process object to the dynmx flog format
        :return: Process object in the dynmx flog format
        """
        convert_result = {
            "os_id": self.os_id,
            "name": self.name,
            "file_path": self.file_path,
            "cmd_line": self.cmd_line,
            "owner": self.owner,
            "api_calls": [],
        }
        for api_call in self.api_calls:
            converted_api_call = api_call.convert()
            convert_result["api_calls"].append(converted_api_call)
        return convert_result

    def add_api_call(self, api_call: APICall) -> None:
        """
        Adds an API call to the process
        :param api_call: APICall object to add
        """
        self.api_calls.append(api_call)
        api_call_name = api_call.function_name
        if api_call_name in self.api_call_lookup_table.keys():
            self.api_call_lookup_table[api_call_name].append(api_call.index)
        else:
            self.api_call_lookup_table[api_call_name] = list()
            self.api_call_lookup_table[api_call_name].append(api_call.index)

    def get_api_calls_by_name(self, function_name: str, is_regex_pattern: bool = False) -> List[APICall]:
        """
        Returns a list of API calls identified by the function name
        :param function_name: Function name
        :param is_regex_pattern: Is function_name regular expression?
        :return: List of identified API calls
        """
        api_calls = list()
        api_call_indices = list()
        if not is_regex_pattern:
            if function_name not in self.api_call_lookup_table.keys():
                return []
            api_call_indices = self.api_call_lookup_table[function_name]
        else:
            for fname in self.api_call_lookup_table:
                if RegexHelper.is_regex_matching(fname, function_name):
                    api_call_indices += self.api_call_lookup_table[fname]
        uniq_indices = set(api_call_indices)
        if uniq_indices:
            for ix in uniq_indices:
                api_calls.append(self.api_calls[ix])
        return api_calls

    def get_api_call_function_names(self) -> Set[str]:
        """
        Returns the function names of all API calls that are part of the process
        :return: Set of function names the process's API calls
        """
        return set(self.api_call_lookup_table.keys())

    def has_api_call_function_name(self, function_name: str, is_regex_pattern: bool = False) -> bool:
        """
        Indicates whether the process has API calls with the given function name
        :param function_name: Function name of the API call
        :param is_regex_pattern: Indicates whether function_name is a regex pattern
        :return:
        """
        if is_regex_pattern:
            for api_call in self.get_api_call_function_names():
                if RegexHelper.is_regex_matching(api_call, function_name):
                    return True
            return False
        else:
            return function_name in self.get_api_call_function_names()

    def extract_resources(self, flog_type: FunctionLogType) -> None:
        self.aam = AccessActivityModel(flog_type)
        self.aam.build(self)

    def __eq__(self, other: Process) -> bool:
        if not isinstance(other, Process):
            return NotImplemented
        is_equal = True
        attributes = self.__dict__.keys()
        for attr in attributes:
            if attr == "api_calls":
                if len(self.api_calls) != len(other.api_calls):
                    is_equal = False
                    break
                for ix, api_call in enumerate(self.api_calls):
                    is_equal &= (api_call == other.api_calls[ix])
            is_equal &= (getattr(self, attr) == getattr(other, attr))
        return is_equal

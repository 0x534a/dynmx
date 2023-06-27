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
from typing import List, Dict, Any
import json
import ntpath
import gzip
import os
from datetime import datetime

from dynmx.flog_parsers.parser import Parser
from dynmx.core.process import Process
from dynmx.core.api_call import APICall, Argument
from dynmx.core.function_log import FunctionLog, FunctionLogType
from dynmx.core.pointer import Pointer
from dynmx.helpers.flog_parser_helper import FlogParserHelper


class DynmxFlogParser(Parser):
    """
    Parser for text-based generic dynmx function logs
    """

    def __init__(self):
        """
        Constructor
        """
        Parser.__init__(self)

    def parse(self, file_path: str) -> FunctionLog:
        """
        Parses the dynmx generic function log
        :param file_path: Path to the text-based dynmx generic function log
        :return: FunctionLog object containing the parsed dynmx function log
        """
        function_log = FunctionLog(FunctionLogType.DYNMX)
        if FlogParserHelper.is_gzip_compressed(file_path):
            with gzip.open(file_path, "rb") as f:
                content = f.read().decode(encoding='utf-8', errors='ignore').split("\n")
        else:
            with open(file_path, "r", encoding='utf-8', errors='ignore') as flog:
                content = flog.readlines()
        for index, line in enumerate(content):
            if not line.startswith("#"):
                break
        self._content = json.loads("".join(content[index:]))
        function_log.name = ntpath.basename(file_path)
        function_log.file_path = os.path.abspath(file_path)
        # Parse process information and corresponding API calls
        if "flog" not in self._content.keys():
            raise Exception("Could not parse dynmx function log. Key 'flog' not present.")
        if "processes" not in self._content["flog"].keys():
            raise Exception("Could not parse dynmx function log. Key 'processes' not present.")
        # Parse flog information
        self._parse_flog_info(function_log, self._content["flog"])
        # Parse processes
        for process in self._content["flog"]["processes"]:
            p = self._parse_process_info(process)
            p.flog_path = function_log.file_path
            function_log.add_process(p)
        return function_log

    @staticmethod
    def probe(file_path: str) -> bool:
        """
        Probes whether the file is a dynmx generic function log
        :param file_path: Path to the file to probe
        :return: Indicates whether the file is a dynmx function log
        """
        if FlogParserHelper.is_gzip_compressed(file_path):
            with gzip.open(file_path, "rb") as f:
                first_line = f.readline().decode(encoding="utf-8", errors="ignore")
        else:
            with open(file_path, "r") as f:
                first_line = f.readline()
        result = (first_line.strip() == "# dynmx generic function log")
        return result

    def _parse_flog_info(self, flog_obj: FunctionLog, flog_dict: Dict[str, Any]) -> None:
        # Define mapping of fields
        attributes = [
            "version",
            "sandbox",
            "sandbox_version",
            "analysis_ts",
        ]
        self._safe_set_obj_property(flog_obj, attributes, flog_dict)
        if flog_obj.analysis_ts:
            ts = datetime.strptime(flog_obj.analysis_ts, "%d.%m.%Y %H:%M:%S.%f")
            flog_obj.analysis_ts = ts

    def _parse_process_info(self, process: Dict[str, Any]) -> Process:
        """
        Parses the process information from the dynmx function log
        :param process: Process section of dynmx function log
        :return: Process object containing the parsed process information
        """
        # Define mapping of fields
        attributes = [
            "os_id",
            "name",
            "file_path",
            "cmd_line",
            "owner",
        ]
        p = Process()
        for k in attributes:
            setattr(p, k, process[k])
        # Parse API calls of the process
        for api_call_index, api_call in enumerate(process["api_calls"]):
            s = self._parse_api_call(api_call)
            s.index = api_call_index
            p.add_api_call(s)
        return p

    def _parse_api_call(self, api_call_dict: Dict[str, Any]) -> APICall:
        """
        Parses the API call information from the dynmx function log
        :param api_call_dict: API call section of dynmx function log
        :return: APICall object containing the parsed information
        """
        # Define attributes to parse
        attributes = [
            "flog_index",
            "function_name",
            "time",
            "arguments",
            "return_value",
        ]
        # Parse attributes
        api_call = APICall()
        for k in attributes:
            if k in api_call_dict.keys():
                setattr(api_call, k, api_call_dict[k])
        args = list()
        for arg in api_call.arguments:
            a = self._parse_argument(arg)
            args.append(a)
            if not api_call.has_in_out_args and (a.is_in or a.is_out):
                api_call.has_in_out_args = True
        api_call.arguments = args
        # Replace pointer structures with objects
        if isinstance(api_call.return_value, dict):
            p = self._parse_pointer(api_call.return_value)
            api_call.return_value = p
        return api_call

    def _parse_pointer(self, pointer: Dict[str, Any]) -> Pointer:
        """
        Parses a pointer structure
        :param pointer: Pointer structure as dict
        :return: Pointer object with the parsed information
        """
        # Define attributes to parse
        attributes = [
            "address",
            "arguments",
        ]
        # Parse attributes
        p = Pointer()
        for k in attributes:
            setattr(p, k, pointer[k] if k in pointer.keys() else None)
        if isinstance(pointer["arguments"], list):
            args = list()
            for arg in pointer["arguments"]:
                if isinstance(arg, dict):
                    args.append(self._parse_argument(arg))
                else:
                    args.append(arg)
            p.arguments = args
        return p

    def _parse_argument(self, arg: Dict[str, Any]) -> Argument:
        """
        Parses an argument structure
        :param arg: Argument structure as dict
        :return: Argument object with the parsed information
        """
        # Define attributes to parse
        attributes = [
            "name",
            "value",
            "is_in",
            "is_out",
        ]
        # Parse attributes
        a = Argument()
        for k in attributes:
            setattr(a, k, arg[k] if k in arg.keys() else None)
        # Replace pointer structures with objects
        if isinstance(a.value, dict):
            p_nested = self._parse_pointer(a.value)
            a.value = p_nested
        return a

    @staticmethod
    def _safe_set_obj_property(obj: Any, attribute_names: List[str], attr_values_dict: Dict[str, Any]) -> None:
        """
        Sets attributes of the given object based on the given value dictionary
        :param obj: Object of that the attributes should be set
        :param attribute_names: List of attribute names to set
        :param attr_values_dict: Dictionary containing the attribute values
        """
        for k in attribute_names:
            setattr(obj, k, attr_values_dict[k] if k in attr_values_dict.keys() else None)

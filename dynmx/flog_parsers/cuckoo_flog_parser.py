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
from typing import Dict, Any, List
import json
import ntpath
import os

from dynmx.flog_parsers.parser import Parser
from dynmx.core.process import Process
from dynmx.core.api_call import APICall, Argument
from dynmx.core.function_log import FunctionLog, FunctionLogType
from dynmx.helpers.flog_parser_helper import FlogParserHelper


class CuckooFlogParser(Parser):
    """
    Parser for text-based Cuckoo sandbox function logs (part of report.json
    file)
    """

    def __init__(self):
        """
        Constructor
        """
        Parser.__init__(self)

    def parse(self, file_path: str) -> FunctionLog:
        """
        Parses the Cuckoo function log (in report.json file)
        :param file_path: Path to the text-based Cuckoo report.json file
        :return: FunctionLog object containing the parsed Cuckoo function log
        """
        function_log = FunctionLog(FunctionLogType.CUCKOO)
        with open(file_path, "r") as flog:
            self._content = json.load(flog)
        function_log.name = ntpath.basename(file_path)
        function_log.file_path = os.path.abspath(file_path)
        function_log.sandbox = "Cuckoo"
        # Parse process information and corresponding API calls
        if "behavior" not in self._content.keys():
            raise Exception(
                "Could not parse Cuckoo function log. Key 'behavior' not present.")
        if "processes" not in self._content["behavior"].keys():
            raise Exception(
                "Could not parse Cuckoo function log. Key 'processes' not present.")
        for process in self._content["behavior"]["processes"]:
            p = self._parse_process_info(process)
            function_log.add_process(p)
        return function_log

    @staticmethod
    def probe(file_path: str) -> bool:
        """
        Probes whether the file is a Cuckoo report.json file
        :param file_path: Path to the file to probe
        :return: Indicates whether the file is a Cuckoo report.json file
        """
        result = False
        if not FlogParserHelper.is_gzip_compressed(file_path):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                first_lines = [next(f) for x in range(2)]
            result = first_lines[0].strip() == "{" and \
                     first_lines[1].strip() == "\"info\": {"
        return result

    def _parse_process_info(self, process: Dict[str, Any]) -> Process:
        """
        Parses the process information from the Cuckoo function log
        :param process: Process section of Cuckoo report.json
        :return: Process object containing the parsed process information
        """
        # Define mapping of fields
        mapping = {
            "os_id": "pid",
            "name": "process_name",
            "file_path": "process_path",
            "cmd_line": "command_line",
        }
        p = Process()
        for k, v in mapping.items():
            setattr(p, k, process[v])
        self._process_start_time = process["first_seen"]
        # Parse API calls of the process
        api_call_index = 0
        for api_call in process["calls"]:
            s = self._parse_api_call(api_call)
            s.index = api_call_index
            p.add_api_call(s)
            api_call_index += 1
        return p

    def _parse_api_call(self, api_call_dict):
        """
        Parses the API call information from the Cuckoo function log
        :param api_call_dict: API call section of Cuckoo report.json
        :return: APICall object containing the parsed information
        """
        api_call = APICall()
        api_call.function_name = api_call_dict["api"]
        api_call.return_value = FlogParserHelper.parse_value(api_call_dict["return"])
        # Convert absolute time to relative time since first api call of
        # process
        api_call.time = self._convert_time_to_relative(api_call_dict["time"])
        # Harmonize arguments
        args = self._parse_args(api_call_dict["arguments"])
        api_call.arguments = args
        return api_call

    def _convert_time_to_relative(self, time: float) -> float:
        """
        Converts the absolute time of a API call to the relative time since
        the start of the process
        :param time: Time to convert as UNIX timestamp
        :return: Relative time
        """
        return (time - self._process_start_time)

    @staticmethod
    def _parse_args(args: List[Dict[str, Any]]) -> List[Argument]:
        """
        Parses arguments of an API call
        :param args: Arguments to parse
        :return: Parsed argument objects
        """
        parsed_args = []
        for arg in args:
            arg_obj = Argument()
            arg_obj.name = arg["name"]
            arg_obj.value = FlogParserHelper.parse_value(arg["value"])
            parsed_args.append(arg_obj)
        return parsed_args

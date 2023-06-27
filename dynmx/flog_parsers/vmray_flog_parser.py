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
from typing import Any, Optional, List
import ntpath
import os

from dynmx.flog_parsers.parser import Parser
from dynmx.helpers.flog_parser_helper import FlogParserHelper
from dynmx.helpers.regex_helper import *
from dynmx.core.pointer import Pointer
from dynmx.core.process import Process
from dynmx.core.api_call import APICall, Argument
from dynmx.core.function_log import FunctionLog, FunctionLogType
from dynmx.helpers.logging_helper import LoggingHelper


class VmRayFlogParser(Parser):
    """
    Parser for text-based VM-Ray function logs
    """

    def __init__(self):
        """
        Constructor
        """
        Parser.__init__(self)
        self._logger = LoggingHelper.get_logger(__name__)

    def parse(self, file_path: str) -> FunctionLog:
        """
        Parses the VM-Ray function log
        :param file_path: Path to the text-based VM-Ray function log
        :return: FunctionLog object containing the parsed VM-Ray function log
        """
        self._logger = LoggingHelper.get_logger(__name__, flog_path=file_path)
        function_log = FunctionLog(FunctionLogType.VMRAY)
        with open(file_path, "r", encoding='utf-8-sig', errors='ignore') as flog:
            self._content = flog.readlines()
        function_log.name = ntpath.basename(file_path)
        function_log.file_path = os.path.abspath(file_path)
        function_log.sandbox = "VMRay Analyzer"
        index = 0
        process_count = 0
        api_call_index = 0
        while index < len(self._content):
            clean_line = self._content[index].strip()
            # Parse header information
            if clean_line.startswith('#'):
                start_index = index
                end_index = self._get_end_of_section(start_index)
                self._parse_header_info(start_index, end_index, function_log)
                index = (end_index + 1)
                continue
            # Parse process section
            elif clean_line == "Process:":
                start_index = index + 1
                end_index = self._get_end_of_section(start_index)
                p = self._parse_process_info(start_index, end_index)
                p.flog_path = function_log.file_path
                function_log.add_process(p)
                process_count += 1
                index = (end_index+1)
                # Parse API calls related to process
                api_call_start_index = self._find_api_call_beginning(index)
                if api_call_start_index:
                    api_call_index = 0
                    api_call_end_index = self._get_end_of_section(api_call_start_index)
                    self._parse_api_calls(api_call_start_index, api_call_end_index, api_call_index, p)
                    api_call_index = p.api_calls[-1].index + 1
                    index = api_call_end_index + 1
                else:
                    index += 1
                continue
            elif clean_line == "Thread:":
                # Parse API calls related to thread and add them to the last
                # process
                api_call_start_index = self._find_api_call_beginning(index)
                if api_call_start_index:
                    api_call_end_index = self._get_end_of_section(api_call_start_index)
                    current_process = function_log.processes[process_count - 1]
                    self._parse_api_calls(api_call_start_index, api_call_end_index, api_call_index, current_process)
                    api_call_index = p.api_calls[-1].index + 1
                    index = api_call_end_index + 1
                else:
                    index += 1
                continue
            index += 1
        return function_log

    @staticmethod
    def probe(file_path: str) -> bool:
        """
        Checks whether the file given as file_path can be parsed by VmRayFlogParser
        :param file_path: Path to the file to probe
        :return: Indicates whether the file can be parsed by VmRayFlogParser
        """
        with open(file_path, "r", encoding='utf-8-sig') as f:
            first_line = f.readline()
        return first_line.strip() == "# Flog Txt Version 1"

    def _parse_header_info(self, start_index: int, end_index: int, flog: FunctionLog) -> None:
        """
        Parses the header information from the function log
        :param start_index: Index of the beginning of the header information
        block
        :param end_index: Index of the end of the header information block
        :param flog: Function log object
        """
        if self._content[start_index].startswith("# Flog"):
            version_parts = self._content[start_index].split(" ")
            if version_parts:
                flog.version = version_parts[-1].strip()
        parameter_mapping = {
            "Analyzer Version": ("sandbox_version", "string"),
            "Log Creation Date": ("analysis_ts", "date"),
        }
        index = start_index + 1
        while index <= end_index:
            clean_line = self._content[index].strip().lstrip("# ")
            key, val = RegexHelper.get_key_value_pair(clean_line, separator=":")
            val = val.strip("\"\'")
            if key in parameter_mapping.keys():
                property_name = parameter_mapping[key][0]
                if parameter_mapping[key][1] == "date":
                    ts = FlogParserHelper.parse_timestamp(val)
                    if ts:
                        setattr(flog, property_name, ts)
                else:
                    setattr(flog, property_name, val.replace("\\\\", "\\"))
            index += 1

    def _parse_process_info(self, start_index: int, end_index: int) -> Process:
        """
        Parses the process information from the function log
        :param start_index: Index of the beginning of the process information
        block
        :param end_index: Index of the end of the process information block
        :return: Process object containing the parsed process information
        """
        p = Process()
        parameter_mapping = {
            "os_pid": ("os_id", "int"),
            "image_name": ("name", "string"),
            "filename": ("file_path", "string"),
            "cmd_line": ("cmd_line", "string"),
            "os_username": ("owner", "string"),
        }
        index = start_index
        while index <= end_index:
            clean_line = self._content[index].strip()
            key, val = RegexHelper.get_key_value_pair(clean_line)
            val = val.strip("\"\'")
            if key in parameter_mapping.keys():
                property_name = parameter_mapping[key][0]
                if parameter_mapping[key][1] == "int":
                    setattr(p, property_name, int(val, 0))
                else:
                    setattr(p, property_name, val.replace("\\\\", "\\"))
            index += 1
        return p

    def _parse_api_calls(self, start_index: int, end_index: int, api_call_start_index: int, process: Process) -> None:
        """
        Parses the API calls belonging to one process
        :param start_index: Start index of the API calls to parse
        :param end_index: End index of the API calls to parse
        :param api_call_start_index: API call start index
        :return: List of parsed APICall objects containing the parsed system
        calls
        """
        index = start_index
        api_call_index = api_call_start_index
        while index <= end_index:
            try:
                api_call_str = self._content[index].strip()
                parsed_api_call = self._parse_api_call_str(api_call_str)
                parsed_api_call.index = api_call_index
                parsed_api_call.flog_index = index+1
                process.add_api_call(parsed_api_call)
                api_call_index += 1
            except Exception as ex:
                self._logger.error("Could not parse API call in line {}. Reason: {}".format(index+1, ex))
            finally:
                index += 1

    def _parse_api_call_str(self, api_call_str: str) -> APICall:
        """
        Parses a VM-Ray API call string
        :param api_call_str: String that contains the API call
        :return: APICall object containing the parsed API call information
        """
        api_call = APICall()
        # Parse API call function name and time
        api_call_str_parts = api_call_str.split(" ", 2)
        if not REGEX_VMRAY_TIME_END.search(api_call_str_parts[0].strip()):
            raise Exception("Time of API call has the wrong format. String: '{}'.".format(api_call_str))
        if not REGEX_API_CALL_NAME.search(api_call_str_parts[1]):
            raise Exception("API call function name has the wrong format. String: '{}'.".format(api_call_str))
        if not REGEX_VMRAY_API_CALL_RETURN.search(api_call_str_parts[2]):
            raise Exception("API call argument string has the wrong format. String: '{}'.".format(api_call_str))
        api_call.time = float(api_call_str_parts[0].strip("\[\]"))
        api_call.function_name = api_call_str_parts[1]
        # Parse arguments and return value
        if ") returned" in api_call_str_parts[2]:
            parts = api_call_str_parts[2].rsplit(") returned", 1)
            args_str = parts[0][1:]
            return_value_str = parts[1].strip()
            return_value = self._parse_ret_value_str(return_value_str)
            api_call.return_value = return_value
        else:
            args_str = api_call_str_parts[2][1:-1]
        # Check if there are IN and OUT arguments
        if args_str.startswith("in: "):
            arg_parts = args_str.split(" | out:")
            in_args_str = arg_parts[0][4:]
            out_args_str = arg_parts[1]
            in_args = self._parse_args_str(in_args_str, is_in=True)
            out_args = self._parse_args_str(out_args_str, is_out=True)
            args = FlogParserHelper.consolidate_args(in_args, out_args)
            api_call.arguments = args
            api_call.has_in_out_args = True
        else:
            args = self._parse_args_str(args_str)
            api_call.arguments = args
        return api_call

    def _parse_ret_value_str(self, ret_val_str: str) -> Any:
        """
        Parses the return value string of a API call
        :param ret_val_str: Return value string
        :return: Return value
        """
        if ret_val_str.startswith("="):
            ret_val_str = ret_val_str[1:]
        if ret_val_str.startswith("\""):
            # Check if the return value includes a normalized string
            if "\" (normalized: " in ret_val_str:
                parts = ret_val_str.split("\" (normalized: ")
                return_value = parts[0][1:]
            else:
                return_value = ret_val_str[1:-1]
            return_value = return_value.replace("\\\\", "\\").lower()
        else:
            if "*" not in ret_val_str:
                return_value = int(ret_val_str, 0)
            else:
                return_value = self._parse_pointer(ret_val_str)
        return return_value

    def _parse_args_str(self, args_str: str, is_in: Optional[bool] = False, is_out: Optional[bool] = False) \
            -> List[Argument]:
        """
        Parses the argument string from a API call
        :param args_str: String containing the arguments of a API call
        :param is_in: Indicates whether args_str represents inbound arguments
        :param is_out: Indicates whether args_str represents outbound arguments
        :return: Dictionary containing the argument name as key with the
        corresponding argument value
        """
        args = []
        index = 0
        # Iterate through arguments string
        while index < len(args_str):
            # Argument starts with a key; delimiter is the equal sign
            start_index_key = index
            while args_str[index] != "=":
                index += 1
            key = args_str[start_index_key:index]
            # Parse the corresponding value
            index += 1
            start_index_val = index
            # Value is a string delimited by quotes
            if args_str[start_index_val] == '"':
                contains_normalized = False
                if "normalized" in args_str[start_index_val:]:
                    contains_normalized = True
                    r = REGEX_ARGUMENT_VALUE_NORMALIZED.search(args_str[start_index_val:])
                else:
                    r = REGEX_ARGUMENT_VALUE.search(args_str[start_index_val:])
                if not r:
                    value = ""
                    index_val = start_index_val
                else:
                    if contains_normalized:
                        value = r.group(1)
                    else:
                        value = r.group(0)
                    end = r.end()
                    index_val = start_index_val + end
                # Normalize value
                value = self._clean_value(value)
                # Find beginning of next parameter
                while index_val < len(args_str):
                    if args_str[index_val] == ",":
                        if args_str[index_val - 1] == '"' or args_str[index_val - 1] == ')':
                            if args_str[index_val - 2] != "\\":
                                break
                            elif args_str[index_val - 3] == "\\":
                                break
                    index_val += 1
                # Set index to start of new parameter if there is one
                if index_val == len(args_str):
                    index = index_val
                else:
                    index = index_val+2
            # Value is a simple integer or a function pointer identified by
            # parentheses
            else:
                is_fp = False
                while index < len(args_str) and args_str[index] != ",":
                    if args_str[index] == "(":
                        is_fp = True
                        parantheses_count = 1
                        index_val = index+1
                        while parantheses_count != 0:
                            if args_str[index_val] == "(":
                                parantheses_count += 1
                            elif args_str[index_val] == ")":
                                parantheses_count -= 1
                            elif args_str[index_val] == "\"" or args_str[index_val] == "'":
                                r = REGEX_ARGUMENT_VALUE.search(args_str[index_val:])
                                index_val = index_val + r.end() - 1
                            index_val += 1
                        index = index_val-1
                    if args_str[index] == "*":
                        is_fp = True
                    if args_str[index] == "\"" or args_str[index] == "'":
                        r = REGEX_ARGUMENT_VALUE.search(args_str[index:])
                        index = index + r.end() - 1
                    index += 1
                if is_fp:
                    pointer_str = args_str[start_index_val:index]
                    value = self._parse_pointer(pointer_str)
                else:
                    str_val = args_str[start_index_val:index]
                    str_val = REGEX_CLOSING_PARANTHESES.sub('', str_val)
                    value = int(str_val, 0)
                index += 2
            if isinstance(value, str):
                value = value.strip()
            arg_obj = Argument()
            arg_obj.name = key.strip()
            arg_obj.value = value
            arg_obj.is_in = is_in
            arg_obj.is_out = is_out
            args.append(arg_obj)
        return args

    def _parse_pointer(self, pointer_str: str) -> Pointer:
        """
        Parses a pointer string
        :param pointer_str: String containing the pointer
        :return: Pointer object containing the parsed pointer information
        """
        ptr = Pointer()
        # Pointer has an address
        ptr_match = REGEX_POINTER.match(pointer_str)
        if ptr_match:
            sptr_match = REGEX_STRUCT_POINTER.match(pointer_str)
            vptr_match = REGEX_VALUE_POINTER.match(pointer_str)
            # Pointer is a struct pointer
            if sptr_match:
                ptr_adr_str = pointer_str[sptr_match.start():sptr_match.end()-2]
                ptr_args_str = pointer_str[sptr_match.end():len(pointer_str)-1]
                ptr.address = int(ptr_adr_str, 0)
                ptr.arguments = self._parse_args_str(ptr_args_str)
            # Pointer is a value pointer
            elif vptr_match:
                ptr_adr_str = pointer_str[vptr_match.start():vptr_match.end() - 2]
                ptr.address = int(ptr_adr_str, 0)
                val_str = pointer_str[vptr_match.end():len(pointer_str)]
                # References value pointer a further pointer?
                ptr_match = REGEX_NESTED_POINTER.match(val_str)
                if ptr_match:
                    ptr.arguments = self._parse_pointer(val_str)
                # Pointer is a list of values
                elif val_str.startswith("(["):
                    ptr.arguments = self._parse_value_list(val_str)
                else:
                    try:
                        ptr.arguments = int(val_str, 0)
                    except ValueError:
                        val_str = val_str.replace("\\\\", "\\")
                        ptr.arguments = val_str.lower().strip("\"'")
            # Pointer has no value but only an address
            else:
                r = REGEX_POINTER_ADDRESS.match(pointer_str)
                ptr.address = int(r.group(0), 0)
        # Pointer has no address
        else:
            if pointer_str.startswith("(["):
                ptr.arguments = self._parse_value_list(pointer_str)
            else:
                num_of_parentheses = REGEX_PARANTHESES.match(pointer_str).end()
                ptr_args_str = pointer_str[num_of_parentheses:len(pointer_str)-num_of_parentheses]
                ptr.arguments = self._parse_args_str(ptr_args_str)
        return ptr

    def _parse_value_list(self, value_str: str) -> List[Any]:
        value_list = []
        raw_vals = value_str.strip("()").split(", [")
        if raw_vals:
            for raw_val in raw_vals:
                parts = raw_val.split("=")
                if parts:
                    val = self._clean_value(parts[1])
                    value_list.append(val)
        return value_list

    def _get_end_of_section(self, start_index: int) -> int:
        """
        Returns the end index of a section
        :param start_index: Start index to search end of section from
        :return: End index of section
        """
        index = start_index
        while self._content[index].strip() != "":
            if (index+1) >= len(self._content):
                return index
            index += 1
        return index-1

    @staticmethod
    def _clean_value(val: str) -> Any:
        cleaned_val = val.lower().strip()
        # Remove unwanted chars
        unwanted_chars = "\"'"
        for char in unwanted_chars:
            cleaned_val = cleaned_val[1:] if cleaned_val.startswith(char) else cleaned_val
            cleaned_val = cleaned_val[:-1] if cleaned_val.endswith(char) else cleaned_val
        # Replace double backslashes
        cleaned_val = cleaned_val.replace("\\\\", "\\")
        try:
            cleaned_val = int(cleaned_val, 0)
        except ValueError:
            pass
        return cleaned_val

    def _find_api_call_beginning(self, start_index):
        """
        Finds the beginning of an API call section by looking for lines
        starting with pattern '[dddd.ddd]'
        :param start_index: Start index indicates the beginning of the search
        range
        :return: Index where the API call section starts
        """
        index = start_index
        while REGEX_VMRAY_TIME.search(self._content[index].strip()) is None:
            if (index+1) >= len(self._content):
                return None
            if self._content[index].strip() == "Process:":
                return None
            index += 1
        return index

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
from typing import Optional, List, Dict, Any, TYPE_CHECKING
import re

# Avoid circular import
if TYPE_CHECKING:
    from dynmx.core.api_call import Argument


class Pointer:
    """
    Representation of a pointer
    """

    def __init__(self, address: Optional[int] = None):
        """
        Constructor
        :param address: Address of the pointer
        """
        self.address = address
        self.arguments = []

    def get_argument_values(self, arg_name: str, is_regex_pattern: bool = False) -> List[Any]:
        """
        Returns the value of the argument identified by arg_name
        :param arg_name: Name of argument to return value from
        :param is_regex_pattern: Decides whether arg_name should be handled as
        regex pattern
        :return: List of values of arg_name
        """
        found_values = []
        # Does the pointer reference another pointer?
        if isinstance(self.arguments, Pointer):
            values = self.arguments.get_argument_values(arg_name)
            if values:
                found_values += values
        # Has the pointer multiple arguments?
        elif isinstance(self.arguments, list):
            # Argument is directly addressed
            if ":" in arg_name:
                arg_parts = arg_name.split(":")
                if not len(arg_parts):
                    return found_values
                addressed_arg_name = arg_parts[0]
                args = self._get_arguments_by_name(addressed_arg_name, is_regex_pattern)
                if args and len(args):
                    addressed_arg = args[0]
                else:
                    addressed_arg = None
                if addressed_arg:
                    if len(arg_parts) > 1:
                        sub_arg = ":".join(arg_parts[1:])
                        arg_vals = addressed_arg.value.get_argument_values(sub_arg, is_regex_pattern)
                        if arg_vals:
                            found_values += arg_vals
            else:
                # Search for arg_name as argument name
                values = self._search_argument_values(arg_name, is_regex_pattern)
                if values:
                    found_values += values
        return found_values if found_values else None

    def _get_arguments_by_name(self, arg_name: str, is_regex_pattern: bool = False) -> List[Argument]:
        """
        Returns the arguments of the pointer identified by the argument name
        :param arg_name: Argument name
        :param is_regex_pattern: Indicates whether the argument name is a regex pattern
        :return: List of arguments if arguments were identified, otherwise None
        """
        found_args = []
        for arg in self.arguments:
            if is_regex_pattern:
                if self._is_regex_matching(arg.name, arg_name):
                    found_args.append(arg)
            else:
                if arg.name.lower() == arg_name.lower():
                    found_args.append(arg)
        return found_args if found_args else None

    def _search_argument_values(self, arg_name: str, is_regex_pattern: bool = False) -> Optional[List[Any]]:
        # Avoid import loop
        from dynmx.core.api_call import Argument
        found_values = []
        if isinstance(self.arguments, list):
            for arg in self.arguments:
                if not isinstance(arg, Argument):
                    break
                if isinstance(arg.value, Pointer):
                    ptr_arg_vals = arg.value.get_argument_values(arg_name, is_regex_pattern)
                    if ptr_arg_vals:
                        found_values += ptr_arg_vals
                else:
                    if is_regex_pattern:
                        if self._is_regex_matching(arg.name, arg_name):
                            # Argument found
                            found_values.append(arg.value)
                    else:
                        if arg.name == arg_name:
                            # Argument found
                            found_values.append(arg.value)
        return found_values if found_values else None

    def get_as_dict(self) -> Dict[str, Any]:
        """
        Returns the pointer object as dict
        :return: Pointer object as dict
        """
        # Avoid import loop
        from dynmx.core.api_call import Argument
        result_dict = {
            "pointer_address": self.address,
            "pointer_args": [],
        }
        if isinstance(self.arguments, list):
            for arg in self.arguments:
                if isinstance(arg, Argument):
                    result_dict["pointer_args"].append(arg.get_as_dict())
                else:
                    result_dict["pointer_args"].append(arg)
        else:
            result_dict["pointer_args"] = self.arguments
        return result_dict

    def convert(self) -> Dict[str, Any]:
        """
        Converts the pointer object to the dynmx flog format
        :return: Pointer object in dynmx flog format
        """
        # Avoid import loop
        from dynmx.core.api_call import Argument
        convert_result = {
            "address": self.address,
            "arguments": [],
        }
        # Argument of pointer is a pointer
        if isinstance(self.arguments, Pointer):
            convert_result["arguments"] = self.arguments.convert()
        elif isinstance(self.arguments, list):
            for arg in self.arguments:
                if isinstance(arg, Argument) or isinstance(arg, Pointer):
                    convert_result["arguments"].append(arg.convert())
                else:
                    convert_result["arguments"].append(arg)
        else:
            convert_result["arguments"] = self.arguments
        return convert_result

    def _get_arguments_by_name(self, arg_name, is_regex_pattern=False) -> Optional[List[Argument]]:
        found_args = []
        for arg in self.arguments:
            if is_regex_pattern:
                if self._is_regex_matching(arg.name, arg_name):
                    found_args.append(arg)
            else:
                if arg.name == arg_name:
                    found_args.append(arg)
        return found_args if found_args else None

    @staticmethod
    def _is_regex_matching(string_to_check: str, regex_pattern: str, ignore_case: bool = True) -> bool:
        """
        Returns whether regex_pattern matches string_to_check
        :param string_to_check: String that should be matched to regex_pattern
        :param regex_pattern: Regex pattern
        :param ignore_case: Decides whether to ignore case while matching
        :return: Indicates whether regex_pattern has matched
        """
        if ignore_case:
            p = re.compile(regex_pattern, re.IGNORECASE)
        else:
            p = re.compile(regex_pattern)
        return (p.search(string_to_check) is not None)

    def __eq__(self, other: Pointer) -> bool:
        if not isinstance(other, Pointer):
            return NotImplemented
        is_equal = (self.address == other.address)
        if isinstance(self.arguments, list):
            if not isinstance(other.arguments, list):
                return False
            if len(self.arguments) != len(other.arguments):
                return False
            for ix, arg in enumerate(self.arguments):
                is_equal &= (arg == other.arguments[ix])
        else:
            is_equal &= (self.arguments == other.arguments)
        return is_equal

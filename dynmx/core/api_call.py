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
import re
from uuid import uuid4
from typing import Optional, List, Dict, Any
from dynmx.core.pointer import Pointer


class APICall:
    """
    Representation of a system call
    """

    def __init__(self, index: Optional[int] = None, function_name: Optional[str] = None, time: Optional[float] = None,
                 return_value: Optional = None, has_in_out_args: Optional[bool] = False,
                 flog_index: Optional[int] = None):
        """
        Constructor
        :param index: Index of system call
        :param function_name: Function name of system call
        :param time: Relative time system call was executed in seconds
        :param return_value: Return value of system call
        :param has_in_out_args: Indicates whether system call has in and out
        arguments
        :param flog_index: Line number of system call in flog
        """
        self.index = index
        self.function_name = function_name
        self.time = time
        self.arguments = []
        self.return_value = return_value
        self.has_in_out_args = has_in_out_args
        self.flog_index = flog_index

    def get_argument_values(self, arg_name: str, is_in: Optional[bool] = None, is_out: Optional[bool] = None,
                            is_regex_pattern: bool = False) -> Optional[List[Any]]:
        """
        Returns the argument value identified by arg_name
        :param arg_name: Name of argument of that the value should be returned
        :param is_in: Indicates whether argument is inbound
        :param is_out: Indicates whether argument is outbound
        :param is_regex_pattern: Indicates whether arg_name is a regex pattern
        :return: List of argument values
        """
        if ":" in arg_name:
            arg_vals = self._get_deep_argument(arg_name,
                                               is_in,
                                               is_out,
                                               is_regex_pattern=is_regex_pattern)
        else:
            arg_vals = self._deep_argument_search(arg_name,
                                                  is_in,
                                                  is_out,
                                                  is_regex_pattern=is_regex_pattern)
        return arg_vals

    def get_return_value(self, arg_name: Optional[str] = None, is_regex_pattern: bool = False) -> Optional[Any]:
        """
        Returns the return value of the API call
        :return: Return value
        """
        if arg_name:
            arg_val = self._get_deep_return_value(arg_name, is_regex_pattern=is_regex_pattern)
            if isinstance(arg_val, Pointer):
                arg_val = arg_val.arguments
            return arg_val
        else:
            if isinstance(self.return_value, Pointer):
                if not isinstance(list, self.return_value.arguments):
                    return self.return_value.arguments
            else:
                return self.return_value
        return None

    def get_return_value_pointer(self, arg_name: str, is_regex_pattern: bool = False) -> Optional[Any]:
        """
        Returns the return value identified by arg_name
        :param arg_name: Name of argument of that the value should be returned
        :param is_regex_pattern: Indicates whether arg_name is a regex pattern
        :return: Argument value
        """
        if isinstance(self.return_value, Pointer):
            arg_val = self._deep_argument_search(arg_name,
                                                 None,
                                                 None,
                                                 is_regex_pattern=is_regex_pattern)
            if arg_val:
                return arg_val
        return None

    def has_argument(self, arg_name: str, is_regex_pattern: bool = False) -> bool:
        """
        Return whether a system call has the attribute identified by arg_name
        :param arg_name: Name of argument that should be present
        :param is_regex_pattern: Indicates whether arg_name is a regex pattern
        :return: Indicates whether the argument is present
        """
        arg_val = self.get_argument_values(arg_name,
                                           is_regex_pattern=is_regex_pattern)
        return (arg_val is not None)

    def _get_deep_argument(self, arg_name: str, is_in: bool, is_out: bool, is_regex_pattern: bool = False) \
            -> Optional[List[Any]]:
        """
        Returns an argument value directly addressed by arg_name in all child objects (Pointer objects)
        :param arg_name: Directly addressed argument in child object (addressed by arg:child_arg)
        :param is_in: Indicates whether argument is inbound
        :param is_out: Indicates whether argument is outbound
        :param is_regex_pattern: Indicates whether arg_name is a regex pattern
        :return: List of values of searched argument
        """
        found_values = []
        arg_parts = arg_name.split(":")
        if not len(arg_parts):
            return found_values
        addressed_arg_name = arg_parts[0]
        addressed_args = self._get_arguments_by_name(addressed_arg_name, is_regex_pattern)
        if not addressed_args:
            return None
        else:
            addressed_arg = addressed_args[0]
        if is_in is not None:
            if addressed_arg.is_in != is_in:
                return None
        if is_out is not None:
            if addressed_arg.is_out != is_out:
                return None
        # Value has to be a pointer to find next addressed argument
        if not isinstance(addressed_arg.value, Pointer):
            return None
        # Find next addressed argument
        if len(arg_parts) > 1:
            sub_arg = ":".join(arg_parts[1:])
            arg_vals = addressed_arg.value.get_argument_values(sub_arg, is_regex_pattern)
            if arg_vals:
                found_values += arg_vals
        else:
            return None
        return found_values if len(found_values) > 0 else None

    def _get_deep_return_value(self, arg_name: str, is_regex_pattern: bool = False) -> Optional[Any]:
        """
        Returns an return value directly addressed by arg_name in all child objects (Pointer objects)
        :param arg_name: Directly addressed argument in child object (addressed by arg:child_arg)
        :param is_in: Indicates whether argument is inbound
        :param is_out: Indicates whether argument is outbound
        :param args: Arguments to search in
        :param is_regex_pattern: Indicates whether arg_name is a regex pattern
        :return: List of values of searched argument
        """
        found_values = []
        if ":" not in arg_name:
            args = self._get_return_value_args_by_name(arg_name, is_regex_pattern)
            if args and len(args):
                return args[0].value
        arg_parts = arg_name.split(":")
        if not len(arg_parts):
            return found_values
        addressed_arg_name = arg_parts[0]
        addressed_args = self._get_return_value_args_by_name(addressed_arg_name, is_regex_pattern)
        if addressed_args:
            addressed_arg = addressed_args[0]
        else:
            return None
        # Value has to be a pointer to find next addressed argument
        if not isinstance(addressed_arg.value, Pointer):
            return None
        # Find next addressed argument
        if len(arg_parts) > 1:
            sub_arg = ":".join(arg_parts[1:])
            arg_vals = addressed_arg.value.get_argument_values(sub_arg, is_regex_pattern)
            found_values += arg_vals
        else:
            return None
        return found_values if len(found_values) > 0 else None

    def _get_arguments_by_name(self, arg_name: str, is_regex_pattern: bool = False) -> Optional[List[Argument]]:
        """
        Returns the arguments of the system call identified by the argument name
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

    def _get_return_value_args_by_name(self, arg_name: str, is_regex_pattern: bool = False) -> Optional[List[Argument]]:
        """
        Returns the arguments of the system call return value identified by the argument name
        :param arg_name: Argument name
        :param is_regex_pattern: Indicates whether the argument name is a regex pattern
        :return: List of arguments if arguments were identified, otherwise None
        """
        found_args = []
        if isinstance(self.return_value, Pointer):
            for arg in self.return_value.arguments:
                if is_regex_pattern:
                    if self._is_regex_matching(arg.name, arg_name):
                        found_args.append(arg)
                else:
                    if arg.name.lower() == arg_name.lower():
                        found_args.append(arg)
        return found_args if found_args else None

    def _deep_argument_search(self, arg_name: str, is_in: Optional[bool], is_out: Optional[bool],
                              is_regex_pattern: bool = False) -> Optional[List[Any]]:
        """
        Searches for argument in all child objects (Pointer objects)
        :param arg_name: Name of argument to search for
        :param is_in: Indicates whether argument is inbound
        :param is_out: Indicates whether argument is outbound
        :param is_regex_pattern: Indicates whether arg_name is a regex pattern
        :return: List of values of searched argument
        """
        found_values = []
        found_args = self._get_arguments_by_name(arg_name)
        if found_args:
            for arg in found_args:
                if is_in is not None:
                    if arg.is_in != is_in:
                        continue
                if is_out is not None:
                    if arg.is_out != is_out:
                        continue
                if isinstance(arg.value, Pointer):
                    if not isinstance(arg.value.arguments, list):
                        found_values.append(arg.value.arguments)
                        continue
                found_values.append(arg.value)
        for arg in self.arguments:
            if isinstance(arg.value, Pointer):
                if isinstance(arg.value.arguments, list):
                    arg_vals = arg.value.get_argument_values(arg_name, is_regex_pattern)
                    if arg_vals:
                        found_values += arg_vals
        return found_values if len(found_values) > 0 else None

    def get_as_dict(self) -> Dict[str, Any]:
        """
        Returns the system call object as dictionary
        :return: SystemCall object as dictionary
        """
        result_dict = {
            "api_call_index": self.index,
            "api_call_flog_index": self.flog_index,
            "api_call_function": self.function_name,
            "api_call_time": self.time,
            "api_call_args": [],
            "api_call_return_value": None,
        }
        for arg in self.arguments:
            result_dict["api_call_args"].append(arg.get_as_dict())
        # Return value conversion
        if isinstance(self.return_value, Pointer):
            result_dict["api_call_return_value"] = self.return_value.convert()
        else:
            result_dict["api_call_return_value"] = self.return_value
        return result_dict

    def convert(self) -> Dict[str, Any]:
        """
        Converts the system call to the dynmx flog format
        :return: Dictionary representing the SystemCall object in the dynmx flog format
        """
        convert_result = {
            "flog_index": str(uuid4()),
            "function_name": self.function_name,
            "time": self.time,
            "arguments": [],
            "return_value": None,
        }
        # Argument conversion
        for arg in self.arguments:
            convert_result["arguments"].append(arg.convert())
        # Return value conversion
        if isinstance(self.return_value, Pointer):
            convert_result["return_value"] = self.return_value.convert()
        else:
            convert_result["return_value"] = self.return_value
        return convert_result

    @staticmethod
    def _is_regex_matching(string_to_check: str, regex_pattern: str, ignore_case: bool = True) -> bool:
        """
        Checks whether the the given string is matching the regex pattern
        :param string_to_check: String to check for regex pattern
        :param regex_pattern: Regex pattern
        :param ignore_case: Indicates whether to match case insensitive
        :return: Whether the string was matched by the regex pattern
        """
        if ignore_case:
            p = re.compile(regex_pattern, re.IGNORECASE)
        else:
            p = re.compile(regex_pattern)
        return (p.search(string_to_check) is not None)

    def __eq__(self, other: APICall) -> bool:
        if not isinstance(other, APICall):
            return NotImplemented
        is_equal = True
        attributes = self.__dict__.keys()
        for attr in attributes:
            if attr == "arguments":
                if len(self.arguments) != len(other.arguments):
                    is_equal = False
                    break
                for ix, arg in enumerate(self.arguments):
                    is_equal &= (arg == other.arguments[ix])
            is_equal &= (getattr(self, attr) == getattr(other, attr))
        return is_equal

    def __str__(self) -> str:
        return "{} ({}; {})".format(self.function_name, self.flog_index, self.index)

    def __repr__(self) -> str:
        return str(self)


class ApiCallSignature:
    """
    Representation of an API call signature without concrete values
    """

    def __init__(self, function_name: Optional[str] = None, description: Optional[str] = None,
                 calling_convention: Optional[str] = None, return_type: Optional[str] = None,
                 return_value_desc: Optional[str] = None):
        """
        Constructor
        :param function_name: Function name
        :param description: Description of the API call
        :param calling_convention: Calling convention
        :param return_type: Type of the return value
        :param return_value_desc: Description of the return value
        """
        self.function_name = function_name
        self.description = description
        self.calling_convention = calling_convention
        self.return_type = return_type
        self.return_value_desc = return_value_desc
        self.arguments = []


class Argument:
    """
    Representation of an API call argument
    """

    def __init__(self, name: Optional[str] = None, value: Optional[Any] = None, is_in: bool = False,
                 is_out: bool = False):
        """
        Constructor
        :param name: Argument name
        :param value: Argument value
        :param is_in: Defines whether the argument is inbound
        :param is_out: Defines whether the argument is outbound
        """
        self.name = name
        self.value = value
        self.is_in = is_in
        self.is_out = is_out

    def get_as_dict(self) -> Dict[str, Any]:
        """
        Returns the system call argument object as dictionary
        :return: System call argument object as dictionary
        """
        result_dict = {
            "api_call_arg_name": self.name,
            "api_call_arg_is_in": self.is_in,
            "api_call_arg_is_out": self.is_out,
        }
        # Argument conversion to dict
        # Is value pointer?
        if isinstance(self.value, Pointer):
            result_dict["value"] = self.value.get_as_dict()
        else:
            result_dict["value"] = self.value
        return result_dict

    def convert(self) -> Dict[str, Any]:
        """
        Converts the Argument object to the dynmx format
        :return: Dictionary representing the converted Argument object
        """
        convert_result = {
            "name": self.name,
            "is_in": self.is_in,
            "is_out": self.is_out,
        }
        # Is value pointer?
        if isinstance(self.value, Pointer):
            convert_result["value"] = self.value.convert()
        else:
            convert_result["value"] = self.value
        return convert_result

    def __eq__(self, other: Argument) -> bool:
        if not isinstance(other, Argument):
            return NotImplemented
        is_equal = True
        attributes = self.__dict__.keys()
        for attr in attributes:
            is_equal &= (getattr(self, attr) == getattr(other, attr))
        return is_equal

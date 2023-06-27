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
from typing import Optional, List, TYPE_CHECKING
from datetime import datetime

from dynmx.core.pointer import Pointer

if TYPE_CHECKING:
    from dynmx.core.api_call import Argument


class FlogParserHelper:
    """
    Helper class for function log parsers
    """

    @staticmethod
    def consolidate_args(args_in: List[Argument], args_out: List[Argument]) -> List[Argument]:
        """
        Consolidates the in- and outbound arguments that were parsed based on the name and value of the argument
        :param args_in: List of Argument objects containing the inbound arguments of the API call
        :param args_out: List of Argument objects containing the outbound arguments of the API call
        :return: Consolidated list of Argument objects
        """
        out_args_to_keep = []
        if args_out and len(args_out) > 0:
            for ix, arg_out in enumerate(args_out):
                found_ix = FlogParserHelper._find_arg(args_in, arg_out.name)
                if found_ix is not None:
                    arg_in = args_in[found_ix]
                    if not isinstance(arg_out.value, Pointer):
                        if arg_in.value is None or arg_in.value == arg_out.value:
                            arg_in.value = arg_out.value
                            arg_in.is_out = True
                        else:
                            out_args_to_keep.append(ix)
                    else:
                        if isinstance(arg_in.value, Pointer):
                            if arg_in.value.address == arg_out.value.address:
                                if isinstance(arg_in.value, list):
                                    if len(arg_in.value.arguments) == 0:
                                        arg_in.value.arguments = arg_out.value.arguments
                                        arg_in.is_out = True
                                    else:
                                        if not arg_in.value == arg_out.value:
                                            out_args_to_keep.append(ix)
                                            arg_in.is_out = True
                                else:
                                    if arg_in.value.arguments is None or \
                                            arg_in.value.arguments == arg_out.value.arguments:
                                        arg_in.value.arguments = arg_out.value.arguments
                                        arg_in.is_out = True
                                    else:
                                        out_args_to_keep.append(ix)
                        else:
                            if arg_in.value == arg_out.value.address:
                                arg_in.value = arg_out.value
                                arg_in.is_out = True
                            else:
                                out_args_to_keep.append(ix)
            for ix in out_args_to_keep:
                args_in.append(args_out[ix])
        return args_in

    @staticmethod
    def _find_arg(args: List[Argument], name: str) -> Optional[Argument]:
        """
        Finds an argument based on the name in a list of arguments
        :param args: List of Argument objects
        :param name: Name of argument to search for
        :return: Index of the found Argument object. If no argument was found None is returned.
        """
        for ix, arg in enumerate(args):
            if arg.name == name:
                return ix
        return None

    @staticmethod
    def parse_timestamp(str_val: str) -> datetime:
        """
        Parses a timestamp
        :param str_val: Timestamp string
        :return: Parsed timestamp
        """
        # 2021-06-03 16:06:54,855
        pattern = ["%d.%m.%Y %H:%M:%S.%f", "%d.%m.%Y %H:%M", "%Y-%m-%d %H:%M:%S,%f"]
        ts = None
        for p in pattern:
            try:
                ts = datetime.strptime(str_val, p)
                if ts:
                    break
            except Exception:
                continue
        return ts

    @staticmethod
    def is_gzip_compressed(file_path: str) -> bool:
        """
        Checks whether a file is gzip compressed
        :param file_path: Path to the file that should be checked
        :return: Bool indicating whether the file is gzip compressed
        """
        gzip_magic_bytes = b'\x1f\x8b'
        with open(file_path, "rb") as f:
            magic_bytes = f.read(2)
        return gzip_magic_bytes == magic_bytes

    @staticmethod
    def parse_value(value_str: str) -> int | str:
        """
        Parses a value
        """
        parsed_value = None
        # Is the value a hex value?
        if isinstance(value_str, str) and value_str.startswith("0x"):
            parsed_value = int(value_str, 0)
        else:
            parsed_value = value_str
        # Is the value a float
        if isinstance(value_str, str) and "." in value_str:
            try:
                parsed_value = float(parsed_value)
            except ValueError:
                pass
        # Is the value an integer?
        else:
            try:
                parsed_value = int(parsed_value)
            except ValueError:
                pass
        return parsed_value

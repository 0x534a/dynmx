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
from typing import Tuple
import re


# Precompile regex patterns for better performance
REGEX_VMRAY_TIME = re.compile(r'^\[\d{4}\.\d{3}\]')
REGEX_VMRAY_TIME_END = re.compile(r'^\[\d{4}\.\d{3}\]$')
REGEX_API_CALL_NAME = re.compile(r'^[0-9a-zA-Z-_:?@].+$')
REGEX_VMRAY_API_CALL_RETURN = re.compile(r'^\(.*?\)( returned.*?.+)?$')
# Arguments
REGEX_ARGUMENT_VALUE = re.compile(r'\"(?:\\.|[^\"\\])*\"')
REGEX_ARGUMENT_VALUE_NORMALIZED = re.compile(r'\(normalized: (\"(?:\\.|[^\"\\])*\")\)')
REGEX_CLOSING_PARANTHESES = re.compile(r'\)$')
# Pointers
REGEX_POINTER = re.compile(r'^0x[0-9a-fA-F]*\*')
REGEX_STRUCT_POINTER = re.compile(r'^0x[0-9a-fA-F]*\*\(')
REGEX_VALUE_POINTER = re.compile(r'^0x[0-9a-fA-F]*\*=')
REGEX_NESTED_POINTER = re.compile(r'^0x[0-9a-fA-F]*\*')
REGEX_POINTER_ADDRESS = re.compile(r'^0x[0-9a-fA-F]*')
REGEX_PARANTHESES = re.compile(r'^\(*')


class RegexHelper:
    @staticmethod
    def is_regex_matching(string_to_check: str, regex_pattern: str, ignore_case: bool = True) -> bool:
        """
        Indicates whether a regex_pattern is matching a string
        :param string_to_check: String to check regex pattern against
        :param regex_pattern: Regex pattern
        :param ignore_case: Decides whether to matching is case insensitive
        :return: Indicates whether regex_pattern is matching string
        """
        if ignore_case:
            p = re.compile(regex_pattern, re.IGNORECASE)
        else:
            p = re.compile(regex_pattern)
        return p.search(string_to_check) is not None

    @staticmethod
    def is_regex_pattern(string_to_check: str) -> bool:
        """
        Checks whether a given string is a regex pattern
        :param string_to_check: String that should be checked
        :return: Indicates whether the string is a regex pattern
        """
        regex_chars = "^([{+*.|\\$"
        for regex_char in regex_chars:
            if regex_char in string_to_check:
                return True
        return False

    @staticmethod
    def is_variable(string_to_check: str) -> bool:
        """
        Checks whether the string is a variable (indicated by $())
        :param string_to_check: String that should be checked
        :return: Indicates whether the string is a variable
        """
        if isinstance(string_to_check, str):
            p = re.compile(r'^\$\([ -~]+\)$')
            return p.search(string_to_check) is not None
        else:
            return False

    @staticmethod
    def get_variable_name(var_string: str) -> str:
        """
        Returns the name of the variable
        :param var_string: String that contains variable name
        :return: Name of variable
        """
        variable_name = re.sub(r'^\$\(', '', var_string)
        variable_name = re.sub(r'\)$', '', variable_name)
        return variable_name

    @staticmethod
    def get_key_value_pair(line: str, separator: str = "=") -> Tuple[str, str]:
        """
        Splits a line separated by given separator into key and value
        :param line: String containing the line to split
        :param separator: Separator string that separates key and value
        :return: Tuple consisting out of parsed key and value
        """
        r = re.search(r'(^[ -~]+ ?{} )([ -~]+)'.format(separator), line)
        return (r.group(1)[:-2].strip(), r.group(2).strip())

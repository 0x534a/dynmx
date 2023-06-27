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
from typing import Any
import pkgutil
import importlib


class ParserLibrary:
    """
    Representation of a library for available flog parsers
    """

    def __init__(self):
        """
        Constructor
        """
        self.parsers = []

    def load(self, parser_pkg: Any) -> None:
        """
        Loads the available function log parsers
        :param parser_pkg: Python package that includes the parsers
        """
        for finder, name, is_pkg in pkgutil.iter_modules(parser_pkg.__path__,
                                                         parser_pkg.__name__ + "."):
            if is_pkg:
                continue
            if name != "dynmx.flog_parsers.parser" and name != "dynmx.flog_parsers.parser_library":
                module = importlib.import_module(name)
                class_name = self._get_parser_class(module.__file__)
                cls = getattr(module, class_name)
                self.parsers.append(cls)

    @staticmethod
    def _get_parser_class(path: str) -> str:
        """
        Returns the class name of a flog parser class
        :param path: Path to flog parser class file
        :return: Class name of flog parser
        """
        with open(path) as f:
            content = [next(f) for x in range(50)]
        for line in content:
            if line.strip().startswith("class"):
                class_name = line.strip().split(" ")[1][:-1]
                class_name = class_name.split("(")[0]
                return class_name

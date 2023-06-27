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
from typing import Optional, TYPE_CHECKING
import os
import json
import datetime
import time
import gzip

from dynmx.converters.dynmx_harmonizer import DynmxHarmonizer
from dynmx.helpers.logging_helper import LoggingHelper

# Avoid cyclic imports
if TYPE_CHECKING:
    from dynmx.core.function_log import FunctionLog


class DynmxConverter:
    """
    Converter for the dynmx flog format
    """

    def __init__(self, api_call_db: Optional[str] = None):
        """
        Constructor
        :param api_call_db: Path to the API call sqlite database used for harmonization. If no path is passed
        harmonization will not take place while converting the function log.
        """
        # Load API call database
        self._logger = LoggingHelper.get_logger(__name__)
        if api_call_db:
            self._harmonizer = DynmxHarmonizer(api_call_db)
            self._logger.debug("API call database is {}. Harmonization will take place based on this database.".format(
                api_call_db))
        else:
            self._harmonizer = None
            self._logger.debug("No API call database given. No harmonization will take place.")

    def convert(self, flog: FunctionLog, output_dir: str, compress: bool) -> None:
        """
        Converts the flog to the dynmx flog format
        :param flog: Function log to convert
        :param output_dir: Directory to write converted flog to
        :param compress: Defines whether the converted flog should be compressed
        """
        self._logger = LoggingHelper.get_logger(__name__, flog.file_path)
        if self._harmonizer:
            self._harmonizer.harmonize_flog(flog)
        self._logger.info("Converting function log '{}'".format(flog.name))
        converted_flog = flog.convert()
        self._logger.info("Preparing JSON output of converted log")
        tic = time.perf_counter()
        json_output = json.dumps(converted_flog, indent=4, ensure_ascii=False)
        toc = time.perf_counter()
        runtime_json = toc - tic
        self._logger.info("JSON conversion took {:.4f}s".format(runtime_json))
        output_path = self._get_converted_file_path(flog.file_path, output_dir, compress)
        self._logger.info("Writing converted function log '{}' to path '{}'".format(flog.name, output_path))
        if compress:
            with gzip.open(output_path, "wb+") as output_file:
                header = self._get_file_header(flog.file_path)
                output_file.write(header.encode())
                output_file.write(json_output.encode())
        else:
            with open(output_path, "w+") as output_file:
                header = self._get_file_header(flog.file_path)
                output_file.write(header)
                output_file.write(json_output)

    @staticmethod
    def _get_converted_file_path(flog_path: str, output_dir: str, compress: bool) -> str:
        """
        Returns the file path for the converted flog
        :param flog_path: Path of flog to convert
        :param output_dir: Output directory
        :param compress: Compress output file
        :return: File path for the converted flog
        """
        file_name = os.path.basename(flog_path)
        if compress:
            converted_flog_file_name = os.path.splitext(file_name)[0] + \
                                       "_dynmx.txt.gz"
        else:
            converted_flog_file_name = os.path.splitext(file_name)[0] + \
                                       "_dynmx.txt"
        if not output_dir:
            output_dir = os.path.dirname(flog_path)
        return os.path.join(output_dir, converted_flog_file_name)

    @staticmethod
    def _get_file_header(flog_path: str) -> str:
        """
        Returns the dynmx flog file header
        :param flog_path: Path of flog to convert
        """
        header = "# dynmx generic function log\n"
        header += "# converted from: {}\n".format(flog_path)
        header += "# converted on: {}\n\n".format(datetime.datetime.now())
        return header

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
import argparse


class ArgumentHelper:
    """
    Represents a helpers for script argument handling
    """

    def __init__(self):
        """
        Constructor
        """
        # Define default parameters
        self._default_params = {
            "format": "overview",
            "show-log": False,
            "detail": False,
            "log-level": "info",
        }

    def handle(self) -> argparse.Namespace:
        """
        Handles the script parameter
        :return: Parsed arguments
        """
        parser = self._build_arg_parser()
        args = parser.parse_args()
        return args

    def _build_arg_parser(self) -> argparse.ArgumentParser:
        """
        Builds the needed argument parser
        :return: ArgumentParser object
        """
        parser = argparse.ArgumentParser(description="Detect dynmx signatures in dynamic program execution information (function logs)")
        subparsers = parser.add_subparsers(title="sub-commands",
                                           description="task to perform",
                                           dest="command")
        # General script parameters
        parser.add_argument("--format",
                            "-f",
                            choices=["overview", "detail"],
                            default=self._default_params["format"],
                            help="Output format")
        parser.add_argument("--show-log",
                            action='store_true',
                            default=self._default_params["show-log"],
                            help="Show all log output on stdout")
        parser.add_argument("--log",
                            "-l",
                            type=argparse.FileType("a+"),
                            help="log file")
        parser.add_argument("--log-level",
                            choices=["debug", "info", "error"],
                            default=self._default_params["log-level"],
                            help="Log level (default: {})".format(self._default_params["log-level"]))
        parser.add_argument("--worker",
                            "-w",
                            metavar="N",
                            type=int,
                            help="Number of workers to spawn (default: number of processors - 2)")
        # Parameters for command 'detect'
        parser_detect = subparsers.add_parser("detect",
                                              help="Detects a dynmx signature")
        req_detect_args = parser_detect.add_argument_group("required arguments")
        req_detect_args.add_argument("--sig",
                                     "-s",
                                     nargs="+",
                                     required=True,
                                     help="dynmx signature(s) to detect")
        req_detect_args.add_argument("--input",
                                     "-i",
                                     nargs="+",
                                     required=True,
                                     help="Input files")
        parser_detect.add_argument("--recursive",
                                   "-r",
                                   help="Search for input files recursively",
                                   action="store_true",
                                   default=False)
        parser_detect.add_argument("--json-result",
                                   help="JSON formatted result file",
                                   type=argparse.FileType("w+"))
        parser_detect.add_argument("--runtime-result",
                                   help="Runtime statistics file formatted in CSV",
                                   type=argparse.FileType("w+"))
        parser_detect.add_argument("--detect-all",
                                   help="Detect signature in all processes and do not stop after the first detection",
                                   action="store_true",
                                   default=False)
        # Parameters for command 'check'
        parser_check = subparsers.add_parser("check",
                                             help="Checks the syntax of dynmx signature(s)")
        req_check_args = parser_check.add_argument_group("required arguments")
        req_check_args.add_argument("--sig",
                                    "-s",
                                    nargs="+",
                                    required=True,
                                    help="dynmx signature(s) to check")
        # Parameters for command 'convert'
        parser_convert = subparsers.add_parser("convert",
                                               help="Converts function logs to the dynmx generic function log format")
        req_convert_args = parser_convert.add_argument_group(
            "required arguments")
        req_convert_args.add_argument("--input",
                                      "-i",
                                      nargs="+",
                                      required=True,
                                      help="Input files to convert")
        parser_convert.add_argument("--output-dir",
                                    "-o",
                                    help="Output directory for the converted files")
        parser_convert.add_argument("--nocompress",
                                    help="Do not compress the converted function log",
                                    action="store_true")
        parser_convert.add_argument("--recursive",
                                    help="Search for input files recursively",
                                    action="store_true",
                                    default=False)
        # Parameters for command 'stats'
        parser_stats = subparsers.add_parser("stats",
                                               help="Statistics of function logs")
        req_stats_args = parser_stats.add_argument_group(
            "required arguments")
        req_stats_args.add_argument("--input",
                                    "-i",
                                    nargs="+",
                                    required=True,
                                    help="Input files to calculate statistics from")
        parser_stats.add_argument("--recursive",
                                  "-r",
                                  help="Search for input files recursively",
                                  action="store_true",
                                  default=False)
        # Parameters for command 'resources'
        parser_resources = subparsers.add_parser("resources",
                                                 help="Resource activity derived from function log")
        req_resources_args = parser_resources.add_argument_group(
            "required arguments")
        req_resources_args.add_argument("--input",
                                        "-i",
                                        nargs="+",
                                        required=True,
                                        help="Input files to derive resource activity from")
        parser_resources.add_argument("--recursive",
                                      "-r",
                                      help="Search for input files recursively",
                                      action="store_true",
                                      default=False)
        return parser

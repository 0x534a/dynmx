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
from typing import Optional, TYPE_CHECKING, List, Dict, Set, TextIO
from enum import Flag, auto
import json

if TYPE_CHECKING:
    from dynmx.core.function_log import FunctionLog
    from dynmx.detection.detection_result import DetectionResult
    from dynmx.core.statistics import Statistics


class OutputHelper:
    """
    Helper class for output
    """

    def __init__(self, show_log, output_format):
        self._show_log = show_log
        self._output_format = output_format

    def render_header(self, version: str) -> None:
        """
        Prints the header
        :param version: Version to show in the header
        """
        print('''

    |
  __|         _  _    _  _  _
 /  |  |   | / |/ |  / |/ |/ |  /\/
 \_/|_/ \_/|/  |  |_/  |  |  |_/ /\_/
          /|
          \|
            ''')
        print(" Ver. {}, by 0x534a".format(version))
        print("")
        print("")

        if self._show_log:
            print("[+] Log output")

    def render_detection_run_info(self, num_of_function_logs: int, num_of_signatures: int, resources_needed: bool,
                                  num_of_workers: int) -> None:
        """
        Renders the detection run information
        :param num_of_function_logs: Number of function logs
        :param num_of_signatures: Number of signatures
        :param resources_needed: Indicates whether resources are extracted from the function log
        :param num_of_workers: Number of workers
        """
        if self._show_log:
            return
        print("[+] Parsing {} function log(s)".format(num_of_function_logs))
        print("[+] Loaded {} dynmx signature(s)".format(num_of_signatures))
        if resources_needed:
            print("[+] Extracting resources from function log(s)")
        print("[+] Starting detection process with {} workers. This probably takes some time...".format(num_of_workers))

    def render_flog_info(self, number_of_function_logs: int, command: str) -> None:
        """
        Renders function log information
        :param number_of_function_logs: Number of function logs
        :param command: Command the function logs are processed with
        """
        if self._show_log:
            return
        print("[+] Parsing {} function log(s)".format(number_of_function_logs))
        print("[+] Processing function log(s) with the command '{}'...".format(command))

    def _render_result_str(self, command_output: str) -> str:
        """
        Renders the command output string
        :param command_output: Output of the command
        :return: Rendered result string
        """
        output = ""
        if self._show_log:
            output += "[+] End of log output\n"
        output += "\n[+] Result\n"
        output += command_output
        return output

    def render_resources_output_str(self, flogs: List[FunctionLog]) -> str:
        """
        Renders the resource output string
        :param flogs: List of function logs to extract resources information from
        :return: Rendered resources output string
        """
        output = ""
        categories = ["filesystem", "registry", "network"]
        for ix, flog in enumerate(flogs):
            output += "Function log: {} ({})\n".format(flog.name, flog.file_path)
            for p in flog.processes:
                output += "\tProcess: {} (PID: {})\n".format(p.name,p.os_id)
                for cat in categories:
                    resources = p.aam.get_resources_by_category(cat)
                    if resources:
                        output += "\t\t{}:\n".format(cat.capitalize())
                        for resource in resources:
                            if self._output_format == OutputType.DETAIL:
                                access_ops = []
                                for op in resource.access_operations:
                                    access_ops.append(op.name)
                                output += "\t\t\t{} ({})\n".format(resource.get_location(), ",".join(access_ops))
                            else:
                                output += "\t\t\t{}\n".format(resource.get_location())
        return self._render_result_str(output)

    def _group_detection_results_by_flog(self, detection_results: List[DetectionResult]) \
            -> Dict[str, List[DetectionResult]]:
        """
        Groups detection results by the function log
        :param detection_results: List of detection results
        :return: Dictionary containing the detection results grouped by the function log
        """
        detected_signatures_by_flog = {}
        for result in detection_results:
            if result and result.detected:
                if result.flog_name not in detected_signatures_by_flog.keys():
                    detected_signatures_by_flog[result.flog_path] = []
                detected_signatures_by_flog[result.flog_path].append(result)
        return detected_signatures_by_flog

    def _group_detected_signatures_by_flog(self, detection_results: List[DetectionResult]) -> Dict[str, Set]:
        """
        Groups the detected signatures by the function log
        :param detection_results: List of detection results
        :return: Dictionary of detected signatures grouped by the function log
        """
        detected_signatures = {}
        for result in detection_results:
            if result and result.detected:
                if result.flog_name not in detected_signatures.keys():
                    detected_signatures[result.flog_path] = set()
                detected_signatures[result.flog_path].add(result.signature_name)
        return detected_signatures

    def render_detection_output_str(self, detection_results: List[DetectionResult]) -> str:
        """
        Renders the detection output string
        :param detection_results: List of detection results
        :return: Rendered detection output string
        """
        output = ""
        if self._output_format == OutputType.DETAIL:
            output = self._render_detailed_detection_output_str(
                self._group_detection_results_by_flog(detection_results)
            )
        elif self._output_format == OutputType.OVERVIEW:
            detected_signatures = self._group_detected_signatures_by_flog(detection_results)
            for flog_path, detected_signatures in detected_signatures.items():
                for sig in detected_signatures:
                    output += "{}\t{}\n".format(sig, flog_path)
            return self._render_result_str(output)
        return self._render_result_str(output)

    @staticmethod
    def _render_detailed_detection_output_str(detection_results: Dict[str, List[DetectionResult]]) -> str:
        """
        Returns the detection results for 'detail' output format
        :param detection_results: Detection results
        :return: Detection results for 'detail' output format as string
        """
        output = ""
        for flog_path, results in detection_results.items():
            output += "Function log: {}\n".format(flog_path)
            for result in results:
                output += "\tSignature: {}\n".format(result.signature_name)
                for p in result.detected_processes:
                    output += "\t\tProcess: {} (PID: {})\n".format(
                        p.process_name,
                        p.process_os_id
                    )
                    output += "\t\tNumber of Findings: {}\n".format(len(p.findings))
                    for index, finding in enumerate(p.findings):
                        output += "\t\t\tFinding {}\n".format(index)
                        for api_call in finding.api_calls:
                            if api_call.flog_index:
                                output += "\t\t\t\t{} : API Call {} (Function log line {}, index {})\n".format(
                                    finding.detection_block_key,
                                    api_call.function_name,
                                    api_call.flog_index,
                                    api_call.index
                                )
                            else:
                                output += "\t\t\t\t{} : API Call {} (index {})\n".format(
                                    finding.detection_block_key, api_call.function_name, api_call.index)
                        for resource in finding.resources:
                            output += "\t\t\t\t{} : Resource {}\n".format(finding.detection_block_key, resource)
            output += "\n"
        return output

    def render_check_output_str(self, check_results: List[bool]) -> str:
        """
        Renders the check output
        :param check_results: Signature check results
        :return: Check output as string
        """
        output = ""
        for sig_path, check_result in check_results.items():
            if check_result:
                output += "[OK]]\t{}\n".format(sig_path)
            else:
                output += "[FAIL]\t{}\n".format(sig_path)
        return self._render_result_str(output)

    def render_stats_output_str(self, stats_objs: List[Statistics]) -> str:
        """
        Generates the statistic output
        :param stats_objs: Statistic objects containing statistics for function log
        :return: Statistic output as string
        """
        output = ""
        for ix, stats in enumerate(stats_objs):
            output += "Function log: {}\n".format(stats.flog.name)
            output += "\tNumber of Processes: {}\n".format(stats.num_of_processes)
            output += "\tNumber of API calls: {}\n".format(stats.num_of_api_calls)
            output += "\tNumber of unique API calls: {}\n".format(stats.num_of_unique_api_calls)
            output += "\tFlop API calls:\n"
            for sys_call_name, count in stats.flop_api_calls.items():
                output += "\t\t{}: {}\n".format(sys_call_name, count)
            output += "\tTop API calls:\n"
            for sys_call_name, count in stats.top_api_calls.items():
                output += "\t\t{}: {}\n".format(sys_call_name, count)
        return self._render_result_str(output)

    def render_error(self, message: str):
        """
        Renders an error message
        :param message: Error message
        """
        if not self._show_log:
            print("[-] {}".format(message))

    def render_converted_flog(self, flog_path: str, conversion_time: float, output_path: str) -> None:
        """
        Renders information of a converted function log
        :param flog_path: Function log path
        :param conversion_time: Run time of the conversion process
        :param output_path: Output path
        """
        if not self._show_log:
            print("[+] Converted function log '{}' in {:.4f}s to output directory '{}'".format(
                flog_path, conversion_time, output_path))

    @staticmethod
    def write_runtime_result_file(runtime_file: TextIO, result_objs: List[DetectionResult]) -> None:
        """
        Writes the CSV-formatted runtime results file
        :param runtime_file: Runtime result file
        :param result_objs: Detection results
        """
        csv_separator = "|"
        attributes = ["flog_name", "flog_path", "signature_name", "signature_path", "detected", "runtime_flog_parsing",
                      "runtime_resource_extraction", "runtime_signature_detection"]
        header = csv_separator.join(attributes)
        runtime_file.write("{}\n".format(header))
        for result_obj in result_objs:
            attribute_values = []
            for attribute in attributes:
                if hasattr(result_obj, attribute):
                    val = getattr(result_obj, attribute)
                    if not val:
                        val = ""
                    if not isinstance(val, str):
                        val = str(val)
                    attribute_values.append(val)
            csv_line = csv_separator.join(attribute_values)
            runtime_file.write("{}\n".format(csv_line))

    @staticmethod
    def write_detection_json_result_file(json_file: TextIO, result_objs: List[DetectionResult]) -> None:
        """
        Writes the detection results as JSON file
        :param json_file: JSON result file
        :param result_objs: Detection results
        """
        # Build dicts and write to result file with json
        detection_results_dict = []
        for result in result_objs:
            if result:
                detection_results_dict.append(result.get_as_dict())
        json_file.write(json.dumps(detection_results_dict, indent=2))


class OutputType(Flag):
    OVERVIEW = auto()
    DETAIL = auto()

    @staticmethod
    def get_entry_by_str(str_entry: str) -> Optional[OutputType]:
        if str_entry.lower() == "overview":
            return OutputType.OVERVIEW
        elif str_entry.lower() == "detail":
            return OutputType.DETAIL
        else:
            return None


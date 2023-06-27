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
from lxml import etree as ET
import os
from datetime import datetime

from dynmx.flog_parsers.parser import Parser
from dynmx.core.process import Process
from dynmx.core.api_call import APICall, Argument
from dynmx.core.function_log import FunctionLog, FunctionLogType
from dynmx.core.pointer import Pointer


class VmrayXmlFlogParser(Parser):
    """
    Parser for XML based VMray function logs
    """

    def __init__(self):
        """
        Constructor
        """
        Parser.__init__(self)

    def parse(self, file_path: str) -> FunctionLog:
        """
        Parses the VMray XML function log
        :param file_path: Path to the text-based VMray XML function log
        :return: FunctionLog object containing the parsed VMray XML function log
        """
        function_log = FunctionLog(FunctionLogType.VMRAY)
        xml_root = ET.parse(file_path).getroot()
        function_log.name = ntpath.basename(file_path)
        function_log.file_path = os.path.abspath(file_path)
        function_log.sandbox = "VMRay Analyzer"
        # Parse header information
        self._parse_header_info(function_log, xml_root)
        # Parse process information and corresponding API calls
        for proc in xml_root.findall('monitor_process'):
            # Parse process information
            p = self._parse_process_info(proc)
            p.flog_path = function_log.file_path
            # Find and parse corresponding API calls
            vmray_proc_id = proc.attrib["process_id"]
            self._parse_all_api_calls(xml_root, vmray_proc_id, p)
            # Append process to function log
            function_log.add_process(p)
        xml_root.clear()
        xml_root = None
        del xml_root
        return function_log

    @staticmethod
    def probe(file_path: str) -> bool:
        """
        Probes whether the file is a VMray XML function log file
        :param file_path: Path to the file to probe
        :return: Indicates whether the file is a VMray XML function log file
        """
        with open(file_path, "r") as f:
            first_lines = [next(f) for x in range(2)]
        result = first_lines[0].strip() == '<?xml version="1.0" encoding="UTF-8"?>' and \
                 first_lines[1].strip().startswith('<analysis log_version=')
        return result

    def _parse_process_info(self, process_node) -> Process:
        """
        Parses the process information from the XML based VMray function log
        :param process_node: Process node (<monitor_process> tag)
        :return: Process object containing the parsed process information
        """
        # Define mapping of fields
        mapping = {
            "os_id": ("os_pid", "int"),
            "name": ("image_name", "string"),
            "file_path": ("filename", "string"),
            "cmd_line": ("cmd_line", "string"),
            "owner": ("os_username", "string"),
        }
        p = Process()
        for k, v in mapping.items():
            if v[1] == "int":
                setattr(p, k, int(process_node.attrib[v[0]], 0))
            else:
                setattr(p, k, self._parse_arg_value(process_node.attrib[v[0]]))
        return p

    def _parse_header_info(self, flog: FunctionLog, analysis_node) -> None:
        """
        Parses the process information from the XML based VMray function log
        :param flog: FunctionLog object
        :param analysis_node: XML node containing the function log metadata
        """
        # Define mapping of fields
        mapping = {
            "version": ("log_version", "string"),
            "sandbox_version": ("analyzer_version", "string"),
            "analysis_ts": ("analysis_date", "date"),
        }
        for k, v in mapping.items():
            if v[1] == "date":
                ts = self._parse_timestamp(analysis_node.attrib[v[0]])
                if ts:
                    setattr(flog, k, ts)
            else:
                setattr(flog, k, self._parse_arg_value(analysis_node.attrib[v[0]]))

    def _parse_all_api_calls(self, xml_root, vmray_proc_id: int, process: Process) -> None:
        """
        Finds and parses API calls belonging to the VMray process id (<fncall> tag)
        :param xml_root: Root node of the XML tree
        :param vmray_proc_id: Internal VMray process ID
        :return: List of APICall objects belonging to the process identified by the VMray process ID
        """
        for ix, api_call_node in enumerate(xml_root.findall("fncall[@process_id='{}']".format(vmray_proc_id))):
            api_call = self._parse_api_call(api_call_node, ix)
            process.add_api_call(api_call)

    def _parse_api_call(self, api_call_node, api_call_index: int) -> APICall:
        """
        Parses an API call node (<fncall> XML tag)
        :param api_call_node: XML node with <fncall> tag containing API call information
        :return: APICall object containing the parsed API call information
        """
        api_call = APICall()
        api_call.function_name = api_call_node.attrib["name"]
        api_call.index = api_call_index
        api_call.time = int(api_call_node.attrib["ts"]) / 1000
        api_call.flog_index = api_call_node.sourceline
        # Return Value
        return_val_node = api_call_node.find("./out/param[@name='ret_val']")
        if return_val_node is not None:
            if self._node_has_children(return_val_node) and return_val_node.attrib["type"] == "ptr":
                # Return value is a pointer
                api_call.return_value = self._parse_pointer_node(return_val_node)
            else:
                if self._node_has_attribute(return_val_node, "value"):
                    ret_val_str = return_val_node.attrib["value"]
                    api_call.return_value = self._parse_arg_value(ret_val_str)
                else:
                    # API call returns void
                    api_call.return_value = None
        else:
            api_call.return_value = None
        # Arguments
        arg_nodes_in = api_call_node.findall("./in/param")
        arg_nodes_out = api_call_node.xpath('./out/param[not(@name="ret_val")]')
        if len(arg_nodes_in) and len(arg_nodes_out):
            api_call.has_in_out_args = True
        api_call.arguments = self._parse_argument_nodes(arg_nodes_in, arg_nodes_out)
        return api_call

    @staticmethod
    def _node_has_children(node) -> bool:
        """
        Indicates whether the XML node has children
        :param node: Node to check for children
        :return: Bool that indicates whether the XML node has children
        """
        return len(node.getchildren()) > 0

    @staticmethod
    def _node_has_attribute(node, attribute: str) -> bool:
        """
        Indicates whether the XML node has the given attribute
        :param node: Node to check for presence of attribute
        :param attribute: Name of attribute to check presence for
        :return: Bool that indicates whether the XML node has the attribute
        """
        return attribute in node.attrib.keys()

    def _parse_argument_nodes(self, in_nodes: List[Any], out_nodes: List[Any]) -> List[Argument]:
        """
        Parses the XML argument nodes (<in> and <out> XML tag children)
        :param in_nodes: List of children nodes of the <in> XML tag
        :param out_nodes: List of children nodes of the <out> XML tag
        :return: List of Arguments objects containing the parsed XML argument nodes
        """
        arguments = list()
        if len(in_nodes):
            # In parameters available
            for in_node in in_nodes:
                arg = self._parse_argument_node(in_node, is_in=True)
                arguments.append(arg)
        if len(out_nodes):
            # Out parameters available
            for out_node in out_nodes:
                arg = self._parse_argument_node(out_node, is_out=True)
                arguments.append(arg)
        return arguments

    def _parse_argument_node(self, node, is_in: bool = False, is_out: bool = False) -> Argument:
        """
        Parses the XML argument node (XML tag <param>)
        :param node: Argument node to parse
        :param is_in: Indicates whether the node is an in parameter
        :param is_out: Indicates whether the node is an in parameter
        :return: Argument object containing the parsed parameter information
        """
        arg_obj = Argument()
        arg_obj.is_in = is_in
        arg_obj.is_out = is_out
        if self._node_has_attribute(node, "name"):
            arg_obj.name = node.attrib["name"]
        if self._node_has_children(node):
            # Argument is a pointer
            arg_obj.value = self._parse_pointer_node(node)
        else:
            # Argument has simple value
            if self._node_has_attribute(node, "value"):
                arg_obj.value = self._parse_arg_value(node.attrib["value"])
        return arg_obj

    def _parse_pointer_node(self, node) -> Pointer:
        """
        Parses an XML pointer node (XML tags <deref>, <item type=array>, <item type=container>)
        :param node: XML pointer node
        :return: Pointer object with the parsed information
        """
        p = Pointer()
        if self._node_has_attribute(node, "value"):
            p.address = self._parse_arg_value(node.attrib["value"])
        if node.attrib["type"] == "ptr":
            if self._node_has_children(node):
                child = node.getchildren()[0]
                if child.tag == "deref":
                    # String value
                    if child.attrib["type"] == "str":
                        if self._node_has_attribute(child, "value"):
                            return self._parse_arg_value(child.attrib["value"])
                        else:
                            return None
                    # No named arguments, just value
                    elif self._node_has_attribute(child, "value"):
                        p.arguments = self._parse_arg_value(child.attrib["value"])
                    # Named arguments
                    elif child.attrib["type"] == "container":
                        p.arguments = self._parse_container_node(child)
                    # Array
                    elif child.attrib["type"] == "array":
                        p.arguments = self._parse_array_node(child)
        elif node.attrib["type"] == "array":
            p.arguments = self._parse_array_node(node)
        elif node.attrib["type"] == "container":
            p.arguments = self._parse_container_node(node)
        return p

    def _parse_container_node(self, node) -> List[Argument]:
        """
        Parses the arguments of an XML container node (<item type=container>)
        :param node: XML container node
        :return: List of Arguments objects
        """
        container_args = list()
        for member in node.getchildren():
            container_args.append(self._parse_argument_node(member))
        return container_args

    def _parse_array_node(self, node) -> List[Argument]:
        """
        Parses the arguments of an XML array node (<item type=array>)
        :param node: XML array node
        :return: List of Argument objects
        """
        args = list()
        for ix, item in enumerate(node.getchildren()):
            if item.attrib["type"] == "container":
                args += self._parse_container_node(item)
            else:
                i = self._parse_item_node(item)
                args.append(i)
        return args

    def _parse_item_node(self, node) -> Optional[Pointer | Argument]:
        if self._node_has_attribute(node, "type"):
            if node.attrib["type"] == "ptr":
                return self._parse_pointer_node(node)
            else:
                if self._node_has_attribute(node, "value"):
                    return self._parse_arg_value(node.attrib["value"])
        return None

    @staticmethod
    def _parse_arg_value(value: str) -> Any:
        """
        Parses the argument value
        :param value: Value to parse
        :return: Parsed value
        """
        value = value.lower()
        # Hexadecimal int
        if value.startswith("0x"):
            try:
                int_val = int(value, 0)
                return int_val
            except ValueError:
                pass
        # Int
        try:
            int_val = int(value)
            return int_val
        except ValueError:
            pass
        # String
        value = value.strip(" \"")
        value = value.replace("\\\\", "\\")
        return value

    @staticmethod
    def _parse_timestamp(str_val: str) -> Optional[datetime]:
        pattern = ["%d.%m.%Y %H:%M:%S.%f", "%d.%m.%Y %H:%M"]
        ts = None
        for p in pattern:
            try:
                ts = datetime.strptime(str_val, p)
                if ts:
                    break
            except Exception:
                continue
        return ts

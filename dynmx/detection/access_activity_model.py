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
from typing import Optional, List, Dict, Any, TYPE_CHECKING, AnyStr, Set
from urllib.parse import urlunparse
import shlex
import yaml
import ntpath
import os

from dynmx.core.resource import AccessType
from dynmx.core.file_resource import FileResource
from dynmx.core.registry_resource import RegistryResource
from dynmx.core.network_resource import NetworkResource, NetworkType
from dynmx.helpers.regex_helper import RegexHelper
from dynmx.core.pointer import Pointer
from dynmx.helpers.logging_helper import LoggingHelper
from dynmx.core.function_log import FunctionLogType

if TYPE_CHECKING:
    from dynmx.core.process import Process
    from dynmx.core.resource import Resource
    from dynmx.core.api_call import APICall


# Module level constants
FS = "filesystem"
REG = "registry"
NW = "network"
CLOSE = "close"
API_CALL_NAME = "api_call_name"
HANDLE_ID = "handle_id"
HANDLE_PARAM = "handle_param"
HANDLE_IS_OUT = "handle_is_out"
HANDLE_RETURN_IN = "handle_returned_in"
PATH_PARAM = "path_param"
PATH_PARAM_IS_OUT = "path_param_is_out"
CMD_LINE_PARAM = "cmd_line_arg_name"
VALUE_PARAM = "value_param"
FILE_NAME_PARAM = "file_name_param"
OPERATION = "operation"
RETURN = "return"
COMMON_REG_HANDLES = {
    0x80000000: "HKEY_CLASSES_ROOT",
    0xffffffff80000000: "HKEY_CLASSES_ROOT",
    0x80000001: "HKEY_CURRENT_USER",
    0xffffffff80000001: "HKEY_CURRENT_USER",
    0x80000002: "HKEY_LOCAL_MACHINE",
    0xffffffff80000002: "HKEY_LOCAL_MACHINE",
    0x80000003: "HKEY_USERS",
    0xffffffff80000003: "HKEY_USERS",
    0x80000004: "HKEY_CURRENT_CONFIG",
    0xffffffff80000004: "HKEY_CURRENT_CONFIG",
    0x80000005: "HKEY_DYN_DATA",
    0xffffffff80000005: "HKEY_DYN_DATA",
}
NW_TYPE = "network_type"
DNS_NAME_PARAM = "dns_name_param"
DNS_IP_PARAM = "dns_ip_param"
HOST_PARAM = "host_param"
PORT_PARAM = "port_param"
URL_PARAM = "url_param"
REQUEST_PARAM = "request_param"


class AccessActivityModel:
    """
    Representation of an access activity model
    """

    def __init__(self, flog_type: FunctionLogType):
        """
        Constructor
        """
        self.resources = list()
        self._logger = LoggingHelper.get_logger(__name__)
        # AAM aam_config_path file
        script_path = os.path.dirname(os.path.realpath(__file__))
        if flog_type == FunctionLogType.VMRAY:
            aam_conf_path = os.path.join(script_path, "..", "config", "aam_vmray.yaml")
        elif flog_type == FunctionLogType.CUCKOO or flog_type == FunctionLogType.CAPE:
            aam_conf_path = os.path.join(script_path, "..", "config", "aam_cuckoo.yaml")
        else:
            raise NotImplementedError()
        self._parse_config(aam_conf_path)
        self._handle_table = HandleTable()
        self._dns_table = {}

    def build(self, process: Process) -> None:
        """
        Builds the Access Activity Model
        :param process: Process object to build the model for
        """
        flog_path = process.flog_path
        # Update logger with flog path
        self._logger = LoggingHelper.get_logger(__name__, flog_path=flog_path)
        self._logger.info("Extracting file resources from process {} (PID {})".format(process.name, process.os_id))
        before = len(self.resources)
        self._extract_file_resources(process)
        after = len(self.resources)
        new = after - before
        self._logger.info("Found {} file resources in process {} (PID {})".format(new, process.name, process.os_id))
        self._logger.info("Extracting Registry resources from process {} (PID {})".format(process.name, process.os_id))
        before = len(self.resources)
        self._extract_registry_resources(process)
        after = len(self.resources)
        new = after - before
        self._logger.info("Found {} Registry resources in process {} (PID {})".format(new, process.name, process.os_id))
        self._logger.info("Extracting network resources from process {} (PID {})".format(process.name, process.os_id))
        before = len(self.resources)
        self._extract_network_resources(process)
        after = len(self.resources)
        new = after - before
        self._logger.info("Found {} network resources in process {} (PID {})".format(new, process.name, process.os_id))

    def get_resources_by_category(self, category: str) -> List[Resource]:
        """
        Returns resources of the given category
        :param category: Resource category
        :return: List of resources of the given category
        """
        candidates = list()
        for resource in self.resources:
            if category.lower() == "filesystem":
                if isinstance(resource, FileResource):
                    candidates.append(resource)
            elif category.lower() == "registry":
                if isinstance(resource, RegistryResource):
                    candidates.append(resource)
            elif category.lower() == "network":
                if isinstance(resource, NetworkResource):
                    candidates.append(resource)
        return candidates

    # <editor-fold desc="File Resource">
    def _extract_file_resources(self, process: Process) -> None:
        """
        Extracts file resources from the process
        :param process: Process to extract file resources from
        """
        # Reduce API calls based on relevant filesystem API function names
        fs_api_calls = self._get_relevant_api_calls(FS)
        reduced_api_sequence = self._reduce_api_calls(process, fs_api_calls)
        # Extract file resource for each relevant API call
        for api_call in reduced_api_sequence:
            try:
                self._extract_file_resource(api_call)
            except Exception as ex:
                self._logger.error(
                    "Error while extracting file resource from API call {} (flog line {}). Error message: '{}'.".format(
                        api_call.function_name, api_call.flog_index, ex))

    def _extract_file_resource(self, api_call: APICall) -> None:
        """
        Extracts a file resource from an API call. If the API call references an existing file resource, the resource
        is updated.
        :param api_call: API call to extract the file resource from
        """
        api_call_config_indices = self._get_api_call_configs(api_call.function_name, FS)
        for ix in api_call_config_indices:
            api_call_config = self.config[FS][ix]
            update = False
            new = False
            altered_path = None
            # Check if API call addresses handle
            if HANDLE_PARAM in api_call_config:
                f_resource = self._find_resource_by_handle(api_call_config, api_call)
                if f_resource:
                    if FILE_NAME_PARAM in api_call_config:
                        # Handle altered filename
                        path = ntpath.dirname(f_resource.path)
                        new_fname = api_call.get_argument_values(api_call_config[FILE_NAME_PARAM])[0]
                        altered_path = ntpath.join(path, new_fname)
                        new = True
                    else:
                        update = True
                # If no resource was found return
                else:
                    return
            else:
                f_resource = self._find_file_resource_by_path(api_call_config, api_call)
                if f_resource:
                    update = True
                else:
                    new = True
            if new:
                f_obj = self._build_file_resource_obj(api_call_config, api_call, altered_path=altered_path)
                if f_obj:
                    self.resources.append(f_obj)
                    self._logger.debug("Found new resource '{}' (access: {}, API call: {})".format(
                        f_obj.path, next(iter(f_obj.access_operations)).name, api_call))
            if update:
                self._update_resource_obj(f_resource, api_call_config)
                self._update_handles(api_call_config, api_call, f_resource.id)

    def _find_file_resource_by_path(self, api_call_config: Dict[str, Any], api_call: APICall) \
            -> Optional[List[Resource]]:
        """
        Finds a file resource by the path referenced in the API call
        :param api_call_config: Configuration of the API call extracted from the AAM config file
        :param api_call: API call that references a path which is used to find the resource
        :return: File resource identified by the path
        """
        if PATH_PARAM in api_call_config.keys():
            is_out = None
            if PATH_PARAM_IS_OUT in api_call_config.keys():
                is_out = api_call_config[PATH_PARAM_IS_OUT]
            path = self._get_path_from_api_call(api_call, api_call_config[PATH_PARAM], is_out)
            resource = self._get_resource_by_path(path)
            if resource:
                return resource
        if CMD_LINE_PARAM in api_call_config.keys():
            path = self._get_path_from_api_call_cmd_line(api_call, api_call_config[CMD_LINE_PARAM])
            resource = self._get_resource_by_path(path)
            if resource:
                return resource
        return None

    def _build_file_resource_obj(self, api_call_config: Dict[str, Any], api_call: APICall,
                                 altered_path: Optional[str] = None) -> Optional[FileResource]:
        """
        Builds the file resource object based on the identified API call which references a file resource
        :param api_call_config: Configuration of the API call extracted from the AAM config file
        :param api_call: API call that references a file resource
        :param altered_path: Possibly altered path of the accessed file resource
        :return: FileResource object built based on the API call
        """
        f_obj = FileResource()
        self._update_handles(api_call_config, api_call, f_obj.id)
        if altered_path:
            f_obj.path = altered_path
        else:
            if PATH_PARAM in api_call_config.keys():
                is_out = None
                if PATH_PARAM_IS_OUT in api_call_config.keys():
                    is_out = api_call_config[PATH_PARAM_IS_OUT]
                path = self._get_path_from_api_call(api_call, api_call_config[PATH_PARAM], is_out)
                if path:
                    f_obj.path = path
                else:
                    return None
        if OPERATION in api_call_config.keys():
            new_access = self._get_access_type(api_call_config[OPERATION])
            f_obj.access_operations.add(new_access)
        return f_obj

    @staticmethod
    def _get_path_from_api_call_cmd_line(api_call: APICall, cmd_line_arg_name: str) -> Optional[str]:
        """
        Returns a path from a command line that was called by the API call
        :param api_call: API call that calls a command line
        :param cmd_line_arg_name: Name of the command line argument
        :return: Path extracted from the command line
        """
        vals = api_call.get_argument_values(cmd_line_arg_name)
        cmd_line = None
        if vals:
            if len(vals) == 1:
                cmd_line = vals[0]
            else:
                cmd_line = vals[-1]
        if not isinstance(cmd_line, str):
            return None
        cmd_line_quoted = shlex.quote(cmd_line)
        cmd_parts = shlex.split(cmd_line_quoted, posix=False)
        if cmd_parts:
            path = cmd_parts[0]
            if ntpath.isabs(path):
                return path
        return None

    # </editor-fold>

    # <editor-fold desc="Registry Resource">
    def _extract_registry_resources(self, process: Process) -> None:
        """
        Extracts Registry resources from the given process
        :param process: Process object to extract Registry resources from
        """
        # Reduce API calls based on relevant filesystem API function names
        reg_api_calls = self._get_relevant_api_calls(REG)
        reduced_api_sequence = self._reduce_api_calls(process, reg_api_calls)
        if reduced_api_sequence:
            # Prepare handle table with standard Registry Hives
            self._prepare_common_registry_handles()
            # Extract Registry resource for each relevant API call
            for api_call in reduced_api_sequence:
                try:
                    self._extract_registry_resource(api_call)
                except Exception as ex:
                    self._logger.error(
                        "Error while extracting Registry resource from API call {} (flog line {}). Error message: '{}'.".format(
                            api_call.function_name, api_call.flog_index, ex))
            self._remove_common_registry_handles()

    def _prepare_common_registry_handles(self) -> None:
        """
        Prepares common Registry handles like 0x80000000 (HKEY_CLASSES_ROOT) by adding them to the handle table
        """
        for handle_id, hive in COMMON_REG_HANDLES.items():
            reg_resource = RegistryResource(path=hive)
            self._handle_table.open_handle(handle_id, reg_resource.id)
            self.resources.append(reg_resource)

    def _remove_common_registry_handles(self) -> None:
        """
        Removes common Registry handles from the handle table
        """
        for handle_id in COMMON_REG_HANDLES.keys():
            resource_id = self._handle_table.get_resource_id_by_handle(handle_id)
            if resource_id:
                resource = self._get_resource_by_id(resource_id)
                if not resource.access_operations:
                    self._remove_resource_by_id(resource_id)

    def _extract_registry_resource(self, api_call: APICall) -> None:
        """
        Extracts a Registry resource from the API call. If the API call references an existing Registry resource, the
        resource is updated.
        :param api_call: API call accessing a Registry resource
        """
        api_call_config_indices = self._get_api_call_configs(api_call.function_name, REG)
        for ix in api_call_config_indices:
            api_call_config = self.config[REG][ix]
            update = False
            new = False
            # Check if API call addresses handle
            if HANDLE_PARAM in api_call_config or HANDLE_ID in api_call_config:
                reg_resource = self._find_resource_by_handle(api_call_config, api_call)
                if PATH_PARAM in api_call_config:
                    new_path = self._get_registry_path(api_call_config, api_call, reg_resource)
                    if new_path is not None:
                        res = self._get_resource_by_path(new_path)
                        if res:
                            reg_resource = res
                            update = True
                        else:
                            new = True
                    else:
                        if reg_resource:
                            update = True
                else:
                    update = True
            if new:
                r_obj = self._build_registry_resource_obj(api_call_config, api_call, new_path)
                if r_obj:
                    self.resources.append(r_obj)
                    self._logger.debug("Found new resource '{}' (access: {}, API call: {})".format(r_obj.path, next(iter(r_obj.access_operations)).name, api_call))
            if update and reg_resource:
                self._update_resource_obj(reg_resource, api_call_config)
                self._update_handles(api_call_config, api_call, reg_resource.id)

    @staticmethod
    def _get_registry_path(api_call_config: Dict[str, Any], api_call: APICall, base_resource: RegistryResource) \
            -> Optional[str]:
        """
        Returns the full Registry path based on an API call accessing a certain Registry key or value and a base
        resource
        :param api_call_config: Configuration of the API call extracted from the AAM config file
        :param api_call: API call that references a Registry resource
        :param base_resource: Base resource containing that is referenced by the API call which contains the base
        Registry path
        :return: Full Registry path referenced by the API call
        """
        path = None
        new_path = None
        if base_resource:
            base_path = base_resource.path
        else:
            base_path = ""
        is_out = None
        if PATH_PARAM_IS_OUT in api_call_config.keys():
            is_out = api_call_config[PATH_PARAM_IS_OUT]
        vals = api_call.get_argument_values(api_call_config[PATH_PARAM], is_out=is_out)
        if vals:
            path = vals[0]
        if not isinstance(path, str):
            return None
        if path:
            new_path = ntpath.join(base_path, path)
            if VALUE_PARAM in api_call_config.keys():
                vals = api_call.get_argument_values(api_call_config[VALUE_PARAM])
                if vals:
                    reg_value = vals[0]
                if reg_value:
                    new_path = ntpath.join(new_path, reg_value)
        else:
            if VALUE_PARAM in api_call_config.keys():
                vals = api_call.get_argument_values(api_call_config[VALUE_PARAM])
                if vals:
                    reg_value = vals[0]
                if reg_value:
                    new_path = ntpath.join(base_path, reg_value)
            elif "value" in api_call.function_name.lower():
                new_path = ntpath.join(base_path, "(Default)")
            else:
                new_path = None
        return new_path

    def _build_registry_resource_obj(self, api_call_config: Dict[str, Any], api_call: APICall, reg_path: str) \
            -> RegistryResource:
        """
        Builds a RegistryResource object based on the API call referencing a Registry resource
        :param api_call_config: Configuration of the API call extracted from the AAM config file
        :param api_call: API call that references a Registry resource
        :param reg_path: Full registry path accessed by the API call
        :return: RegistryResource object built based on the API call
        """
        r_obj = RegistryResource()
        self._update_handles(api_call_config, api_call, r_obj.id)
        r_obj.path = reg_path
        if OPERATION in api_call_config.keys():
            new_access = self._get_access_type(api_call_config[OPERATION])
            r_obj.access_operations.add(new_access)
        return r_obj
    # </editor-fold>

    # <editor-fold desc="Network Resource">
    def _extract_network_resources(self, process: Process) -> None:
        """
        Extracts network resources from the given process
        :param process: Process to extract network resources from
        """
        # Reduce API calls based on relevant filesystem API function names
        network_api_calls = self._get_relevant_api_calls(NW)
        reduced_api_sequence = self._reduce_api_calls(process, network_api_calls)
        if reduced_api_sequence:
            # Extract network resource for each relevant API call
            for api_call in reduced_api_sequence:
                try:
                    self._extract_network_resource(api_call)
                except Exception as ex:
                    self._logger.error(
                        "Error while extracting network resource from API call {} (flog line {}). Error message: '{}'.".format(
                            api_call.function_name, api_call.flog_index, ex))

    def _extract_network_resource(self, api_call: APICall) -> None:
        """
        Extracts a network resource from the API call. If the API call references an existing network resource, the
        resource is updated.
        :param api_call: API call that references a network resource
        """
        api_call_config_indices = self._get_api_call_configs(api_call.function_name, NW)
        for ix in api_call_config_indices:
            api_call_config = self.config[NW][ix]
            update = False
            new = False
            network_type = None
            new_url = None
            # Set type
            nw_type = self._get_network_type(api_call_config)
            if nw_type and nw_type == NetworkType.DNS:
                self._add_dns_entry(api_call_config, api_call)
            else:
                # Check if API call addresses handle
                if HANDLE_PARAM in api_call_config:
                    nw_resource = self._find_resource_by_handle(api_call_config, api_call)
                    if nw_resource:
                        if REQUEST_PARAM in api_call_config:
                            new_url = self._get_url(nw_resource, api_call, api_call_config)
                            nw_resource = self._get_network_resource_by_url(new_url)
                            if nw_resource:
                                update = True
                            else:
                                new = True
                        else:
                            update = True
                    else:
                        new = True
                else:
                    if URL_PARAM in api_call_config:
                        url = self._get_api_call_arg_value(api_call, api_call_config[URL_PARAM])
                        nw_resource = self._get_network_resource_by_url(url)
                        if not nw_resource:
                            new = True
                        else:
                            update = True
                    elif HOST_PARAM in api_call_config:
                        host = self._get_api_call_arg_value(api_call, api_call_config[HOST_PARAM])
                        dns_name = self._get_domain_for_ip(host)
                        if dns_name:
                            host = dns_name
                        if PORT_PARAM in api_call_config:
                            port = self._get_api_call_arg_value(api_call, api_call_config[PORT_PARAM])
                            nw_resource = self._get_network_resource_by_host(host, port=port)
                        else:
                            nw_resource = self._get_network_resource_by_host(host)
                        if not nw_resource:
                            new = True
                        else:
                            update = True
                if new:
                    if new_url:
                        n_obj = self._build_network_resource_obj(api_call_config, api_call, nw_type, url=new_url)
                    else:
                        n_obj = self._build_network_resource_obj(api_call_config, api_call, nw_type)
                    if n_obj:
                        self.resources.append(n_obj)
                        self._logger.debug("Found new resource '{}' (access: {}, API call: {})".format(n_obj, next(iter(n_obj.access_operations)).name, api_call))
                if update:
                    self._update_nw_resource_obj(nw_resource, api_call_config, api_call)
                    self._update_handles(api_call_config, api_call, nw_resource.id)

    def _add_dns_entry(self, api_call_config: Dict[str, Any], api_call: APICall) -> None:
        """
        Adds a DNS entry to the internal DNS table
        :param api_call_config: Configuration of the API call extracted from the AAM config file
        :param api_call: API call that does DNS resolution
        """
        ip_address_list = []
        if DNS_NAME_PARAM not in api_call_config or DNS_IP_PARAM not in api_call_config:
            return
        dns_name = self._get_api_call_arg_value(api_call, api_call_config[DNS_NAME_PARAM])
        ips = self._get_api_call_arg_value(api_call, api_call_config[DNS_IP_PARAM])
        if ips:
            if not isinstance(ips, list):
                ips = [ips]
            ip_address_list += ips
        if not dns_name or not ip_address_list:
            return
        self._update_dns_table(dns_name, ip_address_list)

    def _update_dns_table(self, dns_name: str, ip_address_list: List[Any]) -> None:
        """
        Updates an entry in the internal DNS table
        :param dns_name: DNS name
        :param ip_address_list: List of IP addresses that the DNS name resolves to
        """
        entry_exists = False
        for ip in ip_address_list:
            existent_dns_name = self._get_domain_for_ip(ip)
            if existent_dns_name:
                entry_exists = True
                self._dns_table[dns_name] = self._dns_table.pop(existent_dns_name)
        if not entry_exists:
            self._dns_table[dns_name] = ip_address_list

    def _get_domain_for_ip(self, ip_address: Any) -> Optional[str]:
        """
        Does a forward DNS resolution based on the internal DNS table
        :param ip_address: IP address to resolve
        :return: Domain name the IP address resolves to
        """
        for domain, ip_list in self._dns_table.items():
            if str(ip_address) in ip_list:
                return domain
        return None

    @staticmethod
    def _get_network_type(api_call_config: Dict[str, Any]) -> NetworkType:
        """
        Returns the network type based on the type defined in the AAM config
        :param api_call_config: Configuration of the API call extracted from the AAM config file
        """
        nw_type = None
        if NW_TYPE in api_call_config:
            nw_str_type = api_call_config[NW_TYPE]
            if nw_str_type.lower() == "connect":
                nw_type = NetworkType.CONNECT
            elif nw_str_type.lower() == "listen":
                nw_type = NetworkType.LISTEN
            elif nw_str_type.lower() == "dns":
                nw_type = NetworkType.DNS
            else:
                nw_type = NetworkType.UNDEFINED
        return nw_type

    def _get_network_resource_by_host(self, host: str, port: Optional[int] = None) -> NetworkResource:
        """
        Returns a network resource that references the given host
        :param host: Host to find the resource for
        :param port: Port number to find the resource for
        :return: NetworkResource object that references the host
        """
        for resource in self.resources:
            if isinstance(resource, NetworkResource):
                if resource.is_host(host, port=port):
                    return resource

    def _get_network_resource_by_url(self, url: str) -> NetworkResource:
        """
        Returns a network resource that references the given URL
        :param url: URL to find the resource for
        :return: NetworkResource object referencing the given URL
        """
        for resource in self.resources:
            if isinstance(resource, NetworkResource):
                if resource.url == url:
                    return resource

    def _build_network_resource_obj(self, api_call_config: Dict[str, Any], api_call: APICall, network_type: NetworkType,
                                    url: Optional[str] = None) -> NetworkResource:
        """
        Builds a network resource object based on the API call
        :param api_call_config: Configuration of the API call extracted from the AAM config file
        :param api_call: API call that references a network resource
        :param network_type: NetworkType referenced by the API call
        :param url: URL that is accessed by the API call
        :return: NetworkResource object built based on the API call
        """
        n_obj = NetworkResource()
        self._update_handles(api_call_config, api_call, n_obj.id)
        n_obj.network_type = network_type
        if url:
            n_obj.set_url(url)
        if URL_PARAM in api_call_config:
            url = self._get_api_call_arg_value(api_call, api_call_config[URL_PARAM])
            if url:
                n_obj.set_url(url)
        if HOST_PARAM in api_call_config:
            host = self._get_api_call_arg_value(api_call, api_call_config[HOST_PARAM])
            if host:
                n_obj.set_host(host)
        if PORT_PARAM in api_call_config:
            port = self._get_api_call_arg_value(api_call, api_call_config[PORT_PARAM])
            if port:
                n_obj.port = port
        if OPERATION in api_call_config.keys():
            new_access = self._get_access_type(api_call_config[OPERATION])
            n_obj.access_operations.add(new_access)
        if n_obj.has_ip():
            if not n_obj.dns_name:
                n_obj.dns_name = self._get_domain_for_ip(str(n_obj.ip_address))
        return n_obj

    def _update_nw_resource_obj(self, resource: NetworkResource, api_call_config: Dict[str, Any], api_call: APICall) \
            -> None:
        """
        Updates an existing network resource object
        :param resource: Network resource to update
        :param api_call_config: Configuration of the API call extracted from the AAM config file
        :param api_call: API call that references a network resource
        """
        if REQUEST_PARAM in api_call_config:
            request = self._get_api_call_arg_value(api_call, api_call_config[REQUEST_PARAM])
            netloc = resource.get_host()
            if resource.port:
                if resource.port == 443:
                    scheme = "https"
                else:
                    scheme = "http"
            else:
                scheme = "http"
            if not request:
                request = ""
            if not isinstance(request, str):
                request = str(request)
            url = urlunparse((scheme, netloc, request, "", "", None))
            resource.set_url(url)
        self._update_resource_obj(resource, api_call_config)

    def _get_url(self, resource: NetworkResource, api_call: APICall, api_call_config: Dict[str, Any]) -> AnyStr:
        """
        Returns the full URL accessed by an API call
        :param resource: Basis network resource
        :param api_call_config: Configuration of the API call extracted from the AAM config file
        :param api_call: API call that references a network resource
        """
        if REQUEST_PARAM in api_call_config:
            request = self._get_api_call_arg_value(api_call, api_call_config[REQUEST_PARAM])
        else:
            request = ""
        netloc = resource.get_host()
        if resource.port:
            if resource.port == 443:
                scheme = "https"
            else:
                scheme = "http"
        else:
            scheme = "http"
        if not request:
            request = ""
        if not isinstance(request, str):
            request = str(request)
        url = urlunparse((scheme, netloc, request, "", "", None))
        return url

    # </editor-fold>

    @staticmethod
    def _get_api_call_arg_value(api_call: APICall, arg_name: str, is_out: Optional[bool] = None) -> Optional[Any]:
        """
        Returns an API call argument value based on the AAM config
        :param api_call: API call to return the argument value from
        :param arg_name: Name of the argument as defined in the AAM config
        :param is_out: Indicates whether the argument has the direction out
        :return: Value of the argument
        """
        if arg_name == RETURN:
            value = api_call.get_return_value()
        elif arg_name.startswith(RETURN):
            ret_arg_name = ":".join(arg_name.split(":")[1:])
            value = api_call.get_return_value(arg_name=ret_arg_name)
        else:
            values = api_call.get_argument_values(arg_name, is_out=is_out)
            if values and len(values):
                value = values[0]
            else:
                value = None
        return value

    def _remove_resource_by_id(self, resource_id: str) -> None:
        """
        Removes a resource by the given ID
        :param resource_id: ID of the resource to delete (UUID)
        """
        for resource in self.resources:
            if resource.id == resource_id:
                self.resources.remove(resource)
                break

    def _close_handles(self, api_call: APICall) -> None:
        """
        Closes handles referenced by the given API call
        :param api_call: API call that closes handles
        """
        config_section = CLOSE
        api_call_config_indices = self._get_api_call_configs(api_call.function_name, config_section)
        if len(api_call_config_indices) and self._handle_table.has_entries():
            for ix in api_call_config_indices:
                handle_param = self.config[config_section][ix][HANDLE_PARAM]
                handle_id = api_call.get_argument_values(handle_param)[0]
                self._handle_table.close_handle(handle_id)

    def _get_relevant_api_calls(self, config_section: str) -> Set[str]:
        """
        Returns relevant API calls for certain AAM config sections
        :param config_section: Section name of the AAM config
        :return: Set of relevant API calls for the given config section
        """
        relevant_api_calls = set()
        if config_section not in self.config.keys():
            return set()
        for api_call in self.config[config_section]:
            relevant_api_calls.add(api_call[API_CALL_NAME])
        return relevant_api_calls

    def _get_api_call_configs(self, api_call_name: str, config_section: str) -> List[int]:
        """
        Returns the relevant AAM config section for a given API call
        :param api_call_name: Function name of the API call to return the config for
        :param config_section: AAM config section
        """
        config_indices = list()
        if config_section not in self.config.keys():
            return config_indices
        for ix, api_call in enumerate(self.config[config_section]):
            if RegexHelper.is_regex_pattern(api_call[API_CALL_NAME]):
                if RegexHelper.is_regex_matching(api_call_name, api_call[API_CALL_NAME]):
                    config_indices.append(ix)
            elif api_call[API_CALL_NAME] == api_call_name:
                config_indices.append(ix)
        return config_indices

    def _parse_config(self, aam_config_path: str) -> None:
        """
        Parses the AAM configuration file
        :param aam_config_path: Path to the AAM config file
        """
        with open(aam_config_path, "r") as aam_config_file:
            config_content = yaml.safe_load(aam_config_file)
        self.config = config_content

    def _find_resource_by_handle(self, api_call_config: Dict[str, Any], api_call: APICall) -> Optional[Resource]:
        """
        Finds a resource by a handle referenced by the given API call
        :param api_call_config: Configuration of the API call extracted from the AAM config file
        :param api_call: API call that references a certain handle
        """
        if HANDLE_ID in api_call_config.keys():
            handle_id = api_call_config[HANDLE_ID]
        elif HANDLE_PARAM in api_call_config.keys():
            handle_id = self._get_api_call_arg_value(api_call, api_call_config[HANDLE_PARAM])
        else:
            return None
        if not handle_id:
            return None
        if self._handle_table.handle_exists(handle_id):
            resource_id = self._handle_table.get_resource_id_by_handle(handle_id)
            return self._get_resource_by_id(resource_id)
        return None

    def _get_resource_by_id(self, resource_id: str) -> Optional[Resource]:
        """
        Returns a resource by its ID (UUID)
        :param resource_id: ID of the resource to return
        :return: Resource identified by the given ID
        """
        for resource in self.resources:
            if resource.id == resource_id:
                return resource
        return None

    def _get_resource_by_path(self, path: str) -> Optional[Resource]:
        """
        Returns a resource accessing the given path
        :param path: Path that is referenced by a resource
        :return: Resource accessing the given path
        """
        if isinstance(path, str):
            for resource in self.resources:
                if not isinstance(resource, NetworkResource):
                    if resource.path.lower() == path.lower():
                        return resource
        return None

    def _update_handles(self, api_call_config: Dict[str, Any], api_call: APICall, resource_id: str) -> None:
        """
        Updates the internal handle table based on the API call opening a new handle
        :param api_call_config: Configuration of the API call extracted from the AAM config file
        :param api_call: API call that opens a handle
        :param resource_id: ID of the resource that is referenced by the API call opening a new handle
        """
        if HANDLE_RETURN_IN in api_call_config.keys():
            if api_call_config[HANDLE_RETURN_IN] == RETURN:
                handle_id = api_call.get_return_value()
            else:
                is_out = None
                if HANDLE_IS_OUT in api_call_config.keys():
                    is_out = api_call_config[HANDLE_IS_OUT]
                arg_vals = api_call.get_argument_values(api_call_config[HANDLE_RETURN_IN], is_out=is_out)
                if arg_vals:
                    arg_val = arg_vals[0]
                else:
                    return None
                if isinstance(arg_val, Pointer):
                    if not isinstance(arg_val.arguments, list):
                        handle_id = arg_val.arguments
                    else:
                        return None
                else:
                    handle_id = arg_val
            self._handle_table.open_handle(handle_id, resource_id)

    @staticmethod
    def _get_path_from_api_call(api_call: APICall, path_arg: str, is_out: Optional[bool]) -> Optional[str]:
        """
        Returns the path referenced by the given API call
        :param api_call: API call to return the argument value from
        :param path_arg: Name of the argument containing the path
        :param is_out: Indicates whether the argument has the direction out
        :return: Path that is referenced by the API call
        """
        vals = api_call.get_argument_values(path_arg, is_out=is_out)
        if vals:
            if len(vals) == 1:
                path = vals[0]
            else:
                path = vals[-1]
        else:
            path = None
        if isinstance(path, str):
            return path
        else:
            return None

    def _update_resource_obj(self, resource: Optional[Resource], api_call_config: Dict[str, Any]) -> None:
        """
        Updates an existing resource
        :param resource: Resource object to update
        :param api_call_config: Configuration of the API call extracted from the AAM config file
        """
        if not resource:
            return
        new_access = self._get_access_type(api_call_config[OPERATION])
        if new_access not in resource.access_operations:
            resource.access_operations.add(new_access)

    @staticmethod
    def _get_access_type(operation: str) -> AccessType:
        """
        Returns the AccessType value based on the given operation string
        :param operation: Operation as string
        :return: AccessType value
        """
        if operation.lower() == "read":
            return AccessType.READ
        elif operation.lower() == "write":
            return AccessType.WRITE
        elif operation.lower() == "execute":
            return AccessType.EXECUTE
        elif operation.lower() == "create":
            return AccessType.CREATE
        elif operation.lower() == "delete":
            return AccessType.DELETE
        else:
            return AccessType.UNDEFINED

    @staticmethod
    def _reduce_api_calls(process: Process, api_function_names: Set[str]) -> List[APICall]:
        """
        Reduces the process's list of API calls based on the provided API function names
        :param process: Process object of that the API calls should be reduced
        :param api_function_names: List of relevant API call function names
        :return: List of APICall objects that were reduced based on the API function names
        """
        reduced_api_calls = dict()
        # Find suitable candidates for every detection step and add them to a list
        for fname in api_function_names:
            candidates = process.get_api_calls_by_name(fname, is_regex_pattern=RegexHelper.is_regex_pattern(fname))
            for candidate in candidates:
                if candidate.index not in reduced_api_calls.keys():
                    reduced_api_calls[candidate.index] = candidate
        # Sort the list by the API call index
        reduced_api_calls = list(reduced_api_calls.values())
        reduced_api_calls.sort(key=lambda x: x.index)
        return reduced_api_calls


class HandleTable:
    def __init__(self):
        self._handle_table = {}

    def open_handle(self, handle_id: int, resource_id: str) -> None:
        """
        Opens a new handle in the internal handle table
        :param handle_id: ID of the handle as extracted from the API call
        :param resource_id: ID of the resource referenced by the handle ID
        """
        self._handle_table[handle_id] = resource_id

    def handle_exists(self, handle_id: int) -> bool:
        """
        Indicates whether a handle with the given ID is existing in the internal handle table
        :param handle_id: ID of the handle as extracted from the API call
        :return: Indicates whether the handle is existing
        """
        return handle_id in self._handle_table.keys()

    def get_resource_id_by_handle(self, handle_id: int) -> str:
        """
        Returns the resource ID referenced by the given handle ID
        :param handle_id: ID of the handle
        :return: ID of the resource referenced by the handle
        """
        if handle_id in self._handle_table.keys():
            return self._handle_table[handle_id]

    def close_handle(self, handle_id: int) -> None:
        """
        Closes a handle with the given ID
        :param handle_id: ID of the handle to close
        """
        if handle_id in self._handle_table.keys():
            del self._handle_table[handle_id]

    def has_entries(self) -> bool:
        """
        Indicates whether the internal handle table has entries
        """
        return len(self._handle_table) > 0

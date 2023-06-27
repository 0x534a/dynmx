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
from typing import Optional, Dict, Any
from enum import Flag
from urllib.parse import urlparse
import ipaddress
from dynmx.core.resource import Resource, AccessType
from dynmx.helpers.resource_helper import ResourceHelper


class NetworkResource(Resource):
    """
    Representation of a Registry resource
    """

    def __init__(self, access: Optional[AccessType] = None, url: Optional[str] = None,
                 network_type: Optional[NetworkType] = None, ip_address: Optional[Any] = None,
                 port: Optional[int] = None, dns_name: Optional[str] = None):
        """
        Constructor
        """
        self.url = None
        if url:
            self.set_url(url)
        if network_type:
            self.network_type = network_type
        else:
            self.network_type = NetworkType.UNDEFINED
        self.ip_address = ip_address
        self.port = port
        self.dns_name = dns_name
        Resource.__init__(self, access)

    def get_as_dict(self) -> Dict[str, Any]:
        result_dict = {
            "access_operations": []
        }
        for op in self.access_operations:
            result_dict["access_operations"].append(op.name)
        if self.url:
            result_dict["url"] = self.url
        if self.port:
            result_dict["port"] = self.port
        if self.dns_name:
            result_dict["dns_name"] = self.dns_name
        if self.ip_address:
            result_dict["ip_address"] = str(self.ip_address)
        return result_dict

    def get_location(self) -> str:
        return self.get_url()

    def set_url(self, url: str) -> None:
        if ResourceHelper.is_url(url):
            self.url = url
            parsed_url = urlparse(url)
            net_location = parsed_url.netloc
            if ":" in net_location:
                location_parts = net_location.split(":")
                host = location_parts[0]
                self.set_host(host)
                self.port = location_parts[1]
            else:
                self.set_host(net_location)

    def set_host(self, host: str) -> None:
        if ResourceHelper.is_ip_address(host):
            self.ip_address = ipaddress.ip_address(host)
        else:
            self.dns_name = host

    def get_host(self) -> str:
        if self.dns_name:
            host = self.dns_name
        else:
            host = str(self.ip_address)
        if self.port:
            host += ":" + str(self.port)
        return host

    def get_url(self) -> str:
        if self.url:
            return self.url
        else:
            return self.get_host()

    def is_host(self, host: str, port: Optional[int] = None) -> bool:
        if ResourceHelper.is_ip_address(host):
            is_host = str(self.ip_address) == host
        else:
            is_host = self.dns_name == host
        if is_host and port:
            if self.port == port:
                is_host = True
        return is_host

    def has_ip(self) -> bool:
        return self.ip_address is not None

    def __str__(self) -> str:
        if self.url:
            return str(self.url)
        else:
            if self.dns_name:
                host = self.dns_name
            else:
                host = str(self.ip_address)
            if self.port:
                host += ":" + str(self.port)
            return host


class NetworkType(Flag):
    UNDEFINED = 1
    CONNECT = 2
    DNS = 3
    LISTEN = 4

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


class DetectionResult:
    """
    Representation of a detection result
    """

    def __init__(self, flog_name: Optional[str] = None, flog_path: Optional[str] = None,
                 signature_name: Optional[str] = None, signature_path: Optional[str] = None, detected: bool = False):
        """
        Constructor
        """
        self.flog_name = flog_name
        self.flog_path = flog_path
        self.signature_name = signature_name
        self.signature_path = signature_path
        self.detected = detected
        self.runtime_flog_parsing = None
        self.runtime_resource_extraction = None
        self.runtime_signature_detection = None
        self.detected_processes = []

    def get_as_dict(self) -> Dict[str, Any]:
        """
        Returns DetectionResult object as dictionary
        :return: Dictionary representing the DetectionResult object
        """
        result_dict = {
            "flog": self.flog_name,
            "flog_path": self.flog_path,
            "signature": self.signature_name,
            "signature_path": self.signature_path,
            "detected": self.detected,
            "detected_processes": [],
        }
        if self.runtime_flog_parsing:
            result_dict["runtime_flog_parsing"] = self.runtime_flog_parsing
        if self.runtime_resource_extraction:
            result_dict["runtime_resource_extraction"] = self.runtime_resource_extraction
        if self.runtime_signature_detection:
            result_dict["runtime_signature_detection"] = self.runtime_signature_detection
        for p in self.detected_processes:
            p_dict = p.get_as_dict()
            result_dict["detected_processes"].append(p_dict)
        return result_dict


class DetectedProcess:
    """
    Representation of a detected process
    """

    def __init__(self, os_id: Optional[int] = None, name: Optional[str] = None, file_path: Optional[str] = None,
                 cmd_line: Optional[str] = None, owner: Optional[str] = None):
        """
        Constructor
        :param process: Process that was detected
        """
        self.process_os_id = os_id
        self.process_name = name
        self.process_file_path = file_path
        self.process_cmd_line = cmd_line
        self.process_owner = owner
        self.findings = []

    def get_as_dict(self) -> Dict[str, Any]:
        """
        Returns the object as dictionary
        :return: DetectedProcess object as dictionary
        """
        proc_info = {
            "os_id": self.process_os_id,
            "name": self.process_name,
            "file_path": self.process_file_path,
            "cmd_line": self.process_cmd_line,
            "owner": self.process_owner,
        }
        result_dict = {
            "process": proc_info,
            "findings": [],
        }
        for finding in self.findings:
            f_dict = finding.get_as_dict()
            result_dict["findings"].append(f_dict)
        return result_dict


class DetectedBlock:
    """
    Representation of a finding
    """
    def __init__(self, detection_block_key: Optional[str] = None):
        """
        Constructor
        :param detection_block_key: Key of the detection block that was
        detected
        """
        self.detection_block_key = detection_block_key
        self.api_calls = []
        self.resources = []

    def get_as_dict(self) -> Dict[str, Any]:
        """
            Returns the object as dictionary
            :return: DetectedStep object as dictionary
            """
        result_dict = {
            "detection_block_key": self.detection_block_key,
            "api_calls": [],
            "resources": [],
        }
        for api_call in self.api_calls:
            s_dict = api_call.get_as_dict()
            result_dict["api_calls"].append(s_dict)
        for resource in self.resources:
            r_dict = resource.get_as_dict()
            result_dict["resources"].append(r_dict)
        return result_dict

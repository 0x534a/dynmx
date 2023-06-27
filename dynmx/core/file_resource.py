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

from dynmx.core.resource import Resource, AccessType


class FileResource(Resource):
    """
    Representation of an OS file resource
    """

    def __init__(self, access: Optional[AccessType] = None, path: Optional[str] = None):
        """
        Constructor
        """
        self.path = path
        Resource.__init__(self, access)

    def get_location(self) -> str:
        return self.path

    def get_as_dict(self) -> Dict[str, Any]:
        result_dict = {
            "path": self.path,
            "access_operations": []
        }
        for op in self.access_operations:
            result_dict["access_operations"].append(op.name)
        return result_dict

    def __str__(self) -> str:
        return self.path

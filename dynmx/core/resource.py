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
from enum import Flag, auto
from uuid import uuid4


class Resource:
    """
    Representation of an OS resource
    """

    def __init__(self, access: Optional[AccessType] = None):
        """
        Constructor
        """
        self.id = uuid4()
        if access:
            self.access_operations = set([access])
        else:
            self.access_operations = set()

    # Needs to be implemented in the specialized class
    def get_location(self) -> str:
        pass

    # Needs to be implemented in the specialized class
    def get_as_dict(self) -> Dict[str, Any]:
        pass

    def has_access_operation(self, access_operation: AccessType) -> bool:
        return access_operation in self.access_operations


class AccessType(Flag):
    UNDEFINED = 1
    READ = 2
    WRITE = 3
    EXECUTE = 4
    CREATE = 5
    DELETE = 6

    @staticmethod
    def get_entry_by_str(str_entry: str) -> Optional[AccessType]:
        if str_entry.lower() == "read":
            return AccessType.READ
        elif str_entry.lower() == "write":
            return AccessType.WRITE
        elif str_entry.lower() == "execute":
            return AccessType.EXECUTE
        elif str_entry.lower() == "create":
            return AccessType.CREATE
        elif str_entry.lower() == "delete":
            return AccessType.DELETE
        else:
            return None

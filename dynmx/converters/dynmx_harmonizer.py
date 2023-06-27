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
from typing import Optional, TYPE_CHECKING, List, Dict, Any
import logging
import sqlite3

from dynmx.core.api_call import ApiCallSignature, Argument

if TYPE_CHECKING:
    from dynmx.core.function_log import FunctionLog
    from dynmx.core.api_call import APICall


class DynmxHarmonizer:
    """
    Harmonization layer for the dynmx flog format based on an API call database
    """

    def __init__(self, api_call_db: str):
        """
        Constructor
        :param api_call_db: Path to API call sqlite database file
        """
        # Load API call database
        self._logger = logging.getLogger(__name__)
        self._api_call_db = ApiCallDb(api_call_db)

    def harmonize_flog(self, flog: FunctionLog) -> None:
        """
        Harmonizes all APICall objects of the function log
        :param flog: Function log to harmonize
        :return:
        """
        # Iterate over each process and identify unique API calls
        unique_api_calls = list()
        for proc in flog.processes:
            unique_api_calls = self._identify_api_call_signatures(proc.api_calls, unique_api_calls)
        self._logger.debug("Identified {} unique API calls for function log {}".format(len(unique_api_calls),
                                                                                       flog.file_path))
        mapping = self._build_api_call_mapping(unique_api_calls)
        # Manipulate API calls based on mapping
        for proc in flog.processes:
            self._logger.debug("Harmonizing API calls of process ID {}: {}".format(proc.os_id, proc.name))
            for api_call in proc.api_calls:
                self._logger.debug("Harmonizing API call {}: {}".format(api_call.index, api_call.function_name))
                if api_call.function_name in mapping.keys():
                    self._manipulate_api_call_obj(api_call, mapping[api_call.function_name])

    def harmonize_api_call(self, api_call: APICall) -> None:
        """
        Harmonizes the APICall object
        :param api_call: APICall object to harmonize
        :return:
        """
        function_name = api_call.function_name
        api_call_signature = self._find_harmonized_api_call(function_name)
        if api_call_signature:
            self._manipulate_api_call_obj(api_call, api_call_signature)

    def _identify_api_call_signatures(self, api_calls: List[APICall],
                                      unique_api_calls: Optional[List[APICall]] = None) -> List[APICall]:
        """
        Identifies unique API call signatures in a list of APICall objects
        :param api_calls: List of APICall objects
        :param unique_api_calls: List of already identified unique APICall objects
        :return: List of unique APICall objects
        """
        unique_api_calls = list() if not unique_api_calls else unique_api_calls
        for api_call in api_calls:
            ix = self._find_api_call_signature(unique_api_calls, api_call)
            if ix is None:
                unique_api_calls.append(api_call)
        return unique_api_calls

    @staticmethod
    def _find_api_call_signature(api_calls: List[APICall], api_call: APICall) -> Optional[int]:
        """
        Finds duplicates of a APICall object in a list of APICall objects. APICall objects are considered as
        duplicates if the function name and the number of arguments are matching
        :param api_calls: List of APICall objects
        :param api_call: APICall object
        :return: Index of the duplicate APICall object or None if no duplicate was found
        """
        if not len(api_calls):
            return None
        api_call_name = api_call.function_name
        num_of_args = len(api_call.arguments)
        for ix, a in enumerate(api_calls):
            if a.function_name == api_call_name:
                if len(a.arguments) == num_of_args:
                    return ix
        return None

    def _build_api_call_mapping(self, api_calls: List[APICall]) -> Dict[str, ApiCallSignature]:
        """
        Builds a mapping represented by a dictionary of APICall objects to the corresponding harmonized
        ApiCallSignature object
        :param api_calls: List APICall objects to build the mapping for
        :return: Dictionary consisting of the APICall function names as keys and the corresponding harmonized
        ApiCallSignature object as value
        """
        mapping = {}
        for api_call in api_calls:
            harmonized_sig = self._find_harmonized_api_call(api_call.function_name)
            if harmonized_sig:
                mapping[harmonized_sig.function_name] = harmonized_sig
        return mapping

    def _find_harmonized_api_call(self, function_name: str) -> ApiCallSignature:
        """
        Finds a harmonized ApiCallSignature in the API call database for the given function name
        :param function_name: Function name to find harmonized API call signature for
        :return: ApiCallSignature object if a harmonized API call was found. None if no harmonized API call
        signature was found in the API call database.
        """
        self._logger.debug("Searching for suitable API calls for {} in API call database".format(function_name))
        candidates = self._api_call_db.select_api_call(function_name)
        if len(candidates):
            if len(candidates) > 1:
                self._logger.debug("Found {} harmonization candidates for API call {}".format(
                    len(candidates), function_name))
                # Identify the right API call by the calling convention
                for candidate in candidates:
                    if candidate["calling_convention"] == "WINAPI":
                        self._logger.debug("Found candidate with row ID {} for harmonizing API call {}".format(
                            candidate["id"], function_name))
                        return self._build_api_call_obj(candidate)
                # If WINAPI calling convention can not be found take first found API call from database
                self._logger.debug("Found candidate with row ID {} for harmonizing API call {}".format(
                    candidates[0]["id"], function_name))
                return self._build_api_call_obj(candidates[0])
            else:
                self._logger.debug("Found candidate with row ID {} for harmonizing API call {}".format(
                    candidates[0]["id"], function_name))
                return self._build_api_call_obj(candidates[0])
        else:
            self._logger.warning("No harmonization candidates found for API call {}".format(function_name))
        return None

    def _build_api_call_obj(self, api_call_row: Dict[str, Any]) -> ApiCallSignature:
        """
        Builds a ApiCallSignature object based on the row retrieved from the API call database
        :param api_call_row: API call row returned by the API call database
        :return: ApiCallSignature object containing the information retrieved from the API call database row
        """
        api_call = ApiCallSignature()
        api_call.function_name = api_call_row["name"]
        api_call.description = api_call_row["description"]
        api_call.return_value_desc = api_call_row["return_value"]
        api_call.return_type = api_call_row["return_type"]
        api_call.calling_convention = api_call_row["calling_convention"]
        # Arguments
        arg_rows = self._api_call_db.select_args_by_api_call(api_call_row["id"])
        api_call.arguments = self._build_arg_objects(arg_rows)
        return api_call

    @staticmethod
    def _build_arg_objects(arg_rows: List[Dict[str, Any]]) -> List[Argument]:
        """
        Builds a list of Argument objects based on the given argument rows retrieved from the API call database
        :param arg_rows: Rows from the API call database containing argument information
        :return: List of Argument objects containing the information retrieved by the API call database
        """
        args = []
        for arg_row in arg_rows:
            arg = Argument()
            arg.name = arg_row["name"]
            arg.is_in = True if arg_row["is_in"] == 1 else False
            arg.is_out = True if arg_row["is_out"] == 1 else False
            args.append(arg)
        return args

    def _manipulate_api_call_obj(self, api_call: APICall, api_call_signature: ApiCallSignature) -> None:
        """
        Manipulates the given APICall object in order to harmonize the object based on the ApiCallSignature object
        :param api_call: APICall object to manipulate
        :param api_call_signature: ApiCallSignature object used as harmonization baseline
        """
        # Find duplicate arguments based on the name in the concrete API call
        reference_table = self._build_arg_reference_table(api_call.arguments)
        # Manipulate arguments of API calls and their duplicates
        for ix, arg in enumerate(api_call_signature.arguments):
            if ix < len(api_call.arguments):
                api_call.arguments[ix].name = arg.name
                api_call.arguments[ix].is_in = arg.is_in
                api_call.arguments[ix].is_out = arg.is_out
                # Check for duplicate arguments and manipulate them too
                if ix in reference_table.keys():
                    referenced_ixs = reference_table[ix]
                    for referenced_ix in referenced_ixs:
                        api_call.arguments[referenced_ix].name = arg.name
                        api_call.arguments[referenced_ix].is_in = arg.is_in
                        api_call.arguments[referenced_ix].is_out = arg.is_out

    @staticmethod
    def _build_arg_reference_table(args: List[Argument]) -> Dict[int, List[int]]:
        """
        Finds all duplicates of an argument in a list of arguments. An argument is considered as duplicate of another
        argument if the name is equal.
        :param args: List of arguments to search for duplicates in
        :return: Reference table representing duplicate arguments
        """
        reference_table = {}
        already_visited = set()
        for ix, arg in enumerate(args):
            if ix in already_visited:
                continue
            for ix2, arg2 in enumerate(args):
                if ix != ix2 and arg.name == arg2.name:
                    if ix not in reference_table.keys():
                        reference_table[ix] = [ix2]
                    else:
                        reference_table[ix].append(ix2)
                    already_visited.update([ix, ix2])
        return reference_table


class ApiCallDb:
    """
    Interface to the API call database
    """

    def __init__(self, api_call_db: str):
        """
        Constructor
        :param api_call_db: Path to API call sqlite database file
        """
        # Load API call database
        self._logger = logging.getLogger(__name__)
        self._api_call_db = sqlite3.connect(api_call_db)
        self._api_call_db.row_factory = sqlite3.Row
        self._db_cursor = self._api_call_db.cursor()

    def select_api_call(self, function_name: str) -> List[Dict[str, Any]]:
        """
        Finds all Windows API calls with the given function name in the API call database
        :param function_name: Function name to search for in API call database
        :return: Database rows of the found API calls
        """
        # Search for Windows API calls matching the function name
        self._db_cursor.execute(
            "SELECT * FROM api_calls WHERE name=? AND target_os=\"Windows\";",
            (function_name,)
        )
        rows = self._db_cursor.fetchall()
        self._logger.debug("Found {} rows for API call {} in API call database".format(len(rows), function_name))
        return self._transform_rows(rows)

    def select_args_by_api_call(self, api_call_id: int) -> List[Dict[str, Any]]:
        """
        Finds all arguments belonging to the given API call ID
        :param api_call_id: ID of the API call to find the arguments for
        :return: Database rows of the found arguments
        """
        # Search for arguments of the API call id
        stmt = "SELECT p.*, t.name " \
               "FROM api_calls a, api_call_params p, types t " \
               "WHERE p.api_call_id=a.id AND p.type_id=t.id AND a.id=?;"
        self._db_cursor.execute(
            stmt,
            (api_call_id,)
        )
        rows = self._db_cursor.fetchall()
        self._logger.debug("Found {} rows for arguments of API call with ID {} in API call database".format(
            len(rows), api_call_id))
        return self._transform_rows(rows)

    @staticmethod
    def _transform_rows(rows: List) -> List:
        """
        Builds a list of dictionaries based on the rows. The column names become the keys of the dictionary.
        :param rows: Rows returned from the database cursor
        :return: List of dictionaries representing a returned row
        """
        if rows:
            return [dict(row) for row in rows]
        else:
            return []

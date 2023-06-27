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
from typing import Optional, List, Dict, Any, TYPE_CHECKING
from abc import ABC, abstractmethod
from enum import Enum
from dynmx.core.pointer import Pointer
from dynmx.detection.graph import GraphNode
from dynmx.core.network_resource import NetworkResource
from dynmx.helpers.regex_helper import RegexHelper
from dynmx.helpers.logging_helper import LoggingHelper

# Avoids cyclic imports
if TYPE_CHECKING:
    from dynmx.detection.signature import StoreDirective, VariableStorage
    from dynmx.core.api_call import APICall
    from dynmx.core.process import Process
    from dynmx.core.resource import Resource


class DetectionStep(GraphNode, ABC):
    """
    Representation of a generic detection step
    """

    def __init__(self, step_type: DetectionStepType, with_conditions: Optional[List[WithCondition]] = None,
                 store_directives: Optional[List[StoreDirective]] = None, neighbours: Optional[List[GraphNode]] = None):
        GraphNode.__init__(self, neighbours)
        self.step_type = step_type
        if with_conditions:
            self.with_conditions = with_conditions
        else:
            self.with_conditions = list()
        if store_directives:
            self.store_directives = store_directives
        else:
            self.store_directives = list()
        self._logger = LoggingHelper.get_logger(__name__)

    @abstractmethod
    def detect(self, flog_path: str, obj: Any, var_storage: VariableStorage, last_detected_index: Optional[int] = None) -> Any:
        """
        Detects the detection step in the given API call
        :param obj: Object to detect the detection step in
        :param var_storage: VariableStorage of the signature
        :param last_detected_index: Index of the API call that was detected in the previous step (only needed for
        sequence detection type)
        """
        pass

    @abstractmethod
    def store_variables(self, obj: Any, var_storage: VariableStorage):
        """
        Stores variables defined in the detection step
        :param obj: Object to store variables from
        :param var_storage: VariableStorage object
        """
        pass


class APICallDetectionStep(DetectionStep):
    """
    Representation of an API call graph node
    """

    def __init__(self, function_names: Optional[Any] = None, with_conditions: Optional[List[WithCondition]] = None,
                 store_directives: Optional[List[StoreDirective]] = None, limit: Optional[int] = None,
                 min_occurrence: Optional[int] = 1, neighbours: Optional[List[GraphNode]] = None):
        DetectionStep.__init__(
            self,
            DetectionStepType.API_CALL,
            with_conditions=with_conditions,
            store_directives=store_directives,
            neighbours=neighbours
        )
        self.function_names = function_names
        if self.function_names:
            if type(self.function_names) is not list:
                self.function_names = [function_names]
        else:
            self.function_names = []
        self.limit = limit
        self.min_occurrence = min_occurrence

    def detect(self, flog_path: str, api_call: APICall, var_storage: VariableStorage,
               last_detected_index: Optional[int] = None) -> bool:
        """
        Detects the detection step in the given API call
        :param flog_path: Function log path
        :param api_call: API call to detect the detection step in
        :param var_storage: VariableStorage of the signature
        :param last_detected_index: Index of the API call that was detected in the previous step (only needed for
        sequence detection type)
        :return:
        """
        self._logger = LoggingHelper.get_logger(__name__, flog_path=flog_path)
        result = self.detect_function_name(api_call)
        if not result:
            return False
        self._logger.debug(
            "Detection step: step={}, api_call={}".format(self, api_call))
        for with_condition in self.with_conditions:
            result = with_condition.detect(flog_path, self.step_type, api_call, var_storage)
            self._logger.debug(
                "with condition detection result: with_condition={}, api_call={}, result={}".format(
                    with_condition, api_call, result))
            if not result:
                break
        if result and self.limit and last_detected_index:
            max_index = last_detected_index + self.limit
            if not api_call.index <= max_index:
                result = False
        if result and self.store_directives:
            try:
                self.store_variables(api_call, var_storage)
            except ValueError as ex:
                self._logger.warning("Could not store variable. Error message: '{}'. Step not detected.".format(ex))
                result = False
        self._logger.debug("Detection step result: step={}, api_call={}, result={}".format(
            self, api_call, result))
        return result

    def detect_function_name_in_process(self, process: Process) -> bool:
        """
        Checks whether the function name of the detection step exists in the process's API calls
        :param process: Process to find the function name of the detection step in
        :return: Bool that indicates whether the function name of the detection step was found in the process
        """
        result = False
        for fname in self.function_names:
            result = process.has_api_call_function_name(fname, is_regex_pattern=RegexHelper.is_regex_pattern(fname))
            if result:
                break
        return result

    def detect_function_name(self, api_call: APICall) -> bool:
        """
        Detects the function name of the detection step in the API call
        :param api_call: API call to detect the function name of the detection step in
        :return: Bool that indicates whether the function name of the detection step was detected in the API call
        """
        result = False
        for fname in self.function_names:
            if RegexHelper.is_regex_pattern(fname):
                result = RegexHelper.is_regex_matching(api_call.function_name, fname)
            else:
                result = fname == api_call.function_name
            if result:
                break
        return result

    def get_variables(self, api_call: APICall) -> Dict[str, List[Any]]:
        variables = {}
        for store_directive in self.store_directives:
            vals = list()
            if store_directive.argument == "return":
                vals.append(api_call.return_value)
            else:
                is_regex = RegexHelper.is_regex_pattern(store_directive.argument)
                vals = api_call.get_argument_values(
                    store_directive.argument,
                    is_regex_pattern=is_regex,
                    is_in=store_directive.is_in,
                    is_out=store_directive.is_out
                )
            if vals and len(vals) > 0:
                variables[store_directive.var_name] = vals[0]
        return variables

    def accesses_variables(self) -> bool:
        for with_cond in self.with_conditions:
            if with_cond.accesses_variables():
                return True
        return False

    def store_variables(self, api_call: APICall, var_storage: VariableStorage) -> None:
        """
        Stores variables defined in the detection step
        :param api_call: Directives with the keyword "store"
        :param var_storage: API call to store variables from
        """
        variables = self.get_variables(api_call)
        for var_name, value in variables.items():
            var_storage.store(var_name, value)
            self._logger.debug("Store variable: var_name={}, value={}".format(var_name, value))

    def stores_variables(self) -> bool:
        return len(self.store_directives) > 0

    def __str__(self) -> str:
        """
        Returns the string representation of the detection step
        :return: String representation of the detection step
        """
        return "<{},[{}]>".format(self.step_type.name, ",".join(self.function_names))

    def __repr__(self) -> str:
        return str(self)


class ResourceDetectionStep(DetectionStep):
    """
    Representation of a resource graph node
    """

    def __init__(self, category: Optional[str] = None, access_operations: Any = None,
                 with_conditions: Optional[List[WithCondition]] = None,
                 store_directives: Optional[List[StoreDirective]] = None, neighbours: Optional[List[GraphNode]] = None):
        DetectionStep.__init__(
            self,
            DetectionStepType.RESOURCE,
            with_conditions=with_conditions,
            store_directives=store_directives,
            neighbours=neighbours
        )
        self.category = category
        self.access_operations = access_operations
        if self.access_operations:
            if not isinstance(self.access_operations, list):
                self.access_operations = [self.access_operations]
        else:
            self.access_operations = list()

    def detect(self, flog_path: str, resource: Resource, var_storage: VariableStorage,
               last_detected_index: Optional[int] = None) -> bool:
        """
        Detects the detection step in the given resource object
        :param flog_path: Function Log path
        :param resource: Resource to detect the detection step in
        :param var_storage: VariableStorage of the signature
        :param last_detected_index: Index of the API call that was detected in the previous step (only needed for
        sequence detection type)
        :return:
        """
        self._logger = LoggingHelper.get_logger(__name__, flog_path=flog_path)
        result = True
        self._logger.debug(
            "Detection step: step={}, resource={}".format(self, resource))
        # Detect access operations
        if len(self.access_operations):
            for op in self.access_operations:
                result &= resource.has_access_operation(op)
        if not result:
            return result
        # Detect with conditions
        if len(self.with_conditions):
            for with_condition in self.with_conditions:
                result = with_condition.detect(flog_path, self.step_type, resource, var_storage)
                self._logger.debug(
                    "with condition detection result: with_condition={}, resource={}, result={}".format(
                        with_condition, resource, result))
                if not result:
                    break
        # Store variables
        if result and self.store_directives:
            try:
                self.store_variables(resource, var_storage)
            except ValueError as ex:
                self._logger.warning("Could not store variable. Error message: '{}'. Step not detected.".format(ex))
                result = False
        return result

    def store_variables(self, resource: Resource, var_storage: VariableStorage):
        """
        Stores variables defined in the detection step
        :param resource: Resource to store variables from
        :param var_storage: VariableStorage object
        """
        for store_directive in self.store_directives:
            vals = list()
            if store_directive.argument == "location":
                vals.append(resource.get_location())
            elif store_directive.argument == "host":
                if isinstance(resource, NetworkResource):
                    vals.append(resource.get_host())
            elif store_directive.argument == "port":
                if isinstance(resource, NetworkResource):
                    vals.append(resource.port)
            if not len(vals):
                raise ValueError("Source argument {} for variable {} could not be found for resource".format(
                    store_directive.argument, store_directive.var_name))
            var_storage.store(store_directive.var_name, vals[0])
            self._logger.debug("Store variable: var_name={}, value={}".format(store_directive.var_name, vals[0]))

    def __str__(self):
        """
        Returns the string representation of the detection step
        :return: String representation of the detection step
        """
        return "<{},{}>".format(self.step_type.name, self.category)

    def __repr__(self):
        return str(self)


class DetectionStepType(Enum):
    """
    Enum that defines types of the detection step
    """
    API_CALL = "api_call"
    RESOURCE = "resource"


class WithCondition:
    """
    Representation of a "with" condition
    """

    def __init__(self, with_condition_type: WithConditionType, arguments: Optional[List[Any]] = None,
                 is_in: Optional[bool] = None, is_out: Optional[bool] = None, operation: Optional[str] = None,
                 values: Optional[List[Any]] = None):
        if not isinstance(with_condition_type, WithConditionType):
            raise ValueError("with condition type '{}' not supported".format(with_condition_type))
        self.with_condition_type = with_condition_type
        if not arguments:
            arguments = list()
        self.arguments = arguments
        self.is_in = is_in
        self.is_out = is_out
        self.operation = operation
        self.values = values
        self._logger = LoggingHelper.get_logger(__name__)

    def detect(self, flog_path: str, step_type: DetectionStepType, obj: Any, var_storage: VariableStorage) -> bool:
        """
        Detects the with condition in the given API call
        :param flog_path: Function Log path
        :param step_type: Type of detection step
        :param obj: Object to detect the with condition in
        :param var_storage: VariableStorage of the signature
        :return: Bool indicating whether the with condition was detected in the object
        """
        self._logger = LoggingHelper.get_logger(__name__, flog_path)
        if step_type == DetectionStepType.API_CALL:
            # Check if an argument or return value has to be detected
            if self.with_condition_type == WithConditionType.ARGUMENT:
                return self._detect_argument(obj, var_storage)
            elif self.with_condition_type == WithConditionType.RETURN:
                return self._detect_return_value(obj, var_storage)
            else:
                raise NotImplementedError(
                    "Detection type '{}' not implemented for API call detection".format(self.with_condition_type))
        elif step_type == DetectionStepType.RESOURCE:
            if self.with_condition_type == WithConditionType.ATTRIBUTE:
                return self._detect_resource_attribute(obj, var_storage)
            else:
                raise NotImplementedError(
                    "Detection type '{}' not implemented for resource detection".format(self.with_condition_type))

    def accesses_variables(self) -> bool:
        for value in self.values:
            if RegexHelper.is_variable(value):
                return True
        return False

    def _detect_argument(self, api_call: APICall, var_storage: VariableStorage) -> bool:
        """
        Detects an argument with condition in the API call
        :param api_call: APICall object to detect the argument with condition in
        :param var_storage: VariableStorage of the signature
        :return: Bool indicating whether the argument with condition was detected in the API call
        """
        result = False
        for arg in self.arguments:
            is_regex = RegexHelper.is_regex_pattern(arg)
            arg_vals = api_call.get_argument_values(
                arg, is_in=self.is_in, is_out=self.is_out, is_regex_pattern=is_regex)
            if self.values:
                if arg_vals:
                    result |= self._detect_argument_value(arg_vals, var_storage)
                else:
                    result = False
            else:
                result = len(arg_vals) > 0
            if result:
                break
        return result

    def _detect_argument_value(self, argument_values: List[Any], var_storage: VariableStorage) -> bool:
        """
        Detects the values of the with condition in the argument values
        :param argument_values: Argument values to detect the with condition values in
        :param var_storage: VariableStorage of the signature
        :return:
        """
        result = False
        for val in self.values:
            if RegexHelper.is_variable(val):
                var_name = RegexHelper.get_variable_name(val)
                try:
                    condition_val = var_storage.get_variable_value(var_name)
                except ValueError:
                    result = False
                    self._logger.debug("Variable not found {}".format(var_name))
                    continue
            else:
                condition_val = val
            for arg_value in argument_values:
                result |= self._check_value(self.operation, arg_value, condition_val)
                if result:
                    break
            if result:
                break
        return result

    def _detect_return_value(self, api_call: APICall, var_storage: VariableStorage) -> bool:
        """
        Detects a return value with condition in the API call
        :param api_call: APICall object to detect the return value with condition in
        :param var_storage: VariableStorage of the signature
        :return: Bool that indicates whether the return value with condition was detected in the API call
        """
        result = False
        # Check the whole return value
        if not self.arguments:
            return_vals = api_call.return_value
            if isinstance(return_vals, Pointer):
                return_vals = return_vals.arguments
            if type(return_vals) is not list:
                return_vals = [return_vals]
            # Check the value of the return value
            if self.values:
                result = self._detect_argument_value(return_vals, var_storage)
            else:
                result = len(return_vals) > 0
        # Check a specific returned pointer argument of the return value
        else:
            for arg in self.arguments:
                is_regex = RegexHelper.is_regex_pattern(arg)
                arg_vals = api_call.get_return_value_pointer(arg, is_regex_pattern=is_regex)
                if self.values:
                    if arg_vals:
                        result |= self._detect_argument_value(arg_vals, var_storage)
                    else:
                        result = False
                    if result:
                        break
                else:
                    result = len(arg_vals) > 0
        return result

    def _detect_resource_attribute(self, resource: Resource, var_storage: VariableStorage) -> bool:
        """
        Detects a resource based on values
        :param resource: Resource to detect the values in
        :param var_storage: VariableStorage of the signature
        :return Bool that indicates whether the values were detected in the resource
        """
        result = False
        attr_value = None
        if "location" in self.arguments:
            attr_value = resource.get_location()
        if "host" in self.arguments:
            if isinstance(resource, NetworkResource):
                attr_value = resource.get_host()
        if "port" in self.arguments:
            if isinstance(resource, NetworkResource):
                attr_value = resource.port
        if attr_value:
            for val in self.values:
                if RegexHelper.is_variable(val):
                    var_name = RegexHelper.get_variable_name(val)
                    vals = var_storage.get_variable_value(var_name)
                else:
                    vals = [val]
                for val in vals:
                    result |= self._check_value(self.operation, attr_value, val)
                    if result:
                        break
                if result:
                    break
        return result

    def _check_value(self, operation: str, value: Any, condition_value: Any) -> bool:
        """
        Checks a value based on the given operation
        :param operation: Operation that the value should be checked with
        :param value: Value that should be checked
        :param condition_value: Value of the condition that should be fulfilled
        :return: Indicates whether the check was successful
        """
        self._logger.debug("Check value operation={}, value={}, condition_value={}".format(operation, value,
                                                                                           condition_value))
        value_is_string = isinstance(value, str)
        condition_val_is_string = isinstance(condition_value, str)
        if condition_value and condition_val_is_string:
            condition_value = condition_value.lower()
        if value_is_string:
            value = value.lower()
        if operation == "is":
            return value == condition_value
        if operation == "is not":
            return value != condition_value
        if operation == "contains":
            if value_is_string:
                return condition_value in value
        if operation == "contains not":
            if value_is_string:
                return condition_value not in value
        if operation == "startswith":
            if value_is_string:
                return value.startswith(condition_value)
        if operation == "startswith not":
            if value_is_string:
                return not (value.startswith(condition_value))
        if operation == "endswith":
            if value_is_string:
                return value.endswith(condition_value)
        if operation == "endswith not":
            if value_is_string:
                return not (value.endswith(condition_value))
        if operation == "regex":
            if value_is_string:
                return RegexHelper.is_regex_matching(value, condition_value)
        if operation == "flag is set":
            return self._flag_is_set(value, condition_value)
        if operation == "flag is not set":
            return not self._flag_is_set(value, condition_value)
        return False

    @staticmethod
    def _flag_is_set(value: Any, flag: int) -> bool:
        """
        Checks whether the flag is set in the value
        :param value:
        :param flag:
        :return:
        """
        return (int(value) & flag) != 0

    def __str__(self) -> str:
        return "with_condition(type={}, args={}, is_in={}, is_out={}, operation={}, vals={})".format(
            self.with_condition_type, self.arguments, self.is_in, self.is_out, self.operation, self.values)

    def __repr__(self) -> str:
        return str(self)


class WithConditionType(Enum):
    """
    Enum that defines types of the "with" condition
    """
    RETURN = "return"
    ARGUMENT = "argument"
    ATTRIBUTE = "attribute"

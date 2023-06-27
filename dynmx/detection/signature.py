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
from typing import Optional, List, Dict, Set, Any, TYPE_CHECKING, Tuple
import pyparsing
import yaml
from anytree import NodeMixin, PreOrderIter
import traceback
import sys
from enum import Enum
from itertools import repeat, product
from dynmx.detection.detection_result import DetectionResult, DetectedProcess, DetectedBlock
from dynmx.helpers.regex_helper import RegexHelper
from dynmx.detection.graph import DirectedAcyclicGraph
from dynmx.detection.detection_step import APICallDetectionStep, ResourceDetectionStep, \
    DetectionStepType, WithCondition, WithConditionType
from dynmx.core.resource import AccessType
from dynmx.helpers.logging_helper import LoggingHelper

# Avoid cyclic imports
if TYPE_CHECKING:
    from dynmx.core.function_log import FunctionLog
    from dynmx.core.process import Process
    from dynmx.detection.graph import GraphNode
    from dynmx.detection.detection_step import DetectionStep
    from dynmx.core.resource import Resource
    from dynmx.core.api_call import APICall


class Signature:
    """
    Representation of a dynmx signature
    """

    def __init__(self, file_path: Optional[str] = None, detect_all: bool = False):
        """
        Constructor
        :param file_path: Path to dynmx signature file
        """
        self.content = {}
        self.var_storage = VariableStorage()
        self.condition = None
        self.file_path = file_path
        self.name = None
        self.detection_blocks = {}
        self.detect_all = detect_all
        self._logger = LoggingHelper.get_logger(__name__)
        self._parsed = False

    # <editor-fold desc="Parsing">
    def parse(self) -> None:
        """
        Parses a dynmx signature file
        """
        with open(self.file_path) as sig_file:
            self.content = yaml.safe_load(sig_file)
        self.name = self.content["dynmx_signature"]["meta"]["name"]
        self._logger.debug("Loaded YAML content of signature '{}'".format(self.name))
        self._logger.debug("Checked structure of signature '{}'".format(self.name))
        self.condition = Condition(self.content["dynmx_signature"]["condition"])
        self.condition.parse()
        self._logger.debug("Parsed condition of signature '{}'".format(self.name))
        self.check()
        self._parse_detection_blocks(self.content["dynmx_signature"]["detection"])
        self._logger.debug("Parsed {} detection block(s) from signature".format(len(self.detection_blocks)))
        self._parsed = True
        self._logger.info("Parsed signature file {} successfully".format(self.file_path))

    def check(self) -> None:
        """
        Checks the loaded signature file content for semantic validity
        """
        # Basic structure checks
        if "dynmx_signature" not in self.content:
            raise Exception("No dynmx signature found")
        if "meta" not in self.content["dynmx_signature"].keys():
            raise Exception("No meta section found in dynmx rule")
        if "detection" not in self.content["dynmx_signature"].keys():
            raise Exception("No detection section found in dynmx rule")
        if "condition" not in self.content["dynmx_signature"].keys():
            raise Exception(
                "No condition found in detection section of dynmx rule")
        # Basic content checks
        if "name" not in self.content["dynmx_signature"]["meta"].keys() and \
                self.content["dynmx_signature"]["meta"]["name"] == "":
            raise Exception("No name for signature defined")
        if "author" not in self.content["dynmx_signature"]["meta"].keys() and \
                self.content["dynmx_signature"]["meta"]["author"] == "":
            raise Exception("No name for signature defined")
        if self.content["dynmx_signature"]["condition"] == "":
            raise Exception(
                "Empty condition in detection section of dynmx rule")
        if len(self.get_detection_block_keys()) == 0:
            raise Exception("No detection blocks defined")
        for detection_block_key in self.get_detection_block_keys():
            if len(self.content["dynmx_signature"]["detection"][detection_block_key]) == 0:
                raise Exception(
                    "Empty detection block '{}'".format(detection_block_key))
            if not self.condition.has_detection_block(detection_block_key):
                self._logger.warning(
                    "Detection block '{}' is not part of the condition.".format(
                        detection_block_key))

    def needs_resources(self) -> bool:
        needs_res = False
        for block_key, block_obj in self.detection_blocks.items():
            needs_res |= block_obj.has_resource_step()
        return needs_res

    def _parse_detection_blocks(self, detection_blocks: Dict[str, Any]) -> None:
        """
        Parses the detection blocks of the signature. The blocks are transformed to a directed acyclic graph and stored
        in a dictionary where the detection block key is the key and the graph is the value of the dictionary.
        :param detection_blocks: Detection blocks as parsed from the "detection" section of the dynmx signature.
        """
        detection_block_keys = self.get_detection_block_keys()
        for ix, detection_block_key in enumerate(detection_block_keys):
            detection_block_dict = detection_blocks[detection_block_key]
            detection_block_type = self.condition.get_detection_type_for_block(detection_block_key)
            detection_block_obj = DetectionBlock(detection_block_key, detection_block_type)
            detection_block_obj.parse(detection_block_dict)
            self.detection_blocks[detection_block_key] = detection_block_obj
            self._logger.debug(
                "Successfully parsed detection block with key '{}' ({}/{} detection blocks)".format(
                    detection_block_key, ix+1, len(detection_block_keys)))
    # </editor-fold>

    # <editor-fold desc="Detection">
    def detect(self, flog: FunctionLog) -> DetectionResult:
        """
        Detects the dynmx signature in the function log
        :param flog: FunctionLog object in that the dynmx signature should be detected
        :return: DetectionResult object indicating if the signature was detected in the function log
        """
        self._logger = LoggingHelper.get_logger(__name__, flog_path=flog.file_path)
        detection_result = DetectionResult()
        detected_processes = []
        detection_block_keys = self.get_detection_block_keys()
        # Assertions
        if len(flog.processes) == 0:
            self._logger.warning("Function log has no processes. Detection omitted.")
            detection_result.flog_name = flog.name
            detection_result.flog_path = flog.file_path
            detection_result.signature_name = self.name
            detection_result.signature_path = self.file_path
            detection_result.detected = False
            return detection_result
        if len(detection_block_keys) == 0:
            self._logger.warning(
                "dynmx signature '{}' has no detection blocks. Detection omitted.".format(self.file_path))
            detection_result.flog_name = flog.name
            detection_result.flog_path = flog.file_path
            detection_result.signature_name = self.name
            detection_result.signature_path = self.file_path
            detection_result.detected = False
            return detection_result
        process_count = len(flog.processes)
        self._logger.debug("Function log process count={}".format(process_count))
        # Iterate over all processes that belong to the function log and try to detect the signature in the process
        for process in flog.processes:
            process_findings = self._detect_in_process(process)
            if process_findings:
                detected_processes.append(process_findings)
                if not self.detect_all:
                    break
        # Build detection result object
        detection_result.flog_name = flog.name
        detection_result.flog_path = flog.file_path
        detection_result.signature_name = self.name
        detection_result.signature_path = self.file_path
        # Signature is successfully detected in the function log if at least one process was detected
        sig_detected = len(detected_processes) > 0
        detection_result.detected = sig_detected
        if sig_detected:
            detection_result.detected_processes = detected_processes
        return detection_result

    def _detect_in_process(self, process: Process) -> Optional[DetectedProcess]:
        """
        Detects the dynmx signature in the process
        :param process: Process object in that the signature should be detected
        :return: DetectedProcess object indicating if the dynmx signature was detected in the process
        """
        self.var_storage = VariableStorage()
        detection_block_results = {}
        findings_process = []
        proc_detection_result = DetectedProcess()
        # Iterate over all detection blocks and try to detect them in the process
        try:
            for detection_block_key, detection_block in self.detection_blocks.items():
                self._logger.debug(
                    "Detecting block '{}' in process '{}' ({})".format(
                        detection_block_key, process.name, process.os_id))
                potential_detection_paths = None
                # Only find the possible detection paths if the detection block is not negated in the condition
                # Presence of the API calls in negated detection blocks are not necessary to detect the
                # signature, so omit these blocks in this step
                if not self.condition.is_detection_block_negated(detection_block_key):
                    potential_detection_paths = detection_block.find_detection_paths(process)
                    self._logger.debug(
                        "Possible detection paths in precheck: process={} (PID: {}), key={}, path_count={}".format(
                            process.name, process.os_id, detection_block_key, len(potential_detection_paths)))
                    if not potential_detection_paths:
                        detection_block_results[detection_block_key] = False
                        continue
                # Detect the block in the process with the previously found detection paths
                findings = detection_block.detect(process, self.var_storage, potential_detection_paths)
                if findings:
                    findings_process.append(findings)
                    detection_block_results[detection_block_key] = True
                else:
                    detection_block_results[detection_block_key] = False
                self._logger.debug(
                    "Detection block result: process={} (PID: {}), key={}, result={}".format(
                        process.name, process.os_id, detection_block_key, detection_block_results[detection_block_key]))
            self._logger.debug("Detection block results='{}'".format(detection_block_results))
            # Evaluate condition based on results of detection blocks
            signature_detected = self.condition.evaluate(detection_block_results)
            self._logger.debug(
                "Condition evaluation result: signature={}, process={} (PID {}), result: {})".format(
                    self.name, process.name, process.os_id, signature_detected))
            # Gather information for result
            if not signature_detected:
                proc_detection_result = None
            else:
                proc_detection_result.process_os_id = process.os_id
                proc_detection_result.process_name = process.name
                proc_detection_result.process_cmd_line = process.cmd_line
                proc_detection_result.process_owner = process.owner
                proc_detection_result.process_file_path = process.file_path
                proc_detection_result.findings = findings_process
        except Exception as err:
            self._logger.error(
                "An error occured while detecting block with key '{}'. Omitting detection of process with PID {} ({}). Error message was: '{}'.".format(
                    detection_block_key, process.os_id, hex(process.os_id), err))
            exc_type, exc_value, exc_traceback = sys.exc_info()
            st = traceback.format_exception(exc_type, exc_value, exc_traceback, limit=15)
            self._logger.error("Traceback: {}".format(st))
            proc_detection_result = None
        return proc_detection_result
    # </editor-fold>

    # <editor-fold desc="Helper Methods">
    def get_as_dict(self, include_content: bool = False) -> Dict[str, Any]:
        """
        Returns the signature as dict
        :param include_content: Indicates whether to add the full content of
        the dynmx signature to the result dict
        :return: Representation of the dynmx signature as dictionary
        """
        result_dict = {
            "sig_name": self.name,
            "sig_file_path": self.file_path,
        }
        if include_content:
            result_dict["sig_content"] = self.content
        return result_dict

    def get_detection_block_keys(self) -> Set[str]:
        """
        Returns the detection block keys of a dynmx signature
        :return: Set of detection block keys contained in the dynmx signature
        """
        if self._parsed:
            return set(self.detection_blocks.keys())
        else:
            return set(self._get_detection_block_keys_from_content())

    def _get_detection_block_keys_from_content(self) -> Set[str]:
        """
        Returns the detection block keys from a dynmx signature's content dictionary
        :return: Set of detection block keys contained in the content dictionary
        """
        keys = set(self.content["dynmx_signature"]["detection"].keys())
        excludes = set(["condition"])
        return keys.difference(excludes)
    # </editor-fold>


# <editor-fold desc="Condition Tree">
class Condition:
    """
    Representation of the dynmx signature condition
    """

    def __init__(self, condition_str: str):
        self.condition_str = condition_str
        self.operators = {
            "AND": ['AND', '&'],
            "OR": ['OR', '|'],
            "NOT": ['NOT', '~', '!'],
        }
        self.condition = None
        self.condition_tree = None

    def parse(self) -> None:
        """
        Parses the dynmx signature condition
        :return:
        """
        # Define pyparsing grammar
        not_symbol = pyparsing.Or(
            [pyparsing.CaselessLiteral(sym) for sym in self.operators['NOT']])
        and_symbol = pyparsing.Or(
            [pyparsing.CaselessLiteral(sym) for sym in self.operators['AND']])
        or_symbol = pyparsing.Or(
            [pyparsing.CaselessLiteral(sym) for sym in self.operators['OR']])
        as_symbol = pyparsing.Suppress(pyparsing.CaselessLiteral('AS'))
        operator_precedence_list = [
            (not_symbol, 1, pyparsing.opAssoc.RIGHT,),
            (and_symbol, 2, pyparsing.opAssoc.LEFT,),
            (or_symbol, 2, pyparsing.opAssoc.LEFT,), ]
        detection_block_term = pyparsing.Word(pyparsing.alphanums + "_" + "-")
        detection_type = pyparsing.CaselessLiteral(
            "sequence") | pyparsing.CaselessLiteral("simple")
        detection_term = pyparsing.Group(
            detection_block_term + as_symbol + detection_type)
        condition_expr = pyparsing.operatorPrecedence(detection_term,
                                                      operator_precedence_list)
        # Parse condition
        self.condition = condition_expr.parseString(self.condition_str)
        self.condition = self._strip_condition_array_recursively(
            self.condition)
        # Transform the parsed condition to a tree in order to evaluate the
        # condition better
        self._transform_condition_to_tree()

    def get_detection_type_for_block(self, detection_block_key: str) -> DetectionType:
        """
        Returns the detection type for the given detection block
        :param detection_block_key: Identifies the detection block
        :return: The type of the detection block. If detection block was not
        found False is returned.
        """
        node = self._find_detection_block_node(detection_block_key)
        if node:
            type_str = node.detection_type.lower()
            return DetectionType.from_str(type_str)
        return False

    def has_detection_block(self, detection_block_key: str) -> bool:
        """
        Returns whether the detection block is part of the condition
        :param detection_block_key: Key of the detection block
        :return: Indicates whether the detection block is part of the condition
        """
        return self._find_detection_block_node(detection_block_key) is not False

    def _find_detection_block_node(self, detection_block_key: str) -> GraphNode:
        for node in PreOrderIter(self.condition_tree):
            if type(node) == ConditionLeaf:
                if node.detection_block_key == detection_block_key:
                    return node
        return False

    def is_detection_block_negated(self, detection_block_key: str) -> bool:
        # Find leaf node representing the detection block
        node = self._find_detection_block_node(detection_block_key)
        if not node:
            return False
        # Find "NOT" operator node in the upstream tree of the node
        return self._find_operator_of_node_recursively("NOT", node)

    def _find_operator_of_node_recursively(self, operator: str, start_node: GraphNode) -> bool:
        result = False
        if start_node.parent:
            if type(start_node.parent) == OperatorNode:
                operator_node = start_node.parent
                if operator_node.operator == operator:
                    return True
                else:
                    result = self._find_operator_of_node_recursively(operator, operator_node)
        return result

    def evaluate(self, detection_block_results: List[bool]) -> bool:
        """
        Evaluates the condition
        :param detection_block_results: Results of the detection blocks defined
        in the dynmx signature
        :return: Indicates whether the condition is true
        """
        return self._evaluate_tree_recursively(self.condition_tree,
                                               detection_block_results)

    def _evaluate_tree_recursively(self, tree_node: GraphNode, detection_block_results: List[bool]) -> bool:
        """
        Evaluates the condition tree recursively
        :param tree_node: Tree node to evaluate
        :param detection_block_results: Results of the detection blocks defined
        in the dynmx signature
        :return: Result of the evaluation of the given tree node
        """
        # Empty tree
        if tree_node is None:
            return True
        # Tree node is a leaf
        if tree_node.is_leaf:
            if tree_node.detection_block_key in detection_block_results:
                return detection_block_results[tree_node.detection_block_key]
            else:
                return True
        results = list()
        for node in tree_node.children:
            node_result = self._evaluate_tree_recursively(node, detection_block_results)
            results.append(node_result)
        return self._evaluate_operator_node(tree_node, results)

    def _evaluate_operator_node(self, operator_node: GraphNode, results: List[bool]) -> bool:
        """
        Evaluates an operator node based on the operation defined in the node
        :param operator_node: OperatorNode object to evaluate
        :param results: Result of the evaluation
        :return:
        """
        if operator_node.operator == "NOT":
            return not results[0]
        elif operator_node.operator == "AND":
            operation_result = True
            for node_result in results:
                operation_result &= node_result
            return operation_result
        elif operator_node.operator == "OR":
            operation_result = False
            for node_result in results:
                operation_result |= node_result
            return operation_result
        return True

    def _transform_condition_to_tree(self) -> None:
        """
        Transforms the parsed condition to a tree
        """
        operator = self._get_operator_from_token(self.condition)
        if operator:
            operator_root_node = OperatorNode(operator)
            operands = self._get_operands_from_token(self.condition, operator)
            for operand in operands:
                self._build_subtree_recursively(operator_root_node, operand)
            self.condition_tree = operator_root_node
        elif len(self.condition) == 2:
            leaf_node = ConditionLeaf(self.condition[0], self.condition[1])
            self.condition_tree = leaf_node

    def _strip_condition_array_recursively(self, condition_array: pyparsing.ParseResults) -> pyparsing.ParseResults:
        """
        Strips the condition array
        :param condition_array: Array containing the parsed condition
        :return: Stripped condition array
        """
        if len(condition_array) <= 1:
            stripped_condition_array = self._strip_condition_array_recursively(
                condition_array[0])
            if stripped_condition_array is not None:
                return stripped_condition_array
        else:
            return condition_array

    def _build_subtree_recursively(self, parent: OperatorNode, token: str) -> None:
        """
        Builds the condition subtrees recursively
        :param parent: Parent node
        :param token: Token to build subtree from
        """
        operator = self._get_operator_from_token(token)
        if operator:
            operator_node = OperatorNode(operator, parent=parent)
            operands = self._get_operands_from_token(token, operator)
            for operand in operands:
                self._build_subtree_recursively(operator_node, operand)
        else:
            ConditionLeaf(token[0], token[1], parent)

    def _get_operator_from_token(self, token: str) -> Optional[str]:
        """
        Returns the operator from a condition token
        :param token: Token to return operator from
        """
        for key in self.operators:
            for operator in self.operators[key]:
                if operator in list(token):
                    return key
        return None

    def _get_operands_from_token(self, token: str, operator: str) -> List[str]:
        """
        Returns the operands from a condition token
        :param token: Token to return operands from
        :param operator: Operator in the token that separates operands
        :return: List of operands
        """
        operands = list()
        for sub_token in token:
            if sub_token not in self.operators[operator]:
                operands.append(sub_token)
        return operands

    def _is_operator(self, string_to_check: str) -> bool:
        """
        Checks whether string is an operator
        :param string_to_check: String that should be checked
        :return: Indicates whether given string is an operator
        """
        for key, operators in self.operators:
            if string_to_check.upper() in operators:
                return True
        return False


class OperatorNode(NodeMixin):
    """
    Representation of an operator node in the condition tree
    """

    def __init__(self, operator: str, parent: Optional[OperatorNode] = None):
        super(OperatorNode, self).__init__()
        self.operator = operator
        self.parent = parent

    def __repr__(self):
        return "Operator: {}".format(self.operator)


class ConditionLeaf(NodeMixin):
    """
    Representation of an leaf node in the condition tree
    """

    def __init__(self, detection_block_key: str, detection_type: DetectionType, parent: Optional[OperatorNode] = None):
        super(ConditionLeaf, self).__init__()
        self.detection_block_key = detection_block_key
        self.detection_type = detection_type
        self.parent = parent

    def __repr__(self) -> str:
        return "Leaf: [{}, {}]".format(self.detection_block_key, self.detection_type)
# </editor-fold>


# <editor-fold desc="Detection Graph">
class DetectionBlock:
    """
    Representation of a detection block
    """

    def __init__(self, key: str, detection_type: DetectionType):
        self.key = key
        block_graph = DirectedAcyclicGraph()
        self.graph = block_graph
        self.detection_type = detection_type
        self._logger = LoggingHelper.get_logger(__name__)

    def parse(self, detection_block_dict: Dict[str, Any]) -> None:
        """
        Parses the detection block dictionary to a graph
        :param detection_block_dict: Dictionary of the detection block as defined in the dynmx signature
        """
        self.graph = self._transform_detection_block_to_graph(detection_block_dict)
        self._logger.debug("Detection block graph parsed")
        self._logger.debug("Graph nodes: {}".format(self.graph.get_nodes()))
        self._logger.debug("Graph edges: {}".format(self.graph.get_edges()))

    def has_resource_step(self) -> bool:
        graph_nodes = self.graph.get_nodes()
        for node in graph_nodes:
            if node.step_type == DetectionStepType.RESOURCE:
                return True
        return False

    def _transform_detection_block_to_graph(self, detection_block_dict: List[Dict[str, Any]]) -> DirectedAcyclicGraph:
        """
        Transforms the detection block to a directed acyclic graph
        :param detection_block_dict: The detection block that should be transformed
        :return: DirectedAcyclicGraph object containing the transformed detection block
        """
        graph = self._transform_path_to_graph_recursively(detection_block_dict)
        return graph

    def _transform_path_to_graph_recursively(self, path: List[Dict[str, Any]]) -> DirectedAcyclicGraph:
        """
        Transforms the path recursively to a directed acyclic graph
        :param path: Path to transform
        :return: Graph of the transformed path
        """
        # Create graphs of path
        previous_path_nodes = list()
        graph = DirectedAcyclicGraph()
        # Every step in the path represents a node
        for step in path:
            step_type = list(step.keys())[0].lower()
            # A step with the type "api_call" adds a new node to the graph
            if step_type == "api_call" or step_type == "resource":
                node = self._build_detection_step_obj(step)
                if not previous_path_nodes:
                    graph.add_node(node)
                else:
                    for previous_path_node in previous_path_nodes:
                        graph.add_edge([previous_path_node, node])
                previous_path_nodes = [node]
            # A step with the type "variant" causes a junction in the graph. Remember the junction node and transform
            # the different paths of the variant step to graphs which are concatenated at the junction node to the main
            # graph
            elif step_type == "variant":
                junction_nodes = previous_path_nodes
                paths = step["variant"]
                path_graphs = []
                for path_directive in paths:
                    g = self._transform_path_to_graph_recursively(path_directive["path"])
                    path_graphs.append(g)
                # Concatenate the graphs of the transformed paths to the main graph
                for path_graph in path_graphs:
                    if junction_nodes:
                        for junction_node in junction_nodes:
                            graph.concat(junction_node, path_graph)
                    else:
                        graph.concat(None, path_graph)
                previous_path_nodes = graph.get_end_nodes()
            else:
                raise Exception("Unknown detection step type '{}'".format(step_type))
        return graph

    def _build_detection_step_obj(self, detection_step_dict: Dict[str, Any]) -> Optional[DetectionStep]:
        """
        Builds a detection step object based on detection step type
        :param detection_step_dict: Dictionary containing the detection step configuration
        :return: DetectionStep object
        """
        if DetectionStepType.API_CALL.value in detection_step_dict.keys():
            obj = self._build_api_call_detection_step_obj(detection_step_dict)
        elif DetectionStepType.RESOURCE.value in detection_step_dict.keys():
            obj = self._build_resource_detection_step_obj(detection_step_dict)
        else:
            raise NotImplementedError("Unknown detection step type")
        return obj

    def _build_api_call_detection_step_obj(self, detection_step_dict: Dict[str, Any]) -> Optional[APICallDetectionStep]:
        """
        Builds an API call detection step object
        :param detection_step_dict: Dictionary containing the detection step configuration
        :return: APICallDetectionStep object
        """
        if DetectionStepType.API_CALL.value not in detection_step_dict.keys():
            return None
        function_names = detection_step_dict["api_call"]
        step = APICallDetectionStep(function_names=function_names)
        if "limit" in detection_step_dict.keys():
            step.limit = detection_step_dict["limit"]
        if "min_occurrence" in detection_step_dict.keys():
            step.min_occurrence = detection_step_dict["min_occurrence"]
        if "with" in detection_step_dict.keys():
            with_conditions = self._build_with_condition_objs(detection_step_dict["with"])
            step.with_conditions = with_conditions
        if "store" in detection_step_dict.keys():
            store_directives = self._build_store_directive_objs(detection_step_dict["store"])
            step.store_directives = store_directives
        return step

    def _build_resource_detection_step_obj(self, detection_step_dict: Dict[str, Any]) \
            -> Optional[ResourceDetectionStep]:
        """
        Builds a resource detection step object
        :param detection_step_dict: Dictionary containing the detection step configuration
        :return: ResourceDetectionStep object
        """
        if DetectionStepType.RESOURCE.value not in detection_step_dict.keys():
            return None
        if "category" not in detection_step_dict.keys():
            return None
        category = detection_step_dict["category"]
        step = ResourceDetectionStep(category=category)
        if "access_operations" in detection_step_dict.keys():
            access_ops = detection_step_dict["access_operations"]
            parsed_access_ops = set()
            if not isinstance(access_ops, list):
                access_ops = [access_ops]
            for op in access_ops:
                parsed_op = AccessType.get_entry_by_str(op)
                if parsed_op:
                    parsed_access_ops.add(parsed_op)
            step.access_operations = list(parsed_access_ops)
        if "with" in detection_step_dict.keys():
            with_conditions = self._build_with_condition_objs(detection_step_dict["with"])
            step.with_conditions = with_conditions
        if "store" in detection_step_dict.keys():
            store_directives = self._build_store_directive_objs(detection_step_dict["store"])
            step.store_directives = store_directives
        return step

    def _build_with_condition_objs(self, with_conditions_dict: List[Dict[str, Any]]) -> List[WithCondition]:
        """
        Builds with condition objects based on the with conditions defined in the detection step
        :param with_conditions_dict: List of dictionaries containing the defined with conditions in the detection step
        :return: List of WithCondition objects
        """
        conditions = list()
        for condition_dict in with_conditions_dict:
            if "argument" in condition_dict.keys():
                condition_obj = WithCondition(WithConditionType.ARGUMENT)
                condition_obj.arguments = condition_dict["argument"]
            elif "return_value" in condition_dict.keys():
                condition_obj = WithCondition(WithConditionType.RETURN)
                if condition_dict["return_value"] != "return":
                    condition_obj.arguments = condition_dict["argument"]
            elif "attribute" in condition_dict.keys():
                condition_obj = WithCondition(WithConditionType.ATTRIBUTE)
                condition_obj.arguments = condition_dict["attribute"]
            else:
                self._logger.warning("Could not parse with condition (condition dictionary: '{}')".format(
                    condition_dict))
            if type(condition_obj.arguments) is not list:
                condition_obj.arguments = [condition_obj.arguments]
            if "operation" in condition_dict.keys():
                condition_obj.operation = condition_dict["operation"].lower()
            if "value" in condition_dict.keys():
                condition_obj.values = condition_dict["value"]
                if type(condition_obj.values) is not list:
                    condition_obj.values = [condition_obj.values]
            if "type" in condition_dict.keys():
                arg_types = condition_dict["type"]
                if type(arg_types) is not list:
                    arg_types = [arg_types]
                condition_obj.is_in = True if "in" in arg_types else None
                condition_obj.is_out = True if "out" in arg_types else None
            conditions.append(condition_obj)
        return conditions

    @staticmethod
    def _build_store_directive_objs(store_directives_dict: List[Dict[str, Any]]) -> List[StoreDirective]:
        """
        Build store directive objects based on the store directives defined in the detection step
        :param store_directives_dict: List of store directives defined in the detection step
        :return: List of StoreDirective objects
        """
        store_directives = list()
        for store_directive_dict in store_directives_dict:
            if "name" not in store_directive_dict.keys():
                raise Exception("Store directive could not be parsed. Attribute 'name' not found in directive.")
            if "as" not in store_directive_dict.keys():
                raise Exception("Store directive could not be parsed. Attribute 'as' not found in directive.")
            store_directive = StoreDirective(store_directive_dict["name"], store_directive_dict["as"])
            if "is_in" in store_directive_dict.keys():
                store_directive.is_in = store_directive_dict["is_in"]
            if "is_out" in store_directive_dict.keys():
                store_directive.is_out = store_directive_dict["is_out"]
            store_directives.append(store_directive)
        return store_directives

    def find_detection_paths(self, process: Process) -> List[List[DetectionStep]]:
        """
        Finds possible detection paths based on the detection steps and the processes' API calls
        :param process: Process object to find the detection paths in
        :return:
        """
        # Predict possible API call combinations by finding all paths of the graph and correlating them with the
        # processes API calls based on the API call function name
        combinations = self.graph.find_all_paths()
        possible_detection_paths = []
        for combination in combinations:
            result = False
            for node in combination:
                if node.step_type == DetectionStepType.API_CALL:
                    result = node.detect_function_name_in_process(process)
                    if not result:
                        break
                elif node.step_type == DetectionStepType.RESOURCE:
                    result = True
            if result:
                possible_detection_paths.append(combination)
        # If the detection block should be detected as sequence the path has to be unfolded
        # Unfolding means that every detection step has to reproduced that has a min_occurence > 1
        if self.detection_type == DetectionType.SEQ:
            possible_detection_paths = self._unfold_detection_paths(possible_detection_paths)
        return possible_detection_paths

    @staticmethod
    def _unfold_detection_paths(detection_paths: List[List[DetectionStep]]) -> List[List[DetectionStep]]:
        """
        Unfolds the detection paths by duplicating nodes that have a higher min_occurence than 1
        :param detection_paths: List of detection paths that should be unfolded
        :return: List of unfolded detection paths
        """
        unfolded_paths = list()
        for path in detection_paths:
            unfolded_path = list()
            for step in path:
                if step.step_type == DetectionStepType.API_CALL:
                    unfolded_path += repeat(step, step.min_occurrence)
                elif step.step_type == DetectionStepType.RESOURCE:
                    unfolded_path.append(step)
            unfolded_paths.append(unfolded_path)
        return unfolded_paths

    def detect(self, process: Process, var_storage: VariableStorage,
               potential_detection_paths: Optional[List[List[DetectionStep]]] = None) -> DetectedBlock | bool:
        """
        Detects the detection block in the given process
        :param process: Process to detect the detection block in
        :param var_storage: VariableStorage of the signature
        :param potential_detection_paths: Previously found detection paths
        :return: DetectedBlock object if the detection was successful, False if the detection was not successful
        """
        self._logger = LoggingHelper.get_logger(__name__, flog_path=process.flog_path)
        self._logger.debug("Detecting block: key={}, type={}".format(self.key, self.detection_type))
        # Check whether the detection block should be detected as simple or sequence and call the corresponding method
        if self.detection_type == DetectionType.SIMPLE:
            return self._detect_simple(process, var_storage, potential_detection_paths)
        elif self.detection_type == DetectionType.SEQ:
            return self._detect_sequence(process, var_storage, potential_detection_paths)
        # Return False if the detection type is unknown
        else:
            return False

    def _detect_simple(self, process: Process, var_storage: VariableStorage,
                       potential_detection_paths: Optional[List[List[DetectionStep]]] = None) -> DetectedBlock | bool:
        """
        Detects a simple detection block
        :param process: Process to detect the detection block in
        :param var_storage: VariableStorage of the signature
        :param potential_detection_paths: Previously found detection paths
        :return: DetectedBlock object if the detection was successful, False if the detection was not successful
        """
        flog_path = process.flog_path
        # Check all detection paths if no detection paths were determined in advance
        if not potential_detection_paths:
            potential_detection_paths = self.graph.find_all_paths()
        detection_result = DetectedBlock()
        # Iterate over the potential detection paths and try to detect them
        detected_api_calls = list()
        detected_resources = list()
        detected = False
        for detection_path in potential_detection_paths:
            self._logger.debug("Detection path: {}".format(detection_path))
            detected_api_calls_in_path = list()
            detected_res_in_path = list()
            path_detected = True
            # Iterate over all steps in the detection path and try to detect the steps
            # The path is successfully detected if all steps in the path are detected
            for step in detection_path:
                step_detected = False
                if step.step_type == DetectionStepType.API_CALL:
                    candidates = self._reduce_api_calls(flog_path, process, detection_path)
                    self._logger.debug("Candidate Len={}".format(len(candidates)))
                    step_detected = False
                    occurrence_counter = 0
                    for candidate in candidates:
                        candidate_detected = step.detect(flog_path, candidate, var_storage)
                        if candidate_detected:
                            detected_api_calls_in_path.append(candidate)
                            occurrence_counter += 1
                        # The detection step is successfully detected if the min occurrence count of the step is reached
                        step_detected |= occurrence_counter >= step.min_occurrence
                elif step.step_type == DetectionStepType.RESOURCE:
                    candidates = process.aam.get_resources_by_category(step.category)
                    for candidate in candidates:
                        candidate_detected = step.detect(flog_path, candidate, var_storage)
                        if candidate_detected:
                            step_detected = True
                            detected_res_in_path.append(candidate)
                            break
                if not step_detected:
                    path_detected = False
                    break
            if path_detected:
                for api_call in detected_api_calls_in_path:
                    if api_call not in detected_api_calls:
                        detected_api_calls.append(api_call)
                for resource in detected_res_in_path:
                    if resource not in detected_resources:
                        detected_resources.append(resource)
            detected |= path_detected
        detection_result.detection_block_key = self.key
        detection_result.api_calls = detected_api_calls
        detection_result.resources = detected_resources
        return detection_result if detected else False

    def _detect_sequence(self, process: Process, var_storage: VariableStorage,
                         potential_detection_paths: List[List[DetectionStep]]) -> DetectedBlock | bool:
        """
        Detects a sequence detection block
        :param process: Process to detect the detection block in
        :param var_storage: VariableStorage of the signature
        :param potential_detection_paths: Previously found detection paths
        :return: DetectedBlock object if the detection was successful, False if the detection was not successful
        """
        flog_path = process.flog_path
        # Check all detection paths if no detection paths were determined in advance
        if not potential_detection_paths:
            potential_detection_paths = self.graph.find_all_paths()
        detection_result = DetectedBlock()
        # Iterate over the potential detection paths and try to detect them
        detected_api_calls = list()
        detected_resources = list()
        detected = False
        for detection_path in potential_detection_paths:
            self._logger.debug("Detection path={}".format(detection_path))
            self._logger.debug("Detection path length={}".format(len(detection_path)))
            # Get API call detection steps for detecting API call sequence
            api_detection_path = self._get_detection_steps_by_type(DetectionStepType.API_CALL, detection_path)
            # Find suitable API call candidates by their function name based on the steps in the detection path
            reduced_api_calls = self._reduce_api_calls(flog_path, process, api_detection_path)
            if len(api_detection_path) and len(reduced_api_calls):
                # Calculate the longest common subsequence between the API call candidates and the detection path
                detected_sequence = self._find_lcs(flog_path, reduced_api_calls, api_detection_path, var_storage)
                self._logger.debug("LCS length={}".format(len(detected_sequence)))
                self._logger.debug("LCS={}".format(detected_sequence))
                # The detection path is successfully detected if the longest common subsequence has the length of the
                # detection path
                path_detected = len(detected_sequence) == len(api_detection_path)
            else:
                path_detected = False
            # Detect resources
            resource_detection_path = self._get_detection_steps_by_type(DetectionStepType.RESOURCE, detection_path)
            if len(resource_detection_path):
                detected_res = self._detect_resources(process, resource_detection_path, var_storage)
                path_detected &= len(detected_res) > 0
            else:
                detected_res = []
            if path_detected:
                # Add the API calls of the detected sequence to the list of detected API calls for this block if
                # the detection was successful
                for api_call in detected_sequence:
                    if api_call not in detected_api_calls:
                        detected_api_calls.append(api_call)
                for resource in detected_res:
                    if resource not in detected_resources:
                        detected_resources.append(resource)
                self._logger.debug("Path detected in process {} (PID: {})".format(process.name, process.os_id))
            else:
                self._logger.debug("Path not detected in process {} (PID: {})".format(process.name, process.os_id))
            detected |= path_detected
        # Build the DetectedBlock object
        detection_result.detection_block_key = self.key
        detection_result.api_calls = detected_api_calls
        detection_result.resources = detected_resources
        return detection_result if detected else False

    @staticmethod
    def _detect_resources(process: Process, detection_path: List[DetectionStep], var_storage: VariableStorage) \
            -> List[Resource]:
        """
        Detects resources referenced in the given detection path in the given process
        :param process: Process object to detect the resources of the detection path in
        :param detection_path: Detection path consisting out of detection steps
        :param var_storage: Variable storage of the signature
        :return: List of detected resources
        """
        detected_resources = list()
        for step in detection_path:
            if step.step_type == DetectionStepType.RESOURCE:
                candidates = process.aam.get_resources_by_category(step.category)
                for candidate in candidates:
                    candidate_detected = step.detect(process.file_path, candidate, var_storage)
                    if candidate_detected:
                        detected_resources.append(candidate)
        return detected_resources

    @staticmethod
    def _get_detection_steps_by_type(step_type: DetectionStepType, detection_path: List[DetectionStep]) \
            -> List[DetectionStep]:
        """
        Returns a list of detection steps with the given type from a detection path
        :param step_type: Type of the detection step
        :param detection_path: Detection path consisting out of detection steps
        :return: List of detection steps with the given type
        """
        api_path = list()
        for step in detection_path:
            if step.step_type == step_type:
                api_path.append(step)
        return api_path

    @staticmethod
    def _get_variable_contexts(flog_path: str, api_calls: List[APICall], detection_path: List[DetectionStep]) \
            -> Optional[List[Tuple[Any, Any]]]:
        """
        Calculates possible variable contexts based on the API call candidates and the detection path
        :param flog_path: Path to the function log
        :param api_calls: List of API call candidates for the detection path
        :param detection_path: Detection path consisting out of detection steps
        :return: Possible variable contexts based on the API call candidates and the detection path
        """
        variable_stores = {}
        reduced_detection_path = []
        # Reduce the detection path to the steps that store variables
        for step in detection_path:
            if step.step_type == DetectionStepType.API_CALL:
                if step.stores_variables():
                    reduced_detection_path.append(step)
        # For this reduced detection path extract the API calls that store certain variables
        temp_var_storage = VariableStorage()
        for ix, api_call in enumerate(api_calls):
            for ic, step in enumerate(reduced_detection_path):
                variable_stores_per_step = {}
                if step.detect(flog_path, api_call, temp_var_storage):
                    variables = step.get_variables(api_call)
                    if ix in variable_stores_per_step:
                        for var_name, value in variables.items():
                            variable_stores_per_step[ix][var_name] = value
                    else:
                        variable_stores_per_step[ix] = variables
                    if ic not in variable_stores.keys():
                        variable_stores[ic] = [variable_stores_per_step]
                    else:
                        variable_stores[ic].append(variable_stores_per_step)
        # For each detection step calculate all combinations of the API calls that store variables
        var_store_per_step = {}
        for step_id, var_store in variable_stores.items():
            var_store_per_step_per_name = {}
            for e in var_store:
                for api_call_index, stored_variables in e.items():
                    for var_name in stored_variables.keys():
                        if var_name not in var_store_per_step_per_name:
                            var_store_per_step_per_name[var_name] = set()
                            var_store_per_step_per_name[var_name].add(api_call_index)
                        else:
                            var_store_per_step_per_name[var_name].add(api_call_index)
            if var_store_per_step_per_name:
                var_store_per_step[step_id] = var_store_per_step_per_name
        # Find all unique sets per detection step, each set represents the API call indices that access a
        # certain variable
        api_call_sets_per_step = {}
        for step_id, var_store in var_store_per_step.items():
            for var_name, api_call_indices in var_store.items():
                if step_id not in api_call_sets_per_step.keys():
                    api_call_sets_per_step[step_id] = [api_call_indices]
                else:
                    if api_call_indices not in api_call_sets_per_step[step_id]:
                        api_call_sets_per_step[step_id].append(api_call_indices)
        result_sets = list()
        for step_id, api_call_sets in api_call_sets_per_step.items():
            result_sets += api_call_sets
        # The contexts are the cartesian product of all resulting sets
        variable_contexts = list(product(*result_sets))
        # Deduplicate contexts
        variable_contexts_dedup = list(set([tuple(set(i)) for i in variable_contexts]))
        if variable_contexts_dedup and variable_contexts_dedup[0]:
            variable_contexts_dedup.sort(key=lambda tup: tup[0])
            return variable_contexts_dedup
        return None

    def _find_lcs(self, flog_path: str, api_calls: List[APICall], detection_path: List[DetectionStep],
                  var_storage: VariableStorage) -> List[APICall]:
        """
        Finds the longest common subsequence between the API calls and the detection path
        :param api_calls: Reduced function log of process
        :param detection_path: Detection path
        :param var_storage: Variable storage object
        :return: Sequence of detected API calls
        """
        # Calculate LCS length
        # LCS length is found in the result matrix c in index c[len(api_calls)][len(detection_path)]
        var_contexts = self._get_variable_contexts(flog_path, api_calls, detection_path)
        # If there are variable contexts, calculate LCS matrix for each context
        if var_contexts:
            var_context_len = len(var_contexts)
            self._logger.info("Found {} contexts".format(var_context_len))
            self._logger.info(
                "Len detection path={}, Len API calls={}".format(len(detection_path), len(api_calls)))
            # Traverse list of contexts from beginning and end and meet in the middle to reduce detection run time
            mid = (var_context_len + 1) // 2
            for combination in zip(var_contexts[:mid], var_contexts[::-1]):
                context_found = False
                for context in combination:
                    c = self._calculate_lcs_matrix_for_var_context(flog_path, api_calls, detection_path, var_storage,
                                                                   context)
                    lcs_length = c[-1][-1]
                    # We can stop the detection if a certain context produces a matrix that reflects the length of the
                    # detection path
                    self._logger.info("LCS Length={}".format(lcs_length))
                    if lcs_length == len(detection_path):
                        context_found = True
                        break
                if context_found:
                    break
        else:
            self._logger.info(
                "Len detection path={}, Len API calls={}".format(len(detection_path), len(api_calls)))
            # If no variable contexts are available calculate the LCS without considering variable contexts
            c = self._calculate_lcs_matrix(flog_path, api_calls, detection_path, var_storage)
        # Extract the detected sequence from the calculated matrix
        detected_sequence = self._extract_lcs(c, api_calls, detection_path)
        return detected_sequence

    @staticmethod
    def _calculate_lcs_matrix(flog_path: str, api_calls: List[APICall], detection_path: List[DetectionStep],
                              var_storage: VariableStorage) -> List[List[int]]:
        """
        Calculates the LCS matrix
        :param flog_path: Function log path
        :param api_calls: Reduced function log of process
        :param detection_path: Detection path
        :param var_storage: Variable storage object
        :return: LCS matrix
        """
        # Calculate LCS matrix
        # LCS length is found in the result matrix c in index c[len(api_calls)][len(detection_path)]
        # See https://en.wikipedia.org/wiki/Longest_common_subsequence_problem for algorithm
        # See https://rosettacode.org/wiki/Longest_common_subsequence#Python for implementation
        c = [[0] * (len(detection_path) + 1) for _ in range(len(api_calls) + 1)]
        last_detected_index = None
        for i, api_call in enumerate(api_calls):
            for j, step in enumerate(detection_path):
                if step.detect(flog_path, api_call, var_storage, last_detected_index):
                    c[i + 1][j + 1] = c[i][j] + 1
                    last_detected_index = api_call.index
                else:
                    c[i + 1][j + 1] = max(c[i + 1][j], c[i][j + 1])
        return c

    @staticmethod
    def _calculate_lcs_matrix_for_var_context(flog_path: str, api_calls: List[APICall],
                                              detection_path: List[DetectionStep], var_storage: VariableStorage,
                                              context: Tuple[Any, Any]) -> List[List[int]]:
        """
        Calculates the LCS matrix for a given variable context
        :param flog_path: Function log path
        :param api_calls: Reduced function log of process
        :param detection_path: Detection path
        :param var_storage: Variable storage object
        :param context: Variable context
        :return: LCS matrix for the given variable context
        """
        c = [[0] * (len(detection_path) + 1) for _ in range(len(api_calls) + 1)]
        last_detected_index = None
        for i, api_call in enumerate(api_calls):
            for j, step in enumerate(detection_path):
                # If the current step stores variables and the current API call is part of the context, detect the
                # step otherwise skip the detection to not alter variables for this context
                if step.stores_variables():
                    if i in context:
                        if step.detect(flog_path, api_call, var_storage, last_detected_index):
                            c[i + 1][j + 1] = c[i][j] + 1
                            last_detected_index = api_call.index
                        else:
                            c[i + 1][j + 1] = max(c[i + 1][j], c[i][j + 1])
                    else:
                        c[i + 1][j + 1] = max(c[i + 1][j], c[i][j + 1])
                # If the step does not store variables, we can safely detect the step
                else:
                    if step.detect(flog_path, api_call, var_storage, last_detected_index):
                        c[i + 1][j + 1] = c[i][j] + 1
                        last_detected_index = api_call.index
                    else:
                        c[i + 1][j + 1] = max(c[i + 1][j], c[i][j + 1])
        return c

    @staticmethod
    def _extract_lcs(c: List[List[int]], api_calls: List[APICall], detection_path: List[DetectionStep]) \
            -> List[APICall]:
        """
        Extracts the LCS API call sequence from the LCS matrix c
        :param c: LCS matric
        :param api_calls: Reduced function log
        :param detection_path: Detection path
        :return: LCS sequence
        """
        # Reconstruct the detected sequence based on the LCS matrix
        # Go diagonal through the matrix beginning from the last element and find the first element in the column that
        # has a lower value than the previously found length; the first element that has a lower value is a member of
        # the longest common subsequence
        detected_sequence = []
        i = len(api_calls)
        j = len(detection_path)
        last_length = c[-1][-1]
        while j > 0:
            while i > 0:
                if c[i-1][j] == last_length-1:
                    detected_sequence.append(api_calls[i - 1])
                    i -= 1
                    last_length -= 1
                    break
                i -= 1
            j -= 1
        detected_sequence.reverse()
        return detected_sequence

    def _reduce_api_calls(self, flog_path: str, process: Process, detection_path: List[DetectionStep]) \
            -> List[APICall]:
        """
        Reduces the process's list of API calls based on the function names in the detection path
        :param process: Process object of that the API calls should be reduced
        :param detection_path: Detection path (list of DetectionStep objects)
        :return: List of APICall objects that were reduced based on the detection path
        """
        reduced_api_calls = dict()
        temp_var_storage = VariableStorage()
        # Find suitable candidates for every detection step and add them to a list
        for step in detection_path:
            if step.step_type == DetectionStepType.API_CALL:
                candidates = self._get_api_call_candidates(process, step)
                for candidate in candidates:
                    if not step.accesses_variables():
                        if step.detect(flog_path, candidate, temp_var_storage):
                            if candidate.index not in reduced_api_calls.keys():
                                reduced_api_calls[candidate.index] = candidate
                    else:
                        if candidate.index not in reduced_api_calls.keys():
                            reduced_api_calls[candidate.index] = candidate
        # Sort the list by the API call index
        reduced_api_calls = list(reduced_api_calls.values())
        reduced_api_calls.sort(key=lambda x: x.index)
        return reduced_api_calls

    @staticmethod
    def _get_api_call_candidates(process: Process, step: DetectionStep) -> List[APICall]:
        """
        Returns a list of API call candidates from the process based on the detection step's function name
        :param process: Process object
        :param step: DetectionStep object
        :return: List of APICall objects
        """
        candidates = []
        for fname in step.function_names:
            api_calls = process.get_api_calls_by_name(fname, is_regex_pattern=RegexHelper.is_regex_pattern(fname))
            candidates += api_calls
        return candidates


class DetectionType(Enum):
    """
    Enum that defines the detection types
    """
    SIMPLE = "simple"
    SEQ = "sequence"

    @classmethod
    def from_str(cls, type_str: str) -> DetectionType:
        """
        Parses the detection type from a string
        :param type_str: String to parse
        :return: DetectionType object
        """
        if type_str.lower() == "simple":
            return DetectionType.SIMPLE
        elif type_str.lower() == "sequence":
            return DetectionType.SEQ

# </editor-fold>


# <editor-fold desc="Variable Storage">
class StoreDirective:
    """
    Representation of a store directive
    """

    def __init__(self, argument: str, var_name: str, is_out: Optional[bool] = None, is_in: Optional[bool] = None):
        self.argument = argument
        self.var_name = var_name
        self.is_out = is_out
        self.is_in = is_in


class VariableStorage:
    """
    Representation of a simple storage for variables
    """

    def __init__(self):
        self._var_storage = {}

    def store(self, variable_name: str, value: Any) -> None:
        """
        Stores the variable in the variable storage
        :param variable_name: Name of the variable
        :param value: Value of the variable
        :return:
        """
        # value_obj = VariableValue(value=value)
        # if api_call_index:
        #     value_obj.add_access(api_call_index)
        # if variable_name not in self._var_storage.keys():
        #     self._var_storage[variable_name] = [value_obj]
        # else:
        #     self._var_storage[variable_name].append(value_obj)
        self._var_storage[variable_name] = value

    def get_variable_value(self, variable_name: str) -> Any:
        """
        Returns the variable value from the variable storage
        :param variable_name: Name of the variable
        :return:
        """
        if variable_name not in self._var_storage.keys():
            return None
        return self._var_storage[variable_name]


# </editor-fold>

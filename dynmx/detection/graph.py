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
from typing import Optional, List


class DirectedAcyclicGraph:
    """
    Representation of a directed acyclic graph (DAG)
    """

    def __init__(self):
        self._graph = {}
        self.start_nodes = list()

    def get_nodes(self) -> List[GraphNode]:
        """
        Returns the nodes of the graph
        :return: List containing the nodes of the graph
        """
        return list(self._graph.keys())

    def get_edges(self) -> List[List[GraphNode]]:
        """
        Returns the directed edges of the graph
        :return: List of tuples containing the edges of the graph. Index 0 contains the start node, index 1 the end
        node of the edge.
        """
        return self._generate_edges()

    def get_end_nodes(self) -> List[GraphNode]:
        """
        Returns the end nodes of the graph. End nodes are indicated by having no neighbours.
        :return: List of end nodes of the graph
        """
        # End nodes have no neighbours
        end_nodes = list()
        for key, node in self._graph.items():
            if not node.has_neighbours():
                end_nodes.append(node)
        return end_nodes

    def add_node(self, node: GraphNode) -> None:
        """
        Adds a node to the graph
        :param node: GraphNode that should be added
        """
        if not isinstance(node, GraphNode):
            return
        # Graph is empty; set start_node and add node to graph
        if not self.start_nodes:
            self.start_nodes.append(node)
            self._graph[node] = node
        # Graph is not empty
        elif node not in self._graph.keys():
            self._graph[node] = node

    def add_edge(self, edge: GraphNode) -> None:
        """
        Adds an edge to the graph
        :param edge: Tuple containing two GraphNode objects. Index 0 is the start node, index 1 the end node of the edge
        """
        if len(edge) != 2:
            return
        start_node = edge[0]
        end_node = edge[1]
        if not isinstance(start_node, GraphNode) or not isinstance(end_node, GraphNode):
            return
        if start_node == end_node:
            return
        if start_node in self._graph.keys():
            self._graph[start_node].add_neighbour(end_node)
        else:
            self.add_node(start_node)
            self._graph[start_node].add_neighbour(end_node)
        if end_node not in self._graph.keys():
            self.add_node(end_node)

    def concat(self, junction_node: GraphNode, graph: DirectedAcyclicGraph) -> None:
        """
        Concatenates two graphs on a defined junction node
        :param junction_node: GraphNode object to that the graph should be concatenated
        :param graph: DirectedAcyclicGraph object that should be concatenated
        """
        # Junction node is not part of graph
        if junction_node:
            if junction_node not in self._graph.keys():
                return
        # Add edge from junction node to start node of graph that should be added
        for start_node in graph.start_nodes:
            if junction_node:
                self.add_edge([junction_node, start_node])
            else:
                self.start_nodes.append(start_node)
        # Add all nodes of the added graph
        for node in graph.get_nodes():
            if node not in self._graph.keys():
                self._graph[node] = node

    def find_all_paths(self) -> List[List[GraphNode]]:
        """
        Finds all paths from the start nodes to the end nodes of the graph
        :return: List containing all paths of the graph
        """
        all_paths = []
        # Iterate over all start nodes and find the paths to end nodes beginning from these start nodes recursively
        for start_node in self.start_nodes:
            paths = self._find_all_paths_recursively(start_node)
            if paths:
                all_paths += paths
        return all_paths

    def _find_all_paths_recursively(self, start_node: GraphNode, path: List[GraphNode] = []):
        """
        Recursively finds the paths beginning from the start node
        :param start_node: Node to start the path search from
        :param path: Found path
        :return: Paths found beginning from the start node
        """
        path = path.copy() + [start_node]
        if not start_node.has_neighbours():
            return [path]
        if start_node not in self._graph.keys():
            return []
        # Visit every neighbour of the start node
        paths_from_start = []
        for neighbour in start_node.get_neighbours():
            if neighbour not in path:
                new_paths = self._find_all_paths_recursively(neighbour, path)
                for new_path in new_paths:
                    paths_from_start.append(new_path)
        return paths_from_start

    def _generate_edges(self) -> List[List[GraphNode]]:
        """
        Generates the edges of the path based on the nodes and their neighbours
        :return: List of edges
        """
        edges = list()
        # Iterate over all nodes in the graph and find their neighbours
        # Every neighbour of a give node results in a new edge
        for node in self._graph:
            for neighbour in self._graph[node].get_neighbours():
                edge = [node, neighbour]
                edges.append(edge)
        return edges


class GraphNode:
    """
    Representation of a generic graph node
    """

    def __init__(self, neighbours: Optional[List[GraphNode]] = None):
        if not neighbours:
            neighbours = list()
        self._neighbours = neighbours

    def get_neighbours(self) -> List[GraphNode]:
        """
        Returns the neighbours of the node
        :return: List of neighbours of the node
        """
        return self._neighbours

    def add_neighbour(self, neighbour_node: GraphNode) -> None:
        """
        Adds a neighbour to the node
        :param neighbour_node: GraphNode object that should be added as neighbour
        """
        if neighbour_node not in self._neighbours:
            self._neighbours.append(neighbour_node)

    def has_neighbours(self) -> bool:
        """
        Indicates whether the node has neighbours
        :return: Bool indicating whether the node has neighbours
        """
        return len(self._neighbours) > 0

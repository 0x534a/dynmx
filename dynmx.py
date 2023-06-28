#!/bin/python

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
from typing import Any, Optional, TYPE_CHECKING, List
import logging
import sys
import traceback
import time
import dynmx
import os
from itertools import repeat

import dynmx.flog_parsers
from dynmx.core.statistics import Statistics
from dynmx.detection.signature import Signature
from dynmx.flog_parsers.parser_library import ParserLibrary
from dynmx.helpers.argument_helper import ArgumentHelper
from dynmx.helpers.logging_helper import LoggingHelper
import dynmx.helpers.logging_globals
from dynmx.helpers.multiprocessing_helper import MultiprocessingHelper
from dynmx.converters.dynmx_converter import DynmxConverter
from dynmx.helpers.output_helper import OutputHelper, OutputType

# Avoid cyclic imports
if TYPE_CHECKING:
    from dynmx.detection.detection_result import DetectionResult
    from dynmx.core.function_log import FunctionLog

__version__ = "0.5 (PoC)"
LOGGER = None
OUTPUT_HELPER = None


def main(argv: Any) -> None:
    """
    Main entry point of the script
    """
    try:
        # Handle parameters
        arg_helper = ArgumentHelper()
        args = arg_helper.handle()
    except Exception as e:
        OutputHelper.render_error("Fatal exception while handling parameters. Error message: {}. Exiting.".format(e))
        sys.exit(1)

    global LOGGER
    global OUTPUT_HELPER
    try:
        run_start = time.perf_counter()
        OUTPUT_HELPER = OutputHelper(args.show_log, OutputType.get_entry_by_str(args.format))
        OUTPUT_HELPER.render_header(__version__)
        # Set up logging
        logging_thread = LoggingHelper.set_up_logging(
            log_level=getattr(logging, args.log_level.upper()),
            logfile=args.log,
            show_console_log=args.show_log
        )
        LOGGER = LoggingHelper.get_logger(__name__)
        LOGGER.info("Start of dynmx run")
        # Set up multiprocessing
        MultiprocessingHelper.set_up()
        # Load available parsers
        parser_lib = ParserLibrary()
        parser_lib.load(dynmx.flog_parsers)
        # Do actions based on given command
        command_output = ""
        LOGGER.debug("Command: {}".format(args.command))
        if args.command == "detect":
            detection_results = handle_detect_command(
                args.input,
                args.sig,
                parser_lib,
                args.recursive,
                getattr(logging, args.log_level.upper()),
                num_of_workers=args.worker,
                detect_all=args.detect_all
            )
            # Write JSON-formatted detection result file
            if args.json_result:
                OUTPUT_HELPER.write_detection_json_result_file(args.json_result, detection_results)
                LOGGER.info("Detection results written to file '{}'".format(args.json_result.name))
            if args.runtime_result:
                OUTPUT_HELPER.write_runtime_result_file(args.runtime_result, detection_results)
                LOGGER.info("Runtime statistics written to file '{}'".format(args.runtime_result.name))
            command_output = OUTPUT_HELPER.render_detection_output_str(detection_results)
        elif args.command == "check":
            check_results = handle_check_command(args.sig)
            command_output = OUTPUT_HELPER.render_check_output_str(check_results)
        elif args.command == "convert":
            handle_convert_command(
                args.input,
                parser_lib,
                args.output_dir,
                not args.nocompress,
                args.recursive,
                getattr(logging, args.log_level.upper()),
                args.worker
            )
        elif args.command == "stats":
            stats_objs = handle_stats_command(args.input, parser_lib, args.recursive)
            command_output = OUTPUT_HELPER.render_stats_output_str(stats_objs)
        elif args.command == "resources":
            flogs = handle_resources_command(args.input, parser_lib, args.recursive)
            command_output = OUTPUT_HELPER.render_resources_output_str(flogs)
        run_end = time.perf_counter()
        runtime = run_end - run_start
        LOGGER.info("Run took {:.4f}s".format(runtime))
        LoggingHelper.shutdown_log()
        # Print results
        print(command_output)
        sys.exit(0)
    except Exception as ex:
        err_message = "A fatal error occurred. Error message: '{}'. Exiting.".format(ex)
        LOGGER.error(err_message)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        st = traceback.format_exception(exc_type, exc_value, exc_traceback, limit=10)
        LOGGER.error("Traceback: {}".format(st))
        OUTPUT_HELPER.render_error(err_message)
        sys.exit(1)
    finally:
        if logging_thread:
            logging_thread.terminate_logger()


def handle_detect_command(input_files: List[str], signature_files: List[str], parser_lib: ParserLibrary,
                          recursive: bool, log_level: int, num_of_workers: Optional[int] = None,
                          detect_all: bool = False) -> List[DetectionResult]:
    """
    Handler of the 'detect' command; uses multiprocessing to enhance detection runtime
    :param input_files: List of input files
    :param signature_files: List of signature files to use for the detection
    :param parser_lib: Parser library object
    :param recursive: Indicates whether to search recursively for input files
    :param log_level: Log level
    :param num_of_workers: Number of workers to use for the detection
    :param detect_all: Indicates whether detection should happen in all processes
    :return: Detection results
    """
    # Prepare signatures
    signatures = []
    resources_needed = False
    for signature_path in signature_files:
        LOGGER.info("Parsing dynmx signature '{}'".format(signature_path))
        try:
            sig = Signature(signature_path, detect_all)
            sig.parse()
            signatures.append(sig)
            resources_needed |= sig.needs_resources()
        except Exception as e:
            err_message = "Error while parsing dynmx signature. Error message: {}".format(e)
            LOGGER.error(err_message)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            st = traceback.format_exception(exc_type, exc_value, exc_traceback, limit=5)
            LOGGER.error("Traceback: {}".format(st))
            OUTPUT_HELPER.render_error(err_message)
    # Prepare function logs
    in_files = get_input_files(input_files, recursive)
    input_file_count = len(in_files)
    LOGGER.info("Found {} function logs to parse".format(input_file_count))
    # Multiprocessing
    if input_file_count < MultiprocessingHelper.get_cpu_count():
        num_of_workers = input_file_count
    num_of_processes, proc_pool = MultiprocessingHelper.get_pool(
        num_of_workers=num_of_workers,
        log_level=log_level,
        queue=dynmx.helpers.logging_globals.logging_queue
    )
    LOGGER.info("Instantiated pool of {} workers to process function logs".format(num_of_processes))
    LOGGER.info("Starting worker...")
    OUTPUT_HELPER.render_detection_run_info(input_file_count, len(signatures), resources_needed, num_of_processes)
    detection_results = proc_pool.starmap(
        detect_signatures_in_flog,
        zip(
            in_files,
            repeat(parser_lib),
            repeat(signatures),
            repeat(resources_needed),
            repeat(OUTPUT_HELPER)
        )
    )
    proc_pool.close()
    proc_pool.join()
    return flatten_detection_results(detection_results)


def flatten_detection_results(detection_results: List[List[DetectionResult]]) -> List[DetectionResult]:
    """
    Flattens the nested detection results by consolidating them in a flat list
    :param detection_results: Nested detection results
    :return: Flat list of detection results
    """
    flattened_list = []
    for result_list in detection_results:
        if result_list:
            flattened_list += result_list
    return flattened_list


def detect_signatures_in_flog(flog_path: str, parser_lib: ParserLibrary, signatures: List[Signature],
                              resources_needed: bool, output_helper: OutputHelper) -> List[DetectionResult]:
    """
    Detects the list of signatures in the given function log
    :param flog_path: Path to function log file
    :param parser_lib: Parser library object
    :param signatures: List of parsed signatures
    :param resources_needed: Indicates whether resources are needed for detection
    :param output_helper: OutputHelper object to render output
    :return: Detection results
    """
    cycle_start = time.perf_counter()
    detection_results = []
    # Get a new logger in the worker process that reflects the function log
    LOGGER = LoggingHelper.get_logger(__name__, flog_path)
    LOGGER.info("Parsing input function log")
    # Find suitable parser and parse flog
    try:
        start = time.perf_counter()
        flog = parse_flog(flog_path, parser_lib)
        end = time.perf_counter()
        runtime_parsing = end - start
        LOGGER.info("Parsing took {:.4f}s".format(runtime_parsing))
    except Exception as e:
        err_message = "Error while parsing input file '{}'. Error message: {}".format(flog_path, e)
        LOGGER.error(err_message)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        st = traceback.format_exception(exc_type, exc_value, exc_traceback, limit=5)
        LOGGER.error("Traceback: {}".format(st))
        output_helper.render_error(err_message)
        return None
    # Extract resources for each process of the parsed function log
    if resources_needed:
        LOGGER.info("Used signature(s) need(s) resources")
        LOGGER.info("Extracting resources of function log")
        start = time.perf_counter()
        flog.extract_resources()
        # for p in flog.processes:
        #     p.extract_resources()
        end = time.perf_counter()
        runtime_resources = end - start
        LOGGER.info("Resource extraction took {:.4f}s".format(runtime_resources))
    # Detect signatures in function logs
    LOGGER.info("Starting detection process")
    if not len(signatures):
        LOGGER.warning("No signatures to detect available")
    for sig in signatures:
        LOGGER.info("Trying to detect signature '{}' in function log".format(sig.name))
        detection_result = None
        try:
            start = time.perf_counter()
            detection_result = sig.detect(flog)
            end = time.perf_counter()
            runtime_detection = end - start
            if detection_result.detected:
                LOGGER.info("Signature '{}' detected in function log".format(sig.name))
            else:
                LOGGER.info("Signature '{}' not detected in function log".format(sig.name))
            LOGGER.info("Detection of signature '{}' took {:.4f}s".format(sig.name, runtime_detection))
            # Enrich detection result with runtimes
            detection_result.runtime_flog_parsing = runtime_parsing
            detection_result.runtime_signature_detection = runtime_detection
            if resources_needed:
                detection_result.runtime_resource_extraction = runtime_resources
            detection_results.append(detection_result)
        except Exception as e:
            err_message = "Error while detecting signature '{}' in function log '{}'. Omitting detection. " + \
                          "Error message: {}.".format(sig.file_path, flog.file_path, e)
            LOGGER.error(err_message)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            st = traceback.format_exception(exc_type, exc_value, exc_traceback, limit=4)
            LOGGER.error("Traceback: {}".format(st))
            output_helper.render_error(err_message)
        finally:
            LOGGER.info("End of detection process")
    del flog
    cycle_end = time.perf_counter()
    cycle_time = cycle_end - cycle_start
    LOGGER.info("Processing took {:.4f}s".format(cycle_time))
    return detection_results


def handle_check_command(signature_files: List[str]) -> bool:
    """
    Handler of the 'check' command
    :param signature_files: List of signature files that should be checked
    :return: Check results
    """
    # Check signatures by parsing them
    check_results = {}
    for signature_path in signature_files:
        LOGGER.info("Parsing dynmx signature '{}'".format(signature_path))
        try:
            sig = Signature(signature_path)
            sig.parse()
            check_results[signature_path] = True
        except Exception as e:
            err_message = "Error while parsing dynmx signature {}. Error message: {}".format(signature_path, e)
            LOGGER.error(err_message)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            st = traceback.format_exception(exc_type, exc_value, exc_traceback, limit=5)
            LOGGER.error("Traceback: {}".format(st))
            OUTPUT_HELPER.render_error(err_message)
            check_results[signature_path] = False
    return check_results


def handle_stats_command(input_files: List[str], parser_lib: ParserLibrary, recursive: bool) -> List[Statistics]:
    """
    Handler of the 'stats' command
    :param input_files: List of input files
    :param parser_lib: Parser library object
    :param recursive: Indicates whether to search recursively for input files
    :return: Detection results
    """
    stats_objs = []
    in_files = get_input_files(input_files, recursive)
    input_file_count = len(in_files)
    OUTPUT_HELPER.render_flog_info(input_file_count, "stats")
    for ix, in_file_path in enumerate(in_files):
        percent = (ix + 1) * 100 / input_file_count
        LOGGER.info("Parsing input file '{0}' [{1}/{2}][{3:.1f}%]".format(
            in_file_path, ix + 1, input_file_count, percent))
        # Find suitable parser
        try:
            flog = parse_flog(in_file_path, parser_lib)
        except Exception as e:
            err_message = "Error while parsing function log '{}'. Error message: {}".format(in_file_path, e)
            LOGGER.error(err_message)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            st = traceback.format_exception(exc_type, exc_value, exc_traceback, limit=10)
            LOGGER.error("Traceback: {}".format(st))
            OUTPUT_HELPER.render_error(err_message)
            continue
        # Prepare statistics for flogs
        try:
            stats = Statistics(flog)
            stats.calculate()
            stats_objs.append(stats)
        except Exception as e:
            err_message = "Error while calculating statistics for function log '{}'. Error message: {}.".format(
                    in_file_path, e)
            LOGGER.error(err_message)
            OUTPUT_HELPER.render_error(err_message)
    return stats_objs


def handle_resources_command(input_files: List[str], parser_lib: ParserLibrary, recursive: bool) -> List[FunctionLog]:
    """
    Handler of the 'resources' command
    :param input_files: List of input files
    :param parser_lib: Parser library object
    :param recursive: Indicates whether to search recursively for input files
    :return: List of FunctionLog objects enriched with access activity model
    """
    flogs = []
    in_files = get_input_files(input_files, recursive)
    input_file_count = len(in_files)
    OUTPUT_HELPER.render_flog_info(input_file_count, "resources")
    for ix, in_file_path in enumerate(in_files):
        percent = (ix + 1) * 100 / input_file_count
        LOGGER.info("Parsing input file '{0}' [{1}/{2}][{3:.1f}%]".format(
            in_file_path, ix + 1, input_file_count, percent))
        # Parse function log
        try:
            flog = parse_flog(in_file_path, parser_lib)
            flogs.append(flog)
        except Exception as e:
            err_message = "Error while parsing function log '{}'. Error message: {}".format(in_file_path, e)
            LOGGER.error(err_message)
            exc_type, exc_value, exc_traceback = sys.exc_info()
            st = traceback.format_exception(exc_type, exc_value, exc_traceback, limit=5)
            LOGGER.error("Traceback: {}".format(st))
            OUTPUT_HELPER.render_error(err_message)
            continue
        # Enrich processes of function log with access activity model
        flog.extract_resources()
    return flogs


def handle_convert_command(input_files: List[str], parser_lib: ParserLibrary, output_dir: str, compress: bool,
                           recursive: bool, log_level: int, num_of_workers: Optional[int] = None) -> None:
    """
    Handler of the 'convert' command; uses multiprocessing to enhance conversion runtime
    :param input_files: List of input files
    :param parser_lib: Parser library object
    :param output_dir: Output directory for converted function logs
    :param compress: Indicates whether to compress the converted function log
    :param recursive: Indicates whether to search recursively for input files
    :param log_level: Log level
    :param num_of_workers: Number of workers to use for the conversion
    """
    # Check output directory
    if output_dir:
        if not os.path.isdir(output_dir):
            raise Exception("Output path is not a directory")
    # Prepare function logs
    in_files = get_input_files(input_files, recursive)
    input_file_count = len(in_files)
    LOGGER.info("Found {} function logs to parse".format(input_file_count))
    # Multiprocessing
    if input_file_count < MultiprocessingHelper.get_cpu_count():
        num_of_workers = input_file_count
    num_of_processes, proc_pool = MultiprocessingHelper.get_pool(
        num_of_workers=num_of_workers,
        log_level=log_level,
        queue=dynmx.helpers.logging_globals.logging_queue
    )
    LOGGER.info("Instantiated pool of {} workers to process function logs".format(num_of_processes))
    LOGGER.info("Starting worker...")
    OUTPUT_HELPER.render_flog_info(input_file_count, "convert")
    proc_pool.starmap(
        convert_flog,
        zip(
            in_files,
            repeat(parser_lib),
            repeat(output_dir),
            repeat(compress),
            repeat(OUTPUT_HELPER)
        )
    )
    proc_pool.close()
    proc_pool.join()


def convert_flog(flog_path: str, parser_lib: ParserLibrary, output_dir: str, compress: bool,
                 output_helper: OutputHelper) -> None:
    """
    Converts a function log to the generic dynmx function log format; called by multiple processes
    :param flog_path: Path of function log file
    :param parser_lib: Parser library object
    :param output_dir: Output directory for converted function logs
    :param compress: Indicates whether to compress the converted function log
    :param output_helper: OutputHelper object to render output
    """
    # Get a new logger in the worker process that reflects the function log
    LOGGER = LoggingHelper.get_logger(__name__, flog_path)
    LOGGER.info("Parsing input function log")
    # Find suitable parser and parse flog
    try:
        start = time.perf_counter()
        flog = parse_flog(flog_path, parser_lib)
        end = time.perf_counter()
        runtime_parsing = end - start
        LOGGER.info("Parsing took {:.4f}s".format(runtime_parsing))
    except Exception as e:
        err_message = "Error while parsing function log '{}'. Error message: {}".format(flog_path, e)
        LOGGER.error(err_message)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        st = traceback.format_exception(exc_type, exc_value, exc_traceback, limit=5)
        LOGGER.error("Traceback: {}".format(st))
        output_helper.render_error(err_message)
        return None
    LOGGER.info("Starting conversion process")
    try:
        # Convert function logs and write them to the output directory
        converter = DynmxConverter()
        start = time.perf_counter()
        converter.convert(flog, output_dir, compress)
        end = time.perf_counter()
        runtime_conversion = end - start
        LOGGER.info("Conversion took {:.4f}s".format(runtime_conversion))
        output_helper.render_converted_flog(flog_path, runtime_conversion, output_dir)
        del converter
        del flog
    except Exception as e:
        err_message = "Error while converting input file '{}' to dynmx format. Error message: {}.".format(flog_path, e)
        LOGGER.error(err_message)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        st = traceback.format_exception(exc_type, exc_value, exc_traceback, limit=5)
        LOGGER.debug("Traceback: {}".format(st))
        output_helper.render_error(err_message)
    finally:
        LOGGER.info("End of conversion process")


def parse_flog(flog_path: str, parser_lib: ParserLibrary) -> FunctionLog:
    """
    Parses a function log file
    :param flog_path: Path to function log file
    :param parser_lib: Parser library object
    :return: Parsed input function log as FunctionLog object
    """
    parser_found = False
    flog = None
    LOGGER = LoggingHelper.get_logger(__name__, flog_path)
    # Search for suitable parser and parse function log file
    for parser in parser_lib.parsers:
        parser_found = False
        # If suitable parser is found, parse function log
        if parser.probe(flog_path):
            LOGGER.debug("Parser for function log: {}".format(parser))
            parser_obj = parser()
            flog = parser_obj.parse(flog_path)
            parser_found = True
            break
    if not parser_found:
        raise Exception("No suitable parser found for function log '{}'.".format(flog_path))
    return flog


def get_input_files(input_files: List[str], recursive: bool) -> List[str]:
    """
    Searches for input files
    :param input_files: Input file paths passed as script parameters
    :param recursive: Indicates whether to search recursively for input files in directories
    :return: List of input file paths
    """
    in_files = []
    if recursive:
        for input_file in input_files:
            if os.path.isdir(input_file):
                in_files += find_files(input_file)
            else:
                in_files.append(input_file)
    else:
        in_files = input_files
    return in_files


def find_files(dir_path: str) -> List[str]:
    """
    Finds all files in a given directory recursively
    :param dir_path: Directory to search for files in
    :return: List of relevant file paths
    """
    found_files = list()
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            found_files.append(os.path.join(dir_path, root, file))
    return found_files


# Main entry point
if __name__ == '__main__':
    main(sys.argv[1:])

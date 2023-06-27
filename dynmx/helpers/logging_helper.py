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
from typing import Optional, TextIO
import logging
import logging.config
import logging.handlers
from multiprocessing import Manager, Queue, current_process
from threading import Thread
import time

import dynmx.helpers.logging_globals

# Idea for multiprocess logging found in
# https://www.youtube.com/watch?v=axjfFB81FrE


class LoggingThread:
    """
    Represents a thread for centrally handling log messages that were written to a multiprocessing Queue
    """

    def __init__(self):
        self._logging_thread = Thread(
            target=LoggingThread._logging_thread_run,
            args=(dynmx.helpers.logging_globals.logging_queue,)
        )
        self._logging_thread.start()

    @staticmethod
    def _logging_thread_run(queue: Queue) -> None:
        """
        Runs the logging thread
        :param queue: Multiprocessing queue for storing log messages
        """
        while True:
            record = queue.get()
            if record is None:
                break
            logger = logging.getLogger(record.name)
            logger.handle(record)

    def terminate_logger(self) -> None:
        """
        Terminates the logging thread
        """
        dynmx.helpers.logging_globals.logging_queue.put(None)
        self._logging_thread.join()


class LoggingHelper:
    """
    Represents a centralized logger to log events
    """

    @staticmethod
    def set_up_logging(log_level: Optional[int] = logging.DEBUG, logfile: Optional[TextIO] = None,
                       show_console_log: Optional[bool] = False) -> LoggingThread:
        """
        Sets up the logging configurations
        :param log_level: Log level
        :param logfile: Log file
        :param show_console_log: Indicates whether to show log messages on the console
        :return: Returns the logging thread which handles log messages
        """
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        logging.Formatter.converter = time.gmtime
        log_formatter = logging.Formatter(
            "%(asctime)s+0000 [%(levelname)s] (%(name)s) [PID: %(process)d] [%(flog_path)s]: %(message)s")
        if show_console_log:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(log_formatter)
            root_logger.addHandler(console_handler)
        if logfile:
            file_handler = logging.StreamHandler(logfile)
            file_handler.setFormatter(log_formatter)
            root_logger.addHandler(file_handler)
        # Multiprocessing
        dynmx.helpers.logging_globals.logging_queue = Manager().Queue()
        return LoggingThread()

    @staticmethod
    def set_up_process_logging(log_level: Optional[int] = logging.DEBUG, queue: Optional[Queue] = None) -> None:
        """
        Sets up logging for processes run via multiprocessing
        :param log_level: Log level
        :param queue: Multiprocessing queue to store log messages
        """
        if current_process().name != 'MainProcess' and not Queue:
            pass
        elif queue is not None:
            queue_handler = logging.handlers.QueueHandler(queue)
            queue_handler.set_name(name=current_process().pid.__str__())
            root_logger = logging.getLogger()
            root_logger.setLevel(log_level)
            if queue_handler.name not in [x.name for x in root_logger.handlers]:
                root_logger.addHandler(queue_handler)

    @staticmethod
    def get_logger(logger_name: str, flog_path: Optional[str] = "") -> logging.LoggerAdapter:
        """
        Returns a new logger
        :param logger_name: Name of the logger
        :param flog_path: Function log path that should be included in the log message
        """
        logger = logging.getLogger(logger_name)
        # Make use of logging adapters to inject the function log path in each log message if it is passed to this
        # function
        extra = {'flog_path': flog_path}
        logging_adapter = logging.LoggerAdapter(logger, extra)
        return logging_adapter

    @staticmethod
    def shutdown_log() -> None:
        """
        Shuts the logging down
        """
        logging.shutdown()

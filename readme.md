<!---
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# *dynmx* Prototype
*dynmx* is a signature-based detection approach for behavioural malware features based on Windows API call sequences. The detection approach is described in detail in the master thesis [Signature-Based Detection of Behavioural Malware Features with Windows API Calls](https://github.com/0x534a/master-thesis). This project is the prototype implementation of this approach and was developed in the course of the master thesis. The signatures are manually defined by malware analysts in the *dynmx* signature DSL and can be detected in function logs with the help of this software. Features and syntax of the *dynmx* signature DSL can also be found in the master thesis. Generally, function logs are API call sequences traced by sandboxes. Currently, *dynmx* supports function logs of the following sandboxes:
* VMRay (text-based and XML format)
* CAPEv2
* Cuckoo

## Installation
In order to use the software Python 3.9 must be available on the target system. In addition, the following Python packages need to be installed:
* `anytree`,
* `lxml`,
* `pyparsing`,
* `PyYAML`,
* `six` and
* `stringcase`

To install the packages run the `pip3` command shown below. It is recommended to use a Python virtual environment instead of installing the packages system-wide.
```
pip3 install -r requirements.txt
```

## Usage
To use the prototype, simply run the main entry point `dynmx.py`. The usage information can be viewed with the `-h` command line parameter as shown below.
```
$ python3 dynmx.py -h
usage: dynmx.py [-h] [--format {overview,detail}] [--show-log] [--log LOG] [--log-level {debug,info,error}] [--worker N] {detect,check,convert,stats,resources} ...

Detect dynmx signatures in dynamic program execution information (function logs)

optional arguments:
  -h, --help            show this help message and exit
  --format {overview,detail}, -f {overview,detail}
                        Output format
  --show-log            Show all log output on stdout
  --log LOG, -l LOG     log file
  --log-level {debug,info,error}
                        Log level (default: info)
  --worker N, -w N      Number of workers to spawn (default: number of processors - 2)

sub-commands:
  task to perform

  {detect,check,convert,stats,resources}
    detect              Detects a dynmx signature
    check               Checks the syntax of dynmx signature(s)
    convert             Converts function logs to the dynmx generic function log format
    stats               Statistics of function logs
    resources           Resource activity derived from function log
```
In general, as shown in the output, several command line parameters regarding the log handling, the output format for results or multiprocessing can be defined. Furthermore, a command needs be chosen to run a specific task. Please note, that the number of workers only affects commands that make use of multiprocessing. Currently, these are the commands `detect` and `convert`. 

The commands have specific command line parameters that can be explored by giving the parameter `-h` to the command, e.g. for the `detect` command as shown below.
```
$ python3 dynmx.py detect -h
usage: dynmx.py detect [-h] --sig SIG [SIG ...] --input INPUT [INPUT ...] [--recursive] [--json-result JSON_RESULT] [--runtime-result RUNTIME_RESULT] [--detect-all]

optional arguments:
  -h, --help            show this help message and exit
  --recursive, -r       Search for input files recursively
  --json-result JSON_RESULT
                        JSON formatted result file
  --runtime-result RUNTIME_RESULT
                        Runtime statistics file formatted in CSV
  --detect-all          Detect signature in all processes and do not stop after the first detection

required arguments:
  --sig SIG [SIG ...], -s SIG [SIG ...]
                        dynmx signature(s) to detect
  --input INPUT [INPUT ...], -i INPUT [INPUT ...]
                        Input files
```

As a user of *dynmx*, you can decide how the output is structured. If you choose to show the log on the console by defining the parameter `--show-log`, the output consists of two sections (see listing below). The log is shown first and afterwards the results of the used command. By default, the log is neither shown in the console nor written to a log file (which can be defined using the `--log` parameter). Due to multiprocessing, the entries in the log file are not necessarily in chronological order.
```


    |
  __|         _  _    _  _  _
 /  |  |   | / |/ |  / |/ |/ |  /\/
 \_/|_/ \_/|/  |  |_/  |  |  |_/ /\_/
          /|
          \|
            
 Ver. 0.5 (PoC), by 0x534a


[+] Log output
2023-06-27 19:07:38,068+0000 [INFO] (__main__) [PID: 13315] []: Start of dynmx run
[...]
[+] End of log output

[+] Result
[...]
```

The level of detail of the result output can be defined using the command line parameter `--output-format` which can be set to `overview` for a high-level result or to `detail` for a detailed result. For example, if you define the output format to `detail`, detection results shown in the console will contain the exact API calls and resources that caused the detection. The overview output format will just indicate what signature was detected in which function log.

## Example Command Lines
Detection of a *dynmx* signature in a function log with one worker process
```
python3 dynmx.py -w 1 detect -i "flog.txt" -s dynmx_signature.yml
```

Conversion of a function log to the *dynmx* generic function log format
```
python3 dynmx.py convert -i "flog.txt" -o /tmp/
```

Check a signature (only basic sanity checks)
```
python3 dynmx.py check -s dynmx_signature.yml
```

Get a detailed list of used resources used by a malware sample based on the function log (access activity model)
```
python3 dynmx.py -f detail resources -i "flog.txt"
```

## Troubleshooting
Please consider that this tool is a proof-of-concept which was developed besides writing the master thesis. Hence, the code quality is not always the best and there may be bugs and errors. I tried to make the tool as robust as possible in the given time frame.

The best way to troubleshoot errors is to enable logging (on the console and/or to a log file) and set the log level to `debug`. Exception handlers should write detailed errors to the log which can help troubleshooting. 
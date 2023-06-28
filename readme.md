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
*dynmx* (spoken *dynamics*) is a signature-based detection approach for behavioural malware features based on Windows API call sequences. In a simplified way, you can think of *dynmx* as a sort of YARA for API call traces (so called function logs) originating from malware sandboxes. Hence, the data basis for the detection approach are not the malware samples themselves which are analyzed statically but data that is generated during a dynamic analysis of the malware sample in a malware sandbox. Currently, *dynmx* supports function logs of the following malware sandboxes:
* VMRay (function log, text-based and XML format)
* CAPEv2 (`report.json` file)
* Cuckoo (`report.json` file)

The detection approach is described in detail in the master thesis [Signature-Based Detection of Behavioural Malware Features with Windows API Calls](https://github.com/0x534a/master-thesis). This project is the prototype implementation of this approach and was developed in the course of the master thesis. The signatures are manually defined by malware analysts in the *dynmx* signature DSL and can be detected in function logs with the help of this tool. Features and syntax of the *dynmx* signature DSL can also be found in the master thesis. Furthermore, you can find sample dynmx signatures in the repository [dynmx-signatures](https://github.com/0x534a/dynmx-signatures). In addition to detecting malware features based on API calls, dynmx can extract OS resources that are used by the malware (a so called Access Activity Model). These resources are extracted by examining the API calls and reconstructing operations on OS resources. Currently, OS resources of the categories filesystem, registry and network are considered in the model.

## Example
In the following section, examples are shown for the detection of malware features and for the extraction of resources.

### Detection
For this example, we choose the malware sample with the SHA-256 hash sum `c0832b1008aa0fc828654f9762e37bda019080cbdd92bd2453a05cfb3b79abb3`. According to [MalwareBazaar](https://bazaar.abuse.ch/sample/c0832b1008aa0fc828654f9762e37bda019080cbdd92bd2453a05cfb3b79abb3/), the sample belongs to the malware family [Amadey](https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey). There is a public [VMRay analysis report](https://www.vmray.com/analyses/_mb/c0832b1008aa/report/overview.html) of this sample available which also provides the [function log](https://www.vmray.com/analyses/_mb/c0832b1008aa/logs/flog.txt) traced by VMRay. This function log will be our data basis which we will use for the detection.

If we would like to know if the malware sample uses an injection technique called [Process Hollowing](https://attack.mitre.org/techniques/T1055/012/), we can try to detect the following *dynmx* signature in the function log.
```yaml
dynmx_signature:
  meta:
    name: process_hollow
    title: Process Hollowing
    description: Detection of Process hollowing malware feature
  detection:
    proc_hollow:
      # Create legit process in suspended mode
      - api_call: ["CreateProcess[AW]", "CreateProcessInternal[AW]"]
        with:
          - argument: "dwCreationFlags"
            operation: "flag is set"
            value: 0x4
          - return_value: "return"
            operation: "is not"
            value: 0
        store:
          - name: "hProcess"
            as: "proc_handle"
          - name: "hThread"
            as: "thread_handle"
      # Injection of malicious code into memory of previously created process
      - variant:
        - path:
          # Allocate memory with read, write, execute permission
          - api_call: ["VirtualAllocEx", "VirtualAlloc", "(Nt|Zw)AllocateVirtualMemory"]
            with:
              - argument: ["hProcess", "ProcessHandle"]
                operation: "is"
                value: "$(proc_handle)"
              - argument: ["flProtect", "Protect"]
                operation: "is"
                value: 0x40
          - api_call: ["WriteProcessMemory"]
            with:
              - argument: "hProcess"
                operation: "is"
                value: "$(proc_handle)"
          - api_call: ["SetThreadContext", "(Nt|Zw)SetContextThread"]
            with:
              - argument: "hThread"
                operation: "is"
                value: "$(thread_handle)"
        - path:
          # Map memory section with read, write, execute permission
          - api_call: "(Nt|Zw)MapViewOfSection"
            with:
              - argument: "ProcessHandle"
                operation: "is"
                value: "$(proc_handle)"
              - argument: "AccessProtection"
                operation: "is"
                value: 0x40
      # Resume thread to run injected malicious code
      - api_call: ["ResumeThread", "(Nt|Zw)ResumeThread"]
        with:
          - argument: ["hThread", "ThreadHandle"]
            operation: "is"
            value: "$(thread_handle)"
  condition: proc_hollow as sequence
```

Based on the signature, we can find some DSL features that make *dynmx* powerful:
* Definition of API call sequences with alternative paths
* Matching of API call function names with regular expressions
* Matching of argument and return values with several operators
* Storage of variables, e.g. in order to track handles in the API call sequence
* Definition of a detection condition with boolean operators (`AND`, `OR`, `NOT`)

If we run *dynmx* with the signature shown above against the function of the sample `c0832b1008aa0fc828654f9762e37bda019080cbdd92bd2453a05cfb3b79abb3`, we get the following output indicating that the signature was detected.

```
$ python3 dynmx.py detect -i 601941f00b194587c9e57c5fabaf1ef11596179bea007df9bdcdaa10f162cac9.json -s process_hollow.yml


    |
  __|         _  _    _  _  _
 /  |  |   | / |/ |  / |/ |/ |  /\/
 \_/|_/ \_/|/  |  |_/  |  |  |_/ /\_/
          /|
          \|
            
 Ver. 0.5 (PoC), by 0x534a


[+] Parsing 1 function log(s)
[+] Loaded 1 dynmx signature(s)
[+] Starting detection process with 1 worker(s). This probably takes some time...

[+] Result
process_hollow	c0832b1008aa0fc828654f9762e37bda019080cbdd92bd2453a05cfb3b79abb3.txt
```

We can get into more detail by setting the output format to `detail`. Now, we can see the exact API call sequence that was detected in the function log. Furthermore, we can see that the signature was detected in the process `51f0.exe`.

```
$ python3 dynmx.py -f detail detect -i 601941f00b194587c9e57c5fabaf1ef11596179bea007df9bdcdaa10f162cac9.json -s process_hollow.yml


    |
  __|         _  _    _  _  _
 /  |  |   | / |/ |  / |/ |/ |  /\/
 \_/|_/ \_/|/  |  |_/  |  |  |_/ /\_/
          /|
          \|
            
 Ver. 0.5 (PoC), by 0x534a


[+] Parsing 1 function log(s)
[+] Loaded 1 dynmx signature(s)
[+] Starting detection process with 1 worker(s). This probably takes some time...

[+] Result
Function log: c0832b1008aa0fc828654f9762e37bda019080cbdd92bd2453a05cfb3b79abb3.txt
	Signature: process_hollow
		Process: 51f0.exe (PID: 3768)
		Number of Findings: 1
			Finding 0
				proc_hollow : API Call CreateProcessA (Function log line 20560, index 938)
				proc_hollow : API Call VirtualAllocEx (Function log line 20566, index 944)
				proc_hollow : API Call WriteProcessMemory (Function log line 20573, index 951)
				proc_hollow : API Call SetThreadContext (Function log line 20574, index 952)
				proc_hollow : API Call ResumeThread (Function log line 20575, index 953)
```

### Resources
In order to extract the accessed OS resources from a function log, we can simply run the *dynmx* command `resources` against the function log. An example of the detailed output is shown below for the sample with the SHA-256 hash sum `601941f00b194587c9e57c5fabaf1ef11596179bea007df9bdcdaa10f162cac9`. This is a CAPE sandbox report which is part of the [Avast-CTU Public CAPEv2 Dataset](https://github.com/avast/avast-ctu-cape-dataset).

```
$ python3 dynmx.py -f detail resources --input 601941f00b194587c9e57c5fabaf1ef11596179bea007df9bdcdaa10f162cac9.json


    |
  __|         _  _    _  _  _
 /  |  |   | / |/ |  / |/ |/ |  /\/
 \_/|_/ \_/|/  |  |_/  |  |  |_/ /\_/
          /|
          \|

 Ver. 0.5 (PoC), by 0x534a


[+] Parsing 1 function log(s)
[+] Processing function log(s) with the command 'resources'...

[+] Result
Function log: 601941f00b194587c9e57c5fabaf1ef11596179bea007df9bdcdaa10f162cac9.json (/Users/sijansen/Documents/dev/dynmx_flogs/cape/Public_Avast_CTU_CAPEv2_Dataset_Full/extracted/601941f00b194587c9e57c5fabaf1ef11596179bea007df9bdcdaa10f162cac9.json)
	Process: 601941F00B194587C9E5.exe (PID: 2008)
		Filesystem:
			C:\Windows\SysWOW64\en-US\SETUPAPI.dll.mui (CREATE)
			API-MS-Win-Core-LocalRegistry-L1-1-0.dll (EXECUTE)
			C:\Windows\SysWOW64\ntdll.dll (READ)
			USER32.dll (EXECUTE)
			KERNEL32.dll (EXECUTE)
			C:\Windows\Globalization\Sorting\sortdefault.nls (CREATE)
		Registry:
			HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OLEAUT (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Setup (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Setup\SourcePath (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\DevicePath (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\DisableImprovedZoneCheck (READ)
			HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings (READ)
			HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_HKLM_only (READ)
	Process: 601941F00B194587C9E5.exe (PID: 1800)
		Filesystem:
			C:\Windows\SysWOW64\en-US\SETUPAPI.dll.mui (CREATE)
			API-MS-Win-Core-LocalRegistry-L1-1-0.dll (EXECUTE)
			C:\Windows\SysWOW64\ntdll.dll (READ)
			USER32.dll (EXECUTE)
			KERNEL32.dll (EXECUTE)
			[...]
			C:\Users\comp\AppData\Local\vscmouse (READ)
			C:\Users\comp\AppData\Local\vscmouse\vscmouse.exe:Zone.Identifier (DELETE)
		Registry:
			HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OLEAUT (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Setup (READ)
			[...]
	Process: vscmouse.exe (PID: 900)
		Filesystem:
			C:\Windows\SysWOW64\en-US\SETUPAPI.dll.mui (CREATE)
			API-MS-Win-Core-LocalRegistry-L1-1-0.dll (EXECUTE)
			C:\Windows\SysWOW64\ntdll.dll (READ)
			USER32.dll (EXECUTE)
			KERNEL32.dll (EXECUTE)
			C:\Windows\Globalization\Sorting\sortdefault.nls (CREATE)
		Registry:
			HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OLEAUT (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Setup (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Setup\SourcePath (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\DevicePath (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\DisableImprovedZoneCheck (READ)
			HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings (READ)
			HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_HKLM_only (READ)
	Process: vscmouse.exe (PID: 3036)
		Filesystem:
			C:\Windows\SysWOW64\en-US\SETUPAPI.dll.mui (CREATE)
			API-MS-Win-Core-LocalRegistry-L1-1-0.dll (EXECUTE)
			C:\Windows\SysWOW64\ntdll.dll (READ)
			USER32.dll (EXECUTE)
			KERNEL32.dll (EXECUTE)
			C:\Windows\Globalization\Sorting\sortdefault.nls (CREATE)
			C:\ (READ)
			C:\Windows\System32\uxtheme.dll (EXECUTE)
			dwmapi.dll (EXECUTE)
			advapi32.dll (EXECUTE)
			shell32.dll (EXECUTE)
			C:\Users\comp\AppData\Local\vscmouse\vscmouse.exe (CREATE,READ)
			C:\Users\comp\AppData\Local\iproppass\iproppass.exe (DELETE)
			crypt32.dll (EXECUTE)
			urlmon.dll (EXECUTE)
			userenv.dll (EXECUTE)
			wininet.dll (EXECUTE)
			wtsapi32.dll (EXECUTE)
			CRYPTSP.dll (EXECUTE)
			CRYPTBASE.dll (EXECUTE)
			ole32.dll (EXECUTE)
			OLEAUT32.dll (EXECUTE)
			C:\Windows\SysWOW64\oleaut32.dll (EXECUTE)
			IPHLPAPI.DLL (EXECUTE)
			DHCPCSVC.DLL (EXECUTE)
			C:\Users\comp\AppData\Roaming\Microsoft\Network\Connections\Pbk\_hiddenPbk\ (CREATE)
			C:\Users\comp\AppData\Roaming\Microsoft\Network\Connections\Pbk\_hiddenPbk\rasphone.pbk (CREATE,READ)
		Registry:
			HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OLEAUT (READ)
			HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Setup (READ)
			[...]
		Network:
			24.151.31.150:465 (READ)
			http://24.151.31.150:465 (READ,WRITE)
			107.10.49.252:80 (READ)
			http://107.10.49.252:80 (READ,WRITE)
```

Based on the shown output and the accessed resources, we can deduce some malware features:
* Within the process `601941F00B194587C9E5.exe` (PID 1800), the Zone Identifier of the file `C:\Users\comp\AppData\Local\vscmouse\vscmouse.exe` is deleted
* Some DLLs are loaded dynamically
* The process `vscmouse.exe` (PID: 3036) connects to the network endpoints `http://24.151.31.150:465` and `http://107.10.49.252:80`

The accessed resources are interesting for identifying host- and network-based detection indicators. In addition, resources can be used in *dynmx* signatures. A popular example is the detection of persistence mechanisms in the Registry.
```
dynmx_signature:
  meta:
    name: run_keys_persistence
    title: Run Keys Persistence
    description: Detection of persistence based on Registry Run Keys
  detection:
    run_keys:
      - resource:
        category: "registry"
        access_operations: ["write"]
        with:
          - attribute: "location"
            operation: "regex"
            value: "^(HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\(Run|RunOnce|RunOnceEx)\\\\"
    startup_folders_keys:
      - resource:
        category: "registry"
        access_operations: ["write"]
        with:
          - attribute: "location"
            operation: "regex"
            value: "^(HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\(Shell Folders|User Shell Folders)\\\\"
  condition: run_keys as simple or startup_folders_keys as simple
```

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
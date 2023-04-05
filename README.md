[comment]: # "Auto-generated SOAR connector documentation"
# Yara

Publisher: Splunk Community  
Connector Version: 1.0.1  
Product Vendor: Virus Total  
Product Name: Yara  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

The pattern matching swiss knife for malware researchers (and everyone else)

[comment]: # "File: README.md"
[comment]: # "Copyright (c) 2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## [Yara Python](https://yara.readthedocs.io/en/stable/)

### Actions Configured

-   test connectivity
-   update yara sources
-   list yara sources
-   clear yara sources
-   yara scan

#### update yara sources

**Requires a configured asset with 1 or more Environment Variables set to be a list of sources to
download.**  
  
This will iterate over all sources configured in an asset and explode any .zip or individual files
into the applications's state directory. The files here can be listed or loaded for a scan later,
allowing one asset to be built with many sources of Yara rules, possibly serving many use cases.  
  
![](images/environment_setup.png)

#### list yara sources

  
  
This will list any items found with the provided file glob for path, if provided. If not provided,
it will default to a file glob of \*, listing everything in the application's state directory
(one-level deep). Also, if checked, "stat info" will provide detailed information about each file
found as returned by
[os.stat_result](https://docs.python.org/3/library/pathlib.html#pathlib.Path.stat)  
  
For reference, [Python's pathlib.Path.glob documentation can show some
examples.](https://docs.python.org/3/library/pathlib.html#pathlib.Path.glob)

#### clear yara sources

  
  
This will clear any files in the state directory that do not end with "state.json". If provided, the
"path" parameter will be used to further limit the clearing to a sub-directory of the asset's
downloaded files.

#### yara scan

  
  
This will load any Yara rules found at "yara path", defaulting to "\*\*/\*.yar" if not provided.
Those loaded rules are compiled and saved for use later, cached at a new file in the state
directory. If that cache cannot be found or read, the rules are compiled and loaded again. The scan
will look for "scan dir" first, falling back to reading the file found at the provided "vault id".
**One of "vault id" or "scan dir" must be provided!**  
  
If specified, "use_includes" can be set to allow your rules to include other rules. Similarly, Yara
rule time out can be overridden along with runtime configuration for Yara like "stack size", "max
strings per rule" and "max match data". For reference to these settings, see [The documentation here
for yara-python](https://yara.readthedocs.io/en/stable/yarapython.html#using-yara-from-python)


### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[clear yara sources](#action-clear-yara-sources) - Delete any files stored in the Vault to clear any Yara rules persisted for this asset  
[update yara sources](#action-update-yara-sources) - Download and persist any rule sources defined in assets associated with this app  
[list yara sources](#action-list-yara-sources) - List sources of Yara rules previously downloaded and stored in the Vault  
[yara scan](#action-yara-scan) - Compile (if needed) any specified Yara rules and scan specified target for matches  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'clear yara sources'
Delete any files stored in the Vault to clear any Yara rules persisted for this asset

Type: **generic**  
Read only: **False**

Delete any downloaded files from the location of get_state_dir().  Defaults to everything in the application's state directory but can optionally accept a path parameter that is provided to pathlib.Path().rglob() to limit what is removed.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**path** |  optional  | A valid file glob, relative to the value of the app's state directory | string |  `file path` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.path | string |  `file path`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |    

## action: 'update yara sources'
Download and persist any rule sources defined in assets associated with this app

Type: **generic**  
Read only: **False**

This will reach out to any configured asset to download a set of rules that can saved and used at a later time.  Running will overwrite any previously saved sources matching the file path.   Asset configuration should include the URL(s) of the remote location(s) to fetch and any needed credentials.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |    

## action: 'list yara sources'
List sources of Yara rules previously downloaded and stored in the Vault

Type: **generic**  
Read only: **True**

List the downloaded Yara rules that are stored in the location of get_state_dir().  This will optionally accept a path parameter that, if present, will be provided to pathlib.Path().rglob() for searching for a subset of downloaded files relative to the application's state directory.  This would allow for consuming a subset of the asset's downloaded sources for various use cases.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**path** |  optional  | A relative path to provide for listing specific files in the app's state_dir.  Defaults to "\*\*", or directories in state_dir.  Some examples could be "\*\*/\*.yar" or "malware-rules/\*\*" | string |  `file path` 
**stat_info** |  optional  | A boolean to optionally return the information from os.stat_result for each file object found.  Defaults to False | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.path | string |  `file path`  |  
action_result.parameter.stat_info | boolean |  |   True  False 
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |    

## action: 'yara scan'
Compile (if needed) any specified Yara rules and scan specified target for matches

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**yara_path** |  optional  | String to use for recursive file glob, relative to state directory, for locating Yara rules to use in scan.  Defaults to all files in the state directory | string |  `file path` 
**use_includes** |  optional  | Whether or not rules found can use the include directive to load other files.  Defaults to False | boolean | 
**scan_dir** |  optional  | Directory to scan for matches.  If not specified, vault_id is required | string | 
**vault_id** |  optional  | Vault ID of a file to look up for scanning.  If not specified scan_dir is required | string | 
**fast_mode** |  optional  | Whether or not to have Yara perform a fast mode scan.  Defaults to False | boolean | 
**timeout** |  optional  | How long until a match function in Yara will time out?  Defaults to 60 seconds | numeric | 
**stack_size** |  optional  | Set the stack size used by Yara.  Set with set_config(), interfacing with the C API | numeric | 
**max_strings_per_rule** |  optional  | Set the Yara configuration to define the number of max_strings_per_rule | numeric | 
**max_match_data** |  optional  | Set the max_match_data in Yara configuration | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.yara_path | string |  `file path`  |  
action_result.parameter.use_includes | boolean |  |  
action_result.parameter.scan_dir | string |  |  
action_result.parameter.fast_mode | boolean |  |  
action_result.parameter.timeout | numeric |  |  
action_result.parameter.vault_id | string |  |  
action_result.parameter.stack_size | numeric |  |  
action_result.parameter.max_strings_per_rule | numeric |  |  
action_result.parameter.max_match_data | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
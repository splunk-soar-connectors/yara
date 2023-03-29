# File: yara_connector.py
#
# Copyright (c) 2023 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import hashlib
import io
import sys
import zipfile
from pathlib import Path, PurePath
from typing import Any, Dict, Tuple

import requests
from phantom import vault
from phantom.action_result import ActionResult
from phantom.app import APP_ERROR, APP_SUCCESS
from phantom.base_connector import BaseConnector

import yara
import yara_config


class RetVal(tuple):
    def __new__(cls, val1, val2=None) -> Tuple[bool, Any]:
        return tuple.__new__(RetVal, (val1, val2))


class YaraConnector(BaseConnector):
    def __init__(self) -> None:
        super(YaraConnector, self).__init__()
        self._state = None
        self.state_dir: str = ""

    def _return_with_message(
        self,
        message: str = "",
        action_result: ActionResult = None,
        status: bool = APP_SUCCESS,
    ) -> RetVal:
        self.save_progress(message)
        return RetVal(action_result.set_status(status, message), None)

    def _fetch_yara_source(self, location: str = "") -> None:
        """
        Accept some location read from _reserved_environment_variables
        and download its contents.  This allows an asset to be comprised of
        multiple sources, store any URLs containing credentials as secrets
        and download all content
        """

        response = requests.get(location)
        if not response.ok:
            raise Exception(response.text)

        if self.get_action_identifier() == "test_connectivity":
            self.save_progress(f"Connected successfully to {location}")
            return

        if response.headers.get("Content-Type", "").find("application/zip") > -1:
            self.save_progress("Extracting downloaded zip")
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip:
                zip.extractall(path=self.state_dir)

        if response.headers.get("Content-Type", "").find("text/plain") > -1:
            self.save_progress(f"Writing fetched file to {self.state_dir}")
            with open(
                PurePath(self.state_dir, location.split("/")[-1].split("?")[0]), "wb"
            ) as filename:
                filename.write(response.content)

    def _handle_update_sources(self) -> RetVal:
        """
        Doubles as test connectivity function.  _fetch_yara_source will short-circuit
        and return before overwriting any files.
        """

        action_result = self.add_action_result(ActionResult())
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        env_vars = self.get_config().get("_reserved_environment_variables", {})

        if env_vars:
            for _, source in enumerate(env_vars):
                location = env_vars.get(source, {}).get("value", None)
                try:
                    self._fetch_yara_source(location)
                except Exception as error:
                    message = f"Connection to {source}|{location} failed with {error}"
                    return self._return_with_message(message, action_result, APP_ERROR)
        else:
            message = (
                "No asset environment variables configured.  Add URL sources to fetch!"
            )
            return self._return_with_message(message, action_result, APP_ERROR)

        message = "Connected to all sources!"
        return self._return_with_message(message, action_result)

    def _handle_clear_sources(self, param) -> RetVal:
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        import shutil

        for file in Path(PurePath(self.state_dir, param.get("path", ""))).iterdir():
            if not file.name.endswith("state.json"):
                try:
                    self.save_progress(f"Clearing structure at {file}")
                    action_result.add_data({"name": file.name, "directory": True})

                    shutil.rmtree(str(file))
                except NotADirectoryError:
                    file.unlink(missing_ok=True)
                    action_result.add_data({"name": file.name, "directory": False})
                except Exception as error:
                    return self._return_with_message(
                        f"Failed removing files -- {error}", action_result, APP_ERROR
                    )
        return self._return_with_message("Cleaned up!", action_result)

    def _handle_list_sources(self, param) -> RetVal:
        """
        List all directories in app's state_dir unless user has provided
        param.get("extension").  If it is provided, limit search to
        the files and directories matched in the provided glob.

        Optionally, set stat_info to get os.stat_result info for each file
        found.
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        extension: str = param.get("path", "*")
        for file in Path(self.state_dir).glob(extension):
            if not file.name.endswith("state.json"):
                file_info = {}
                if param.get("stat_info", False):
                    file_info = Path(file).stat()
                action_result.add_data(
                    {
                        **{"name": str(Path(file))},
                        **{
                            key: getattr(file_info, key)
                            for key in dir(file_info)
                            if key.startswith("st_")
                        },
                    }
                )

        return self._return_with_message("Listed sources!", action_result)
    
    def _handle_test_connectivity(self, param) -> RetVal:

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        self.save_progress("Calling update_sources as both actions use the same endpoint")
        return self._handle_update_sources(param)

    def _handle_yara_scan(self, param) -> RetVal:
        """
        Look up all files in self.state_dir found in provided yara_path, defaulting
        to all files in self.state_dir, something we may or may not want depending
        on the source that was downloaded.

        scan_dir is the target of our yara search. If not provided, we're expecting
        a container_id to use for looking up the contents of a vault for scanning.

        Optionally, set a boolean for whether or not the include directive should
        be allowed when yara compiles any specified files.
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        cached_ruleset = hashlib.blake2b(
            f"{param.get('yara_path', '**')}".encode()
        ).hexdigest()
        try:
            rules = yara.load(f"{self.state_dir}/{cached_ruleset}")
        except yara.Error as error:
            self.save_progress(error)
            self.save_progress("No cached compiled rule set found, compiling now...")
            try:
                rules = yara.compile(
                    filepaths={
                        file.name: str(file)
                        for file in Path(self.state_dir).glob(
                            param.get("yara_path", "**/*.yar")
                        )
                    },
                    includes=param.get("use_includes", False),
                )
                rules.save(f"{self.state_dir}/{cached_ruleset}")
            except NotImplementedError as error:
                self.save_progress("You cannot use non-relative path patterns here!")
                return self._return_with_message(str(error), action_result, APP_ERROR)

        # Sends param with user-provided inputs to dataclass and only initialize with those values defined
        # in the class signature.  Then, unpack to keyword arguments for set_config()
        yara.set_config(**vars(yara_config.YaraConfig.from_params((param))))

        if param.get("scan_dir", None) and param.get("vault_id", None):
            self._return_with_message(
                "You can only specify one of scan_dir and vault_id here.",
                action_result,
                APP_ERROR,
            )

        scan_location: str = param.get(
            "scan_dir", vault.vault_info(vault_id=param.get("vault_id"))
        )
        self.save_progress(f"Scanning {scan_location} with loaded Yara rules")
        for file in Path(scan_location).glob("**/*"):
            if not file.is_dir():
                try:
                    self.save_progress(f"Scanning {file}")
                    matches = rules.match(
                        filepath=str(file.resolve()),
                        fast=param.get("fast_mode", False),
                        timeout=param.get("timeout", 60),
                    )
                    if matches:
                        for match in matches:
                            self.save_progress(f"Found match for {match.rule}")
                            action_result.add_data(
                                {
                                    "rule": match.rule,
                                    "namespace": match.namespace,
                                    "tags": match.tags,
                                    "meta": match.meta,
                                    "strings": match.strings,
                                    "file": str(file),
                                }
                            )
                except yara.TimeoutError:
                    message = f"Timeout when scanning {file}.  Specify a larger timeout and try again."
                    return self._return_with_message(message, action_result, APP_ERROR)

        return self._return_with_message(
            f"Finished scanning {scan_location}", action_result
        )

    def handle_action(self, param: Dict[str, Any]) -> RetVal:
        ret_val = APP_SUCCESS

        action_id = self.get_action_identifier()
        self.debug_print("action_id ", action_id)

        if action_id == "yara_scan":
            ret_val = self._handle_yara_scan(param)

        if action_id == "list_yara_sources":
            ret_val = self._handle_list_sources(param)

        if action_id == "clear_yara_sources":
            ret_val = self._handle_clear_sources(param)

        if action_id == "update_yara_sources":
            ret_val = self._handle_update_sources(param)

        if action_id == "test_connectivity":
            # Not a typo.  This will return early if running test_connectivity
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self) -> bool:
        self._state = self.load_state()
        self.state_dir = self.get_state_dir()

        return APP_SUCCESS

    def finalize(self) -> bool:
        self.save_state(self._state)
        return APP_SUCCESS


def main():
    import argparse
    import json

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = YaraConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify)
            csrftoken = r.cookies.get("csrftoken", None)

            data = {
                "username": username,
                "password": password,
                "csrfmiddlewaretoken": csrftoken,
            }

            headers = {"Cookie": f"csrftoken={csrftoken}", "Referer": login_url}

            print("Logging into Platform to get the session id")
            r2 = requests.post(
                login_url, verify=verify, data=data, headers=headers
            )
            session_id = r2.cookies.get("sessionid")
        except Exception as e:
            print(f"Unable to get session id from the platform. Error: {e}")
            sys.exit(1)

    with open(args.input_test_json) as filename:
        in_json = json.load(filename)
        print(json.dumps(in_json, indent=4))

        connector = YaraConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])  # type: ignore  # Pylance

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)


if __name__ == "__main__":
    main()

# File: yara_config.py
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

import inspect
from dataclasses import dataclass
from typing import Optional

from yara_consts import YARA_DEFAULT_MAX_MATCH_DATA, YARA_DEFAULT_MAX_STRINGS_PER_RULE, YARA_DEFAULT_STACK_SIZE


@dataclass
class YaraConfig:
    stack_size: Optional[int] = YARA_DEFAULT_STACK_SIZE
    max_strings_per_rule: Optional[int] = YARA_DEFAULT_MAX_STRINGS_PER_RULE
    max_match_data: Optional[int] = YARA_DEFAULT_MAX_MATCH_DATA

    @classmethod
    def __getitem__(cls, key):
        return dict(zip(inspect.signature(cls).parameters, list(cls.keys())))[key]

    @classmethod
    def keys(cls):
        return inspect.signature(cls).parameters

    @classmethod
    def from_params(cls, params):
        """
        Takes param dictionary passed by SOAR and filters any values unknown to YaraConfig
        so we can initialize Yara with user-provided settings, if provided, or default to YARA_*
        """

        return cls(
            **{
                k: int(v)
                for k, v in params.items()
                if k in inspect.signature(cls).parameters
            }
        )

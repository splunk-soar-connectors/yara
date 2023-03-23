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

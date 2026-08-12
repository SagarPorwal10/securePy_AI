from securepy_ai.scanner.rules.hardcoded_secret import HardcodedSecretRule
from securepy_ai.scanner.rules.sql_injection import SQLInjectionRule
from securepy_ai.scanner.rules.command_injection import CommandInjectionRule
from securepy_ai.scanner.rules.insecure_deserialization import InsecureDeserializationRule
from securepy_ai.scanner.rules.unsafe_exec_eval import UnsafeExecEvalRule


ALL_RULES = [
    HardcodedSecretRule,
    SQLInjectionRule,
    CommandInjectionRule,
    InsecureDeserializationRule,
    UnsafeExecEvalRule,
]

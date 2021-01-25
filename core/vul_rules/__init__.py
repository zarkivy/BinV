from .double_free import check
from .format_string_bug import check
from .integer_overflow import check
from .stack_overflow import check
from .use_after_free import check


def getVulRules(rules_string : str) -> list[str] :
    code_vul_dict = {
        '1' : 'double_free',
        '2' : 'format_string_bug',
        '3' : 'integer_overflow',
        '4' : 'stack_overflow',
        '5' : 'use_after_free',
    }
    rules_list = []
    for rule_code in code_vul_dict.keys() :
        if rule_code in rules_string :
            rules_list.append(code_vul_dict[rule_code])
    return rules_list
from .scanner import *
from .utils import *
import vul_rules
import re


def binvHelp(args) :
    print("[HELP]")


def binvManu(args) :
    pass


# the entry of option-scan
def binvScan(args) :
    if not re.match(r"^-\d+$", args[0]) :
        log("Usage : -<rules>", ORA)
        return
    for file_name in args[1:] :
        log("Analysing '{}'".format(file_name), CYA)
        rules_string, file_name = args[0], args[1:]
        rules = vul_rules.getVulRules(rules_string)
        scanner = Scanner(rules, file_name)
        scanner.doScan()



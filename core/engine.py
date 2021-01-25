from .scanner import *
from .utils import *
from .vul_rules import *
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
    else : 
        rules_string = args[0]
        
    for file_name in args[1:] :
        log("Analysing '{}'".format(file_name), CYA)
        rules = getVulRules(rules_string)
        scanner = Scanner(rules, file_name)
        scanner.doScan()



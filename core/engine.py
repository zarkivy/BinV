from .scanner import Scanner
from .utils import log, DRED, GRE, ORA, GRA, RST
from .vul_rules import getVulRules
from shutil import get_terminal_size
import re


def binvShow() :
    print(R'''
    1 - double free
    2 - format string bug
    3 - stack overflow
    4 - use after free
    ''')


def binvManu() :
    log("< MANU >", GRA)


# the entry of option-scan
def binvScan(targets, rules_string) :
    # check subarg-rules' regexp format
    if not re.match(r"^\d+$", rules_string) :
        log("Format error, rules' regexp format: ^\\d+$", DRED)
        return
    else :
        rules = getVulRules(rules_string)

    try :
        # check vulnerabilities for each elf file
        for file_name in targets :
            print("="*get_terminal_size().columns, end="")
            log("Analysing '{}'\n".format(file_name), GRE)
            scanner = Scanner(rules, file_name)
            scanner.doScan()
        log("DONE!", GRE)
    except KeyboardInterrupt :
        print("\r")
        log("Keyboard interrupt", ORA)
        exit()



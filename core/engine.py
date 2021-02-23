from .scanner import Scanner
from .utils import log, RED, CYA, ORA, GRA, LGRE, RST
from .vul_rules import getVulRules
from shutil import get_terminal_size
import re


def binvShow() :
    log("< SHOW >", GRA)


def binvManu() :
    log("< MANU >", GRA)


# the entry of option-scan
def binvScan(targets, rules) :
    # check subarg-rules' format
    if not re.match(r"^\d+$", rules) :
        log("Rules format: ^\\d+$", RED)
        return
    else :
        rules = getVulRules(rules)

    try :
        # check vulnerabilities for each elf file
        for file_name in targets :
            print("="*get_terminal_size().columns, end="")
            log("Analysing '{}'\n".format(file_name), CYA)
            scanner = Scanner(rules, file_name)
            scanner.doScan()
    except KeyboardInterrupt :
        print("\r")
        log("Keyboard interrupt", ORA)
        exit()



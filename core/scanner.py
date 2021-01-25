from .vul_rules import *
import sys


# Vulerabilites scanner for a single file
class Scanner :
    def __init__(self, rules, file_name) :
        self.rules = rules
        self.file_name = file_name
        
    def doScan(self) :
        for rule in self.rules :
            if hasattr(sys.modules[__name__], rule) :
                getattr(sys.modules[__name__], rule).check(self.file_name)
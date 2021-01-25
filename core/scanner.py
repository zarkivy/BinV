import vul_rules

# Vulerabilites scanner for a single file
class Scanner :
    def __init__(self, rules, file_name) :
        self.rules = rules
        self.file_name = file_name
        self.file_fd = 

    def doScan() :
        for rule in rules :
            if hasattr(vul_rules, rule) :
                getattr(vul_rules, rule).check(file_fd)
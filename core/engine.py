from .scanner import * 

# command implementations
def binvHelp(args) :
    print("[HELP]")

def binvManu(args) :
    pass

def binvScan(args) :
    for file_name in args :
        log("Analysing '" + file_name + "'")
        doScan(rule, file_name)
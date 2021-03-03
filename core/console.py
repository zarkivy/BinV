from .__info__ import __logo__
from .utils import log, PUR, GRE, GRA, RED, ORA, RST
from .engine import binvShow, binvScan, binvManu
import readline

# console mode entry
def initConsole() :
    binv_interpreter = BinvInterpreter()
    binv_interpreter.loopMain()


# console mode handler
class BinvInterpreter() :

    global_help = \
    '''
avaliable commands:
  scan -t [elf ...] -r rule_id_set
                        scan ELF files with specific rules' id
  help                  print this help menu
  show                  show available vulnerabilities' rules
  manu                  print BinV manual
  exit                  exit BinV
    '''

    def __init__(self) :
        self.global_commands = ['scan', 'help', 'show', 'manu', 'exit']

    # console main loop
    def loopMain(self) :
        print(__logo__)
        print(self.global_help)
        while True :
            try :
                command, args = self.parseCommandLine(input(self.line_prompt))
                command = command.lower()
                handleCommand = self.getCommandHandler(command)
                handleCommand(args)
            except TypeError : # getCommandHandler() returns False
                log("Unknown command : '{}'".format(command), RED)
                continue
            except KeyboardInterrupt :
                log("Keyboard interrupt", ORA)
                break

    # the prompt as new command line's header
    @property
    def line_prompt(self) :
        return GRA + ">>> " + RST

    # parse a line of string into command & args
    def parseCommandLine(self, command_line) :
        argv_list = command_line.split(" ")
        return argv_list[0], argv_list[1:]

    # get the corresponding command
    def getCommandHandler(self, command) :
        try :
            command_handler = getattr(self, "handle{}Command".format(command.title()))
        except AttributeError :
            return False
        return command_handler

    # command handlers :
    def handleScanCommand(self, args) :
        try :
            targets, rules = parseConsoleScanArgs(args)
            binvScan(targets, rules)
        except TypeError : # parseConsoleScanArgs returns False, Fasle
            log("usage: scan [-h] [-t [elf ...]] [-r rule_id_set]", RED)
            
    def handleHelpCommand(self, args) :
        self.consoleHelp()

    def handleShowCommand(self, args) :
        binvShow()

    def handleManuCommand(self, args) :
        binvManu()

    def handleExitCommand(self, args) :
        exit()

    def consoleHelp(self) :
        print(self.global_help)


def parseConsoleScanArgs(args):
    if '-t' not in args or '-r' not in args :
        return False, False
    if args[ len(args) - args[::-1].index('-t') : args.index('-r')] != [] :
        return args[len(args) - args[::-1].index('-t') : args.index('-r')], args[args.index('-r') + 1]
    if args[ len(args) - args[::-1].index('-r') : args.index('-t')] != [] :
        return args[args.index('-t') + 1 : ], args[args.index('-r') + 1]
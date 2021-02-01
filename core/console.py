from .__info__ import __logo__
from .utils import log, PUR, GRE, GRA, RED, ORA, RST
from .engine import binvHelp, binvScan, binvManu

# console mode entry
def initConsole() :
    binv_interpreter = BinvInterpreter()
    binv_interpreter.loopMain()


# console mode handler
class BinvInterpreter() :

    global_help = \
    '''
avaliable commands:
  help                  print this help menu
  scan [elf ...]        scan ELF files
  exit                  exit BinV
    '''

    def __init__(self) :
        self.global_commands = ['help', 'scan', 'exit']

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
            except EOFError :
                print("\n" + ORA + "Exit console mode ..." + RST)
                break
            except KeyboardInterrupt :
                print("\n" + ORA + "Keyboard interrupt ..." + RST)
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
            print(RED + "Unknown command : '{}'".format(command) + RST)
            return False
        
        return command_handler

    # command handlers :
    def handleHelpCommand(self, args) :
        binvHelp(args)

    def handleScanCommand(self, args) :
        binvScan(args)

    def handleExitCommand(self, args) :
        exit()

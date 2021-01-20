from .__info__ import __logo__
from .utils import *


# console mode handler
class BinvInterpreter() :

    global_help = __logo__ +                                \
    BLU +                                                   \
    '''
Commands :
    help                                Print this help menu
    scan                                Scan a ELF file
    '''                                                     \
    + RST

    def __init__(self) :
        self.global_commands = ['help', 'scan']

    # console main loop
    def mainLoop(self) :
        print(self.global_help)
        while True :
            try :
                command, args = self.parseCommandLine(input(self.line_prompt))
                command = command.lower()
                handleCommand = self.getCommandHandler(command)
                handleCommand(args)
            except EOFError :
                print(ORA + "Exit console mode ..." + RST)
                break
            except KeyboardInterrupt :
                print(ORA + "Keyboard interrupt ..." + RST)
                break

    # the prompt as new command line's header
    @property
    def line_prompt(self) :
        return PUR + "BinV" + RST + " >>> "

    # parse a line of string into command & args
    def parseCommandLine(self, command_line) :
        return "help", " "

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
        print("[HELP]\n")

    def handleScanCommand(self, args) :
        print("[SCAN]\n")

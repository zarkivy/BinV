from .engine import *
from .console import *
from .__info__ import __title__, __logo__
import argparse

def parseArgs() :
    args_parser = argparse.ArgumentParser(prog=__title__, description=__logo__, formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS)
    args_parser.add_argument('-s', '--scan', action='store',metavar='elf' , nargs='*', help="scan ELF files")
    args_parser.add_argument('-c', '--console', action='store_true', help="enter console mode")
    args_parser.add_argument('-m', '--manual', action='store_true', help="print BinV manual")
    args = args_parser.parse_args()
    
    if args.scan != None :
        binvScan(args.scan)
    
    if args.console == True :
        initConsole()
        exit()

    if args.manual == True :
        binvManu()
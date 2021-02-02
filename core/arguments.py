from .engine import binvScan, binvManu, binvShow
from .console import initConsole
from .__info__ import __title__, __logo__
from .utils import log, RED
import argparse

def parseArgs() :
    # construct args' parser
    args_parser = argparse.ArgumentParser(prog=__title__, description=__logo__, formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS)
    sub_parsers = args_parser.add_subparsers()

    # binv scan parser
    scan_parser = sub_parsers.add_parser("scan", help="scan target path", formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
    scan_parser.add_argument("scan", action="store_true", help=argparse.SUPPRESS)
    scan_parser.add_argument("-t", "--target", action="store", metavar="elf", nargs="*", help="scan ELF files")
    scan_parser.add_argument("-r", "--rule", action="store", metavar="rule_id_set", help="specify target vulerabilities' rules")

    # binv console parser
    console_parser = sub_parsers.add_parser("console", help="enter console mode", formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
    console_parser.add_argument("console", action="store_true", help=argparse.SUPPRESS)

    # binv manual parser
    manual_parser = sub_parsers.add_parser("manual", help="print manual", formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
    manual_parser.add_argument("manual", action="store_true", help=argparse.SUPPRESS)

    # binv show parser
    show_parser = sub_parsers.add_parser("show", help="show available vulnerabilities' rules", formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
    show_parser.add_argument("show", action="store_true", help=argparse.SUPPRESS)

    # do parse
    args = args_parser.parse_args() 

    # scan
    if hasattr(args, "scan") :
        # check scan mode parameters' legality
        if args.target == None or args.rule == None :
            scan_parser.print_help()
            exit()
        # scan mode entry
        binvScan(args.target, args.rule)
        exit()

    # console mode entry
    if hasattr(args, "console") :
        initConsole()
        exit()

    # show entry
    if hasattr(args, "show") :
        binvShow()
        exit()

    # manual entry
    if hasattr(args, "manual") :
        binvManu()
        exit()

    # ./binv
    args_parser.print_help()
import time


# ANSI fonts
RST = "\x1b[0m"
RED = "\x1b[31m"
GRE = "\x1b[32m"
ORA = "\x1b[33m"
BLU = "\x1b[34m"
PUR = "\x1b[35m"
CYA = "\x1b[36m"
WHI = "\x1b[37m"
GRA = "\x1b[1;30m"
DRED = "\x1b[1;31m"
LGRE = "\x1b[1;32m"
YEL = "\x1b[1;33m"
AZU = "\x1b[1;34m"
DPUR = "\x1b[1;35m"
DCYA = "\x1b[1;36m"
WARN = "\x1b[5;31m"


def log(log_string, color) :
    print("{}[ {} ] {}".format(color, time.asctime().split(' ')[-2], log_string) + RST)
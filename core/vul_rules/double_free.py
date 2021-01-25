from ..utils import *
import angr


def check(file_name) :
    #project = angr.Project(file_name, load_options={'auto_load_libs':False})
    log("Checking DF", GRE)
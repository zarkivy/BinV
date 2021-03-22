from ..utils import log, RED, CYA, DRED, RST
import angr


def check(file_name) :
    log("Checking STACK OVERFLOW", CYA)

    try :
        project = angr.Project(file_name)
    except :
        log("Path does not point to a valid binary file: " + file_name + "\n", DRED)
        return
    init_state = project.factory.entry_state()
    simgr = project.factory.simulation_manager(init_state, save_unconstrained=True)

    while simgr.active :
        simgr.step()

    if simgr.unconstrained :
        for unconstrained_state in simgr.unconstrained :
            log("STACK OVERFLOW detected! payload :", RED)
            print("{}< payload >{}\n".format(DRED, RST), unconstrained_state.posix.dumps(0))

    print()
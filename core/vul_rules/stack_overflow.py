from ..utils import log, RED, GRE, DRED, RST
import angr


def check(file_name) :
    log("Checking STACK OVERFLOW", GRE)

    try :
        project = angr.Project(file_name)
    except :
        log("Not a valid binary file: " + file_name + "\n", RED)
        return
    state = project.factory.entry_state()
    simulation = project.factory.simulation_manager(state, save_unconstrained=True)

    while simulation.active :
        simulation.step()

    if simulation.unconstrained :
        for unconstrained_state in simulation.unconstrained :
            log("STACK OVERFLOW detected! payload :", RED)
            print("{}< payload >{}\n".format(DRED, RST), unconstrained_state.posix.dumps(0))

    print()
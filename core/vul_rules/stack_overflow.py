from ..utils import *
import angr


def check(file_name) :
    #project = angr.Project(file_name, load_options={'auto_load_libs':False})
    log("Checking SOF", GRE)

    project = angr.Project(file_name)
    state = project.factory.entry_state()
    simulation = project.factory.simulation_manager(state, save_unconstrained=True)

    while simulation.active :
        simulation.step()

    if simulation.unconstrained :
        for unconstrained_state in simulation.unconstrained :
            log("SOF detected! payload = \n{}".format(unconstrained_state.posix.dumps(0)), RED)
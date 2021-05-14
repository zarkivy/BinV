from ..utils import log, RED, CYA, DRED, RST
from angr import sim_options
import angr, psutil, os, claripy


def checkWriteStackMem(cur_state: angr.SimState):
    for act in cur_state.history.actions:
        if (act.type == 'mem') \
        and (act.action == 'write') \
        and type(act.size.ast) == claripy.ast.bv.BV :
            print("Write mem: {} : {} : {}".format(hex(act.actual_addrs[0]), act.size.ast, type(act.size.ast))) 
            return True
    return False


def check(file_name) :
    log("Checking STACK OVERFLOW", CYA)

    try :
        project = angr.Project(file_name)
    except :
        log("Path does not point to a valid binary file: " + file_name + "\n", DRED)
        return
    extra_option = {sim_options.REVERSE_MEMORY_NAME_MAP,
                    sim_options.TRACK_ACTION_HISTORY,
                    sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    init_state = project.factory.entry_state(add_options=extra_option)
    simgr = project.factory.simulation_manager(init_state, save_unconstrained=True)
    simgr.use_technique(angr.exploration_techniques.DFS())

    while simgr.active :
        simgr.move(filter_func=checkWriteStackMem,
                   from_stash='active', to_stash='writed_stack')
        if hasattr(simgr, 'writed_stack') :
            while simgr.writed_stack :
                simgr.step('writed_stack')
                if simgr.unconstrained :
                    for unconstrained_state in simgr.unconstrained :
                        log("STACK OVERFLOW detected! payload :", RED)
                        print("{}< payload >{}\n".format(DRED, RST), unconstrained_state.posix.dumps(0))
                        print(u'\nmemory consumed：%.4f MB\n' % (psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024) )
                        return
        simgr.step('active')
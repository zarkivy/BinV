from ..utils import log, CYA, RED, DRED, RST, BLU
from ..prune_algorithms import isSimilarPath, getInterProp
import angr
from angr import sim_options
import logging

logging.getLogger('angr').setLevel('ERROR')

paths_with_bug = []     


'''
class free(angr.SimProcedure):
    def run(self, ptr):
        self.state.heap._free(ptr)
'''
# TODO : whether mallocing a freed address is ignored by angr's procedure
class FreeHook(angr.procedures.libc.free.free) :
    def run(self, ptr) :
        free_addr = self.state.solver.eval(ptr)
        # init the free list for current execution path
        if "FREE_LIST" not in self.state.globals :
            self.state.globals["FREE_LIST"] = []
        self.state.globals["FREE_LIST"].append(free_addr)
        
        return self.state.heap._free(ptr)


def checkUAF(cur_state: angr.SimState) :
    # has not FREE yet
    if "FREE_LIST" not in cur_state.globals :
        cur_state.globals["ACTS_BEFORE_FREE"] = \
            [ act for act in reversed(cur_state.history.actions.hardcopy) ]
    # after FREE occured
    else :
        new_actions = [ act 
                        for act in reversed(cur_state.history.actions.hardcopy) 
                        if act not in cur_state.globals["ACTS_BEFORE_FREE"] ]
        for act in new_actions :
            if (act.type == 'mem') \
               and (act.action == 'read' or act.action == 'write') \
               and (act.actual_addrs[0] in cur_state.globals["FREE_LIST"]) :
               # and not isSimilarPath([bbl_addr for bbl_addr in cur_state.history.bbl_addrs], paths_with_bug) :
                log("USE AFTER FREE detected! IO dump :", RED)
                print("{}< stdin >{}\n".format(DRED, RST), cur_state.posix.dumps(0))
                print("{}< stdout >{}\n".format(DRED, RST), cur_state.posix.dumps(1).decode())
                paths_with_bug.append([bbl_addr for bbl_addr in cur_state.history.bbl_addrs])


def pruneRepeatPath(cur_state: angr.SimState) :
    return isSimilarPath([bbl_addr for bbl_addr in cur_state.history.bbl_addrs], paths_with_bug, ratio=0.5)


def check(file_name: str) -> None :
    log("Checking USE AFTER FREE", CYA)

    try :
        project = angr.Project(file_name, load_options={'auto_load_libs': False})
    except :
        log("Not a valid binary file: " + file_name + "\n", DRED)
        return

    project.hook_symbol('free', 
                        FreeHook(cc=project.factory.cc(func_ty="void free(void*)")), 
                        replace=True)

    extra_option = {sim_options.REVERSE_MEMORY_NAME_MAP, 
                    sim_options.TRACK_ACTION_HISTORY, 
                    sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    init_state = project.factory.entry_state(add_options=extra_option)
    simgr = project.factory.simulation_manager(init_state, veritesting=True, save_unconstrained=True)

    # use dfs to search for vulnerabilities as quickly as possible instead of as comprehensively as possible
    # angr uses bfs by default
    # 经测试，对于无限循环的程序，DFS 基本不可用，因为其会深入探索一条无限长的执行路径而陷入死循环
    # simgr.use_technique(angr.exploration_techniques.DFS())

    # use disk dump to reduce memory usage if it's necessary
    # simgr.use_technique(angr.exploration_techniques.Spiller())

    while simgr.active:
        for act_state in simgr.active:
            checkUAF(act_state)
        # pruning
        simgr.move(filter_func=pruneRepeatPath, from_stash='active', to_stash='deadend')
        simgr.step()
from ..utils import log, GRE, RED, DRED, RST
from ..prune_algorithms import checkPathSimilarity
import angr
from angr import sim_options


paths_with_bug = []


'''
class malloc(angr.SimProcedure):
    def run(self, sim_size):
        return self.state.heap._malloc(sim_size)
'''
class MallocHook(angr.procedures.libc.malloc.malloc) :
    def run(self, sim_size) :
        malloc_addr = self.state.heap._malloc(sim_size)
        malloc_size = self.state.solver.eval(sim_size)
        # init the malloc list for current execution path
        if "MALLOC_LIST" not in self.state.globals :
            self.state.globals["MALLOC_LIST"] = {}
        # record a new malloc-call into the malloc list
        self.state.globals["MALLOC_LIST"][malloc_addr] = malloc_size
        return malloc_addr        


'''
class free(angr.SimProcedure):
    def run(self, ptr):
        self.state.heap._free(ptr)
'''
class FreeHook(angr.procedures.libc.free.free) :
    def run(self, ptr) :
        free_addr = self.state.solver.eval(ptr)
        # init the free list for current execution path
        if "FREE_LIST" not in self.state.globals :
            self.state.globals["FREE_LIST"] = {}
            # if free a malloced address, record it
            if ("MALLOC_LIST" in self.state.globals) and (free_addr in self.state.globals["MALLOC_LIST"]) :
                self.state.globals["FREE_LIST"][free_addr] = self.state.globals["MALLOC_LIST"][free_addr]
        else :
            # if free address is already in free list, alert DOUBLE FREE 
            # and is a new path containning bug          
            if free_addr in self.state.globals["FREE_LIST"] \
               and not checkPathSimilarity([bbl_addr for bbl_addr in self.state.history.bbl_addrs], paths_with_bug) :
                log("DOUBLE FREE detected! IO dump :", RED)
                print("{}< stdin >{}\n".format(DRED, RST), self.state.posix.dumps(0))
                print("{}< stdout >{}\n".format(DRED, RST), self.state.posix.dumps(1))
                paths_with_bug.append([bbl_addr for bbl_addr in self.state.history.bbl_addrs])
        
        return self.state.heap._free(ptr)


def checkUAF(cur_state: angr.SimState) -> None :
    # has not FREE yet
    if "FREE_LIST" not in cur_state.globals :
        cur_state.globals["ACTS_BEFORE_FREE"] = \
            [ act for act in reversed(cur_state.history.actions.hardcopy) ]
    # after FREE occured
    else :
        new_actions = [ act \
                        for act in reversed(cur_state.history.actions.hardcopy) \
                        if act not in cur_state.globals["ACTS_BEFORE_FREE"] \
                      ]
        for act in new_actions :
            if (act.type == 'mem') \
               and (act.action == 'read' or act.action == 'write') :
                for free_addr in cur_state.globals["FREE_LIST"] :
                    if free_addr == act.actual_addrs[0] \
                       and not checkPathSimilarity([bbl_addr for bbl_addr in cur_state.history.bbl_addrs], paths_with_bug) :
                            log("USE AFTER FREE detected! IO dump :", RED)
                            print("{}< stdin >{}\n".format(DRED, RST), cur_state.posix.dumps(0))
                            print("{}< stdout >{}\n".format(DRED, RST), cur_state.posix.dumps(1))
                            paths_with_bug.append([bbl_addr for bbl_addr in cur_state.history.bbl_addrs])



def check(file_name: str) -> None :
    log("Checking UAF", GRE)

    try :
        project = angr.Project(file_name, load_options={'auto_load_libs': False})
    except :
        log("Not a valid binary file: " + file_name + "\n", RED)
        return

    project.hook_symbol('malloc', 
                        MallocHook(cc=project.factory.cc(func_ty="void* malloc(int)")), 
                        replace=True)
    project.hook_symbol('free', 
                        FreeHook(cc=project.factory.cc(func_ty="void free(void*)")), 
                        replace=True)

    extra_option = {sim_options.REVERSE_MEMORY_NAME_MAP, 
                    sim_options.TRACK_ACTION_HISTORY, 
                    sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    state = project.factory.entry_state(add_options=extra_option)
    simgr = project.factory.simulation_manager(state, save_unconstrained=True)

    while simgr.active:
        for act_state in simgr.active:
            checkUAF(act_state)
        simgr.step()
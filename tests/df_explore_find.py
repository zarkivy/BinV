simgr.explore(find=judgeDfFind(cur_state), avoid=judgeDfAvoid(cur_state))

# SE suspicious address got from CFG, [ Priority ]
def judgeDfFind(state) -> bool :

# prune unconcerned address got from CFG, [ Prune ]
def judgeDfAvoid(state) -> bool :



def pruneRepeatPath() :
    # X callstack
    # √ basic block path
    1. save every SimState's address to state.global
    2. get SimState address chain of detected path-with-bugs
    3. caculate path-similarity between current path and path-with-bugs, prune similar


def pruneNoneWriteMemPath() :


def prioritizeMallocFreePath() :
    s.explore(find=malloc_addr, avoid=free_addr, num_find=1, find_stash="malloc")
    s.explore(stash="malloc", find=free_addr, find_stash="malloc_free")
    s.explore(stash="malloc_free", find=free_addr, find_stash="malloc_free_free")
    s.explore(stash="malloc_free_free")
    s.run(stash="malloc_free")
    s.run(stash="malloc")
    s.run(stash="active")
    log("DOUBLE FREE bug free!", GRE)




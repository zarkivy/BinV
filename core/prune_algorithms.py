from .utils import log, ORA

def checkPathSimilarity(cur_path, paths_set, ratio=0.85) -> bool :
    for path in paths_set :
        if isSubPath(cur_path.copy(), path.copy()) :
            # skip sub-path 
            return True
        else :
            prop = getInterProp(cur_path.copy(), path.copy())
            if prop > ratio :
                # skip similar path and report it
                log("Repeated bug-path, similarity: {}".format(prop), ORA)
                return True
    return False

# 判断是否是'有序数组子串'，是'有序交集占比计算'的子集
def isSubPath(sub_path, sup_path) -> bool :
    sub_path.reverse()
    for node in sup_path :
        if sub_path == [] :
            return True
        if node == sub_path[-1] :
            sub_path.pop()
    return False

# 计算'有序交集占比'
def getInterProp(sub_path, sup_path) -> float :
    sub_path_len = len(sub_path)
    sub_path.reverse()
    for node in sup_path :
        if sub_path == [] :
            return 1
        if node == sub_path[-1] :
            sub_path.pop()
    return (sub_path_len - len(sub_path)) / sub_path_len



# TODO below

# optimization for double free
def pruneLoopPath() :
    pass


# 当一个 state 经过的路径重复率达到某个值时，使用 move 将此 state 由 active 移动至 deadend，以达到剪枝效果
def pruneRepreatPath() :
    pass
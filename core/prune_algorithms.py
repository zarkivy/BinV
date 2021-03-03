from .utils import log, ORA


def isSimilarPath(cur_path, paths_set, ratio=0.8) -> bool :
    for path in paths_set :
        prop = getInterProp(cur_path.copy(), path.copy())
        if prop > ratio :
            # skip similar path and report it
            # log("Repeated bug-path, similarity: {}".format(prop), ORA)
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


def getSimilarity(cur_path, paths_set) -> list[float] :
    return [ getInterProp(cur_path.copy(), path.copy()) for path in paths_set ]


# 计算'有序交集占比'
def getInterProp(sub_path, sup_path) -> float :
    sub_path_len, sup_path_len = len(sub_path), len(sup_path)
    for node in sup_path :
        if sub_path == [] :
            return 1
        if node == sub_path[0] :
            sub_path.pop(0)
    return (sub_path_len - len(sub_path)) / sup_path_len


# TODO below

# optimization for double free
def pruneLoopPath() :
    pass
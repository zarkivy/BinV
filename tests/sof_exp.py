import angr

p = angr.Project("./test")
es = p.factory.entry_state()
sm = p.factory.simulation_manager(es, save_unconstrained=True)

while sm.active:
    sm.step()
if sm.unconstrained:
    for un in sm.unconstrained:
        print("stdout:\n",un.posix.dumps(1))
        print("stdin:\n",un.posix.dumps(0),"\n")

# graph.py: agent ka loop. plan -> act -> plan ... jab tak planner kaam khatam na bole.
# Web se aaya text sirf DATA hai. Planner use instruction ki tarah nahi maanta.
from typing import Optional, TypedDict

from langgraph.graph import END, StateGraph


class State(TypedDict):
    task: str
    observations: list
    next: Optional[dict]


def build_graph(planner, run_step):
    def plan(state):
        return {"next": planner(state)}          # None = kaam khatam

    def act(state):
        step = state["next"]
        result = run_step(step["url"], step["action"], step.get("params"))
        return {"observations": state["observations"] + [result], "next": None}

    def route(state):
        return END if state["next"] is None else "act"

    g = StateGraph(State)
    g.add_node("plan", plan)
    g.add_node("act", act)
    g.set_entry_point("plan")
    g.add_conditional_edges("plan", route)
    g.add_edge("act", "plan")
    return g.compile()

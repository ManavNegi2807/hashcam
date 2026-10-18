"""A graph view of a run: who asked for what, what the policy said, who approved it.

The signed receipt stays the only source of truth. The graph is a copy made from what is inside the
receipt, so a person can SEE how a run hangs together. It is display and exploration only: nothing
here verifies anything, and a graph that disagrees with `abb verify` is wrong, never the receipt.
"""

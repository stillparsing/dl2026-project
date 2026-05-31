__all__ = ["Solver"]


def __getattr__(name):
    if name == "Solver":
        from .solver import Solver

        return Solver
    raise AttributeError(name)

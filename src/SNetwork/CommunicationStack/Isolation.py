def strict_isolation(function):
    """
    Create a decorator that will ensure that the function is only called from the stack layer that this function is
    defined in. So if the function is defined in Layer1, it can only be called from Layer1 methods. This is to ensure that
    the stack is used correctly, and that the layers are not being bypassed.
    """

    def wrapper(self, *args, **kwargs):
        if isinstance(self, function.__globals__[function.__qualname__.split(".")[0]]):
            return function(self, *args, **kwargs)
        raise Exception(f"Function {function.__name__} is not allowed to be called from this layer.")

    return wrapper


def cross_isolation(*layer_names):
    """
    Create a decorator that allows cross-layer communication from specific layers. For example, @CrossLayer(2) will
    allow the function to be called from both Layer2 methods, and the layer that the function is defined in.
    """

    def decorator(function):
        def wrapper(self, *args, **kwargs):
            if type(self).__name__ in map(lambda x: f"Layer{x}", layer_names):
                return function(self, *args, **kwargs)
            raise Exception(f"Function {function.__name__} is not allowed to be called from this layer.")

        return wrapper

    return decorator


__all__ = ["strict_isolation", "cross_isolation"]

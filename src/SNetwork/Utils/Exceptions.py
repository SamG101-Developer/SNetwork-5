from SNetwork.Utils.Types import Callable, Type


def if_not_throws(function: Callable, *exceptions: Type[Exception]) -> bool:
    try:
        function()
        return True
    except exceptions or Exception:
        return False

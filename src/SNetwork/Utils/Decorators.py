# Decorator that runs a NoReturn function but allows for a KeyboardInterrupt to be raised and caught.
def no_return_interruptable(func):
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except KeyboardInterrupt:
            pass
    return wrapper

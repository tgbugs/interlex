from functools import wraps

class IlxException(Exception):
    pass

class LoadError(IlxException):
    def __init__(self, message, code=400):
        self.message = message
        self.code = code

    @property
    def external_return(self):
        return self.message, self.code

def hasErrors(*error_types):
    def decorator(method):
        @wraps(method)
        def wrapped(*args, **kwargs):
            try:
                return method(*args, **kwargs)
            except error_types as e:
                return e.external_return
        return wrapped
    return decorator

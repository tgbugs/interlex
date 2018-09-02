from functools import wraps
#import sqlalchemy as sa

class IlxException(Exception):
    pass

class NotGroup(IlxException):
    pass

class ShouldNotHappenError(IlxException):
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

def bigError(method):
    @wraps(method)
    def wrapped(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        #except sa.exc.InternalError as e:
        except BaseException as e:
            if hasattr(e, 'orig'):
                if len(e.statement) > 1000:
                    e.statement = e.statement[:1000] + ' ... TRUNCATED'
                if len(e.params) > 20:
                    e.params = {}

            raise e
    return wrapped

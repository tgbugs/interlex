from time import sleep
from flask import has_app_context
from celery import Celery, Task
from interlex import config
from interlex.load import FileFromIRIFactory
from IPython import embed
from pprint import pprint


class fCelery(Celery):
    def init_app(self, app):
        self.conf.update(app.config)  # this is just so the info is available
        # these shouldn't change since they source from the same config
        # but just in case ...
        self.conf.update(broker_url=app.config['CELERY_BROKER_URL'],
                         result_backend=app.config['CELERY_RESULT_BACKEND'])

        class ContextTask(Task):
            cel = self
            def __call__(self, *args, wat=self, **kwargs):
                if has_app_context():  # calling tasks inside tasks
                    return self.run(*args, **kwargs)
                else:
                    with app.app_context():
                        return self.run(*args, **kwargs)

            @property
            def session(self):
                return self.cel.session

        self.Task = ContextTask

    @property
    def session(self):
        return self.db.session   # maybe this will work?


cel = fCelery('InterLex', enable_utc=True,
              backend=config.broker_backend,  # have to set backend here or the worker will have no backend
              broker=config.broker_url,
              #task_track_started = True,
              #result_persistent=True,  # only persists on broker restart
)
cel.conf.update(CELERY_ACCEPT_CONTENT=config.accept_content)


@cel.task
def add(x, y):
    return x + y


@cel.task(bind=True)
def multiple(self, loader, name, expected_bound_name, small=True):
    # fail on the easy stuff early
    #yield 'does this work?'  # nope!
    if small:
        sleep(1)
        self.update_state(state='TRYING_LOAD', meta={'status':'TRYFORLOAD'})
        return 'woo a small one!'
    else:
        self.update_state(state='TOO_BIG')
        task = bigload.delay(loader)
        return task.id

    # if our quick checks don't pass
    #embed()

@cel.task(bind=True)
def long_ffi(self, group, user, reference_name, reference_host,
             name, expected_bound_name, header=None, serialization=None):
    pprint(dir(self))
    # sadly cannot embed in a work :/
    FileFromIRI = FileFromIRIFactory(self.app.session)
    ffi = FileFromIRI(user, group, reference_name, reference_host)
    ffi.check(name)
    ffi.check(name)
    setup_failed = ffi(expected_bound_name)
    if not setup_failed:
        ffi.load()


@cel.task(bind=True)
def long_load(self, loader, expected_bound_name):
    setup_failed = loader(expected_bound_name)
    if setup_failed:
        return 'OOPS TODO'

    return loader.load()  # TODO error handling

@cel.task(bind=True)#, ignore_result=True)
def bigload(self, loader):
    #self.update_state('this is going to take awhile')
    sleep(1)
    self.update_state(state='STARTING')
    sleep(3)
    return 'actually done now'

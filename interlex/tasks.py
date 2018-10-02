from time import sleep
from flask import has_app_context
from celery import Celery, Task
from celery.signals import worker_process_init, worker_process_shutdown
from interlex import config
from interlex.core import getScopedSession
from interlex.load import FileFromIRIFactory, FileFromPostFactory
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
            def __call__(self, *args, wat=self, **kwargs):
                if has_app_context():  # calling tasks inside tasks
                    return self.run(*args, **kwargs)
                else:
                    with app.app_context():
                        return self.run(*args, **kwargs)

        self.Task = ContextTask


session = None


@worker_process_init.connect
def init_worker(**kwargs):
    global session
    print(f'Initializing database connection to {config.database} for worker.')
    session = getScopedSession()


@worker_process_shutdown.connect
def shutdown_worker(**kwargs):
    session
    if session:
        print(f'Closing database connectionn to {config.database} for worker.')
        session.close()  # remove() ??


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

class FakeSelf:
    def update_state(self, *args, **kwargs):
        """ hahahaha you think I'm actually doing something silly caller """

fakeself = FakeSelf()

def base_ffi(group, user, reference_name, reference_host,
             name, expected_bound_name, header=None, serialization=None,
             self=fakeself):
    global session
    # sadly cannot embed in a worker :/
    FileFromIRI = FileFromIRIFactory(session)
    ffi = FileFromIRI(user, group, reference_name, reference_host)
    self.update_state(state='CHECKING')
    check_failed = ffi.check(name)  # should have already been run
    self.update_state(state='SETUP')
    setup_failed = ffi(expected_bound_name)
    self.update_state(state='LOAD')
    if not setup_failed:
        ffi.load()
    self.update_state(state='SUCCESS')  # FIXME use the real success value
    return 'done'

@cel.task(bind=True)
def long_ffi(self, group, user, reference_name, reference_host,
             name, expected_bound_name, header=None, serialization=None):
    #pprint(dir(self))
    return base_ffi(group, user, reference_name, reference_host,
                    name, expected_bound_name, header, serialization, self=self)
    # TODO logging and stats


@cel.task(bind=True)
def long_ffp(self, group, user, reference_host, serialization, header, create):
    global session
    #pprint(dir(self))
    FileFromPost = FileFromPostFactory(session)
    ffp = FileFromPost(group, user, reference_host)
    self.update_state(state='CHECKING')
    check_failed = ffp.check(name, None, header, ser=serialization)  # should have already been run
    self.update_state(state='SETUP')
    setup_failed = ffp(create)
    self.update_state(state='LOAD')
    if not setup_failed:
        ffp.load()
    self.update_state(state='SUCCESS')  # FIXME use the real success value
    return 'done'


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

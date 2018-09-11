import unittest
from time import sleep
from celery.result import AsyncResult
from test.test_stress import nottest  # FIXME put nottest in test utils
from interlex.tasks import cel, multiple, bigload, add
from interlex.uri import run_uri
from test.setup_testing_db import testingdb
from IPython import embed


class TestTasks(unittest.TestCase):
    @nottest
    def test_task(self):
        app = run_uri(echo=True, database=testingdb)
        cel.init_app(app)
        @app.route('/loltesting')  # to we need to be inside here or what?
        def test():
            app
            # don't actually need or want to pass the loader in here
            # probably just better to let the tasks bind the session
            # themselves for the loaders rather than via endpoint?
            def fast_part(*args, small=False):
                if small:
                    sleep(1)
                    return 'woo a small one!'
                else:
                    task = bigload.delay('some-loader')
                    return task

            result_or_task = fast_part('asdf')
            # my issues below make it seem like I can't reuse the task id anyway >_<
            # e.g. from another guni worker
            embed()

            return
            stask = multiple.delay('loader', 'name', 'ebn')
            small = stask.get()
            print(small, stask.status)
            btask = multiple.delay('loader', 'bigname', 'ebn', small=False)
            big_id = btask.get()

            taska = add.delay(1, 2)
            taskb = cel.AsyncResult(taska.id)
            print(taskb.get())
            return
            print(big_id, btask.status, btask.info)
            # we don't actually wait here we return to the user
            big_task = AsyncResult(big_id, app=bigload.app)
            print(big_task.id)
            sleep(2)
            print(big_task.status)
            sleep(1)
            print(big_task.status)
            print(big_task.get())
            #embed()
            #big_result = big_task.get()
            #print(big_result)

        wat = test()
        print(wat)

import os
import shutil
from setuptools import setup

files = [
    'interlex/__init__.py',
    'interlex/alt.py',
    'interlex/alt_server.py',
    'interlex/dump.py',
    'interlex/exc.py',
    'interlex/render.py',
]

try:
    os.mkdir('export')
    for f in files:
        shutil.copyfile(f, f.replace('interlex','export'))

    setup(name='InterLex Alt',
          version='0.0.1',
          description='Serialize InterLex records',
          long_description=' ',
          url='https://github.com/tgbugs/interlex',
          author='Tom Gillespie',
          author_email='tgbugs@gmail.com',
          license='MIT',
          classifiers=[],
          keywords='probably dont use this',
          package_dir={'interlex':'export'},
          packages=['interlex'],
          install_requires=[
              'flask',
              'flask_sqlalchemy',
              'gunicorn',
              'pyontutils',
          ],
          extras_require={'dev':[]},
          scripts=['bin/interlex-alt'],
          entry_points={
              'console_scripts': [ ],
          },
         )
finally:
    shutil.rmtree('export')

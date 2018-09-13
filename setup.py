import os
from setuptools import setup

setup(name='InterLex',
      version='0.0.1',
      description='A lexical quadstore.',
      long_description=' ',
      url='https://github.com/tgbugs/interlex',
      author='Tom Gillespie',
      author_email='tgbugs@gmail.com',
      license='MIT',
      classifiers=[],
      keywords='interlex neurolex lexicon quadstore rdf owl linked-data',
      packages=['interlex'],
      install_requires=[
          'celery',
          'elasticsearch',
          'flask',
          'flask_restplus',
          'flask_sqlalchemy',
          'psycopg2',
          'pyontutils',
      ],
      extras_require={'dev':[]},
      scripts=['bin/interlex-uri', 'bin/interlex-curies', 'bin/interlex-dbsetup'],
      entry_points={
          'console_scripts': [
              'interlex=interlex.cli:main',
          ],
      },
     )

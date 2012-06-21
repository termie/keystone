import logging
import os
import sys

from google.appengine.ext.webapp import util

DEBUG = True

if DEBUG:
  logging.getLogger().setLevel(logging.DEBUG)


def _add_zip_files_to_path():
  for possible_zip_file in os.listdir('.'):
    if possible_zip_file.endswith('.zip'):
      path = os.path.join(os.getcwd(), possible_zip_file)
      if path in sys.path:
        continue
      logging.debug("adding %s to the sys.path", path)
      sys.path.insert(1, path)

_add_zip_files_to_path()

logging.error('%s', sys.path)

from paste import deploy

from keystone import config

CONF = config.CONF


def main():
  if DEBUG:
    logging.getLogger().setLevel(logging.DEBUG)

  _add_zip_files_to_path()
  config_files = ['keystone.conf']
  CONF(project='keystone', default_config_files=config_files)

  import sqlalchemy
  app = deploy.loadapp('config:keystone.conf', 'public_api')

  application = app
  util.run_wsgi_app(application)


if __name__ == '__main__':
  main()

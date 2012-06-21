import logging
import os
import sys

from google.appengine.ext.webapp import util

DEBUG = True

if DEBUG:
  logging.getLogger().setLevel(logging.DEBUG)


def _add_zip_files_to_path():
  logging.error('hey')
  for possible_zip_file in os.listdir('.'):
    logging.error('FILE: %s', possible_zip_file)
    if possible_zip_file.endswith('.zip'):
      path = os.path.join(os.getcwd(), possible_zip_file)
      if path in sys.path:
        continue
      logging.debug("adding %s to the sys.path", path)
      sys.path.insert(1, path)

_add_zip_files_to_path()

logging.error('%s', sys.path)

from paste import deploy



def main():
  if DEBUG:
    logging.getLogger().setLevel(logging.DEBUG)

  _add_zip_files_to_path()
  app = deploy.loadapp('config:etc/keystone.conf.sample', 'public_api')

  application = app
  util.run_wsgi_app(application)


if __name__ == '__main__':
  main()

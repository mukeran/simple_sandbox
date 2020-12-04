import logging
import engines
import filters, decoder
import sys

def start():
  # logging.basicConfig(level=logging.DEBUG)
  logging.info('Starting...')
  paths = sys.argv[1:]
  watcher = engines.FileWatcher(paths)
  watcher.register_filter(filters.BinaryFilter())
  fpm_sniffer = engines.FPMSniffer()

  watcher.start()
  fpm_sniffer.start()
  logging.info("Initialized")
  watcher.join()
  fpm_sniffer.join()


if __name__ == '__main__':
  logging.getLogger().setLevel(logging.DEBUG)
  if len(sys.argv) <= 1:
    logging.fatal('Please give at least a Binary listening path')
    sys.exit(1)
  start()

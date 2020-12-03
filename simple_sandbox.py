import logging
import engines
import filters, decoder

def start():
  logging.basicConfig(level=logging.DEBUG)
  logging.info('Starting...')
  watcher = engines.FileWatcher(['./test'])
  watcher.register_filter(filters.BinaryFilter())
  fpm_sniffer = engines.FPMSniffer()

  watcher.start()
  fpm_sniffer.start()
  logging.info("Initialized")
  watcher.join()
  fpm_sniffer.join()


if __name__ == '__main__':
  start()

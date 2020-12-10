import logging
import engines
import filters
import sys

def start():
  # logging.basicConfig(level=logging.DEBUG)
  logging.info('Starting...')
  # 启动 FileWatcher
  paths = sys.argv[1:]
  watcher = engines.FileWatcher(paths)
  watcher.register_filter(filters.BinaryFilter())
  # 启动 FPMSniffer
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

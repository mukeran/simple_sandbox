import logging
import engines
import filters, decoder

def start():
  logging.basicConfig(level=logging.DEBUG)
  sniffer = engines.HTTPSniffer('lo0')
  watcher = engines.FileWatcher(['./test'])
  logging.debug("Start to register decoder...")
  sniffer.register_decoder(decoder.UrlDecoder)
  sniffer.register_decoder(decoder.Base64Decoder)
  logging.debug("Start to register filters...")
  sniffer.register_filter(filters.SqliFilter())
  sniffer.register_filter(filters.XSSFilter())
  sniffer.register_filter(filters.WebshellFilter())
  sniffer.register_filter(filters.BinaryFilter())
  watcher.register_filter(filters.WebshellFilter())
  watcher.register_filter(filters.BinaryFilter())

  logging.info("Initialized")
  sniffer.start()
  watcher.start()
  sniffer.join()
  watcher.join()


if __name__ == '__main__':
  start()

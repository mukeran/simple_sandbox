import logging

import filters, decoder
import utils
import termcolor


def main():
    logging.basicConfig(level=logging.DEBUG)
    sniffer = utils.HTTPSniffer(iface="lo")
    logging.debug("start to register decoder")
    sniffer.register_decoder(decoder.UrlDecoder)
    sniffer.register_decoder(decoder.Base64Decoder)
    logging.debug("start to register filters")
    sqli_filter = filters.SqliFilter()
    xss_fileter = filters.XSSFilter()
    sniffer.register_filter(sqli_filter)
    sniffer.register_filter(xss_fileter)

    logging.debug("initialized")
    sniffer.start()


def test():
    import urllib.parse
    p = urllib.parse.urlparse(b"http://abc.com/?id=123123123")
    print(p)


if __name__ == '__main__':
    # test()
    # text=termcolor.colored("hallo", "blue")
    # print(text)
    main()

    # test_sniff()

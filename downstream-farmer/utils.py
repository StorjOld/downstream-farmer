#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus


def urlify(string):
    """ You might be wondering: why is this here at all, since it's basically
    doing exactly what the quote_plus function in urllib does. Well, to keep
    the 2 & 3 stuff all in one place, meaning rather than try to import the
    urllib stuff twice in each file where url-safe strings are needed, we keep
    it all in one file: here.

    Supporting multiple Pythons is hard.

    :param string: String to URLify
    :return: URLified string
    """
    return quote_plus(string)

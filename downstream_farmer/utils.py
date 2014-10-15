#!/usr/bin/env python
# -*- coding: utf-8 -*-


from six.moves.urllib.parse import quote

from .exc import DownstreamError


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
    return quote(string)


def handle_json_response(resp):
    try:
        resp.raise_for_status()
    except Exception as ex:
        r_json = resp.json()
        raise DownstreamError("Error fetching downstream"
                              "-node response: %s" % str(ex))

    try:
        r_json = resp.json()
    except:
        raise DownstreamError('Invalid response from Downstream node.')

    return r_json

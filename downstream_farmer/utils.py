#!/usr/bin/env python
# -*- coding: utf-8 -*-


import six

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
    return six.moves.urllib.parse.quote(string)


def handle_json_response(resp):
    """This function handles a response from the downstream-node server.
    If the server responds with an error, we attempt to get the json item
    'message' from the body.  if that fails, we just raise a regular http
    error.
    otherwise, if the server responds with a 200 'ok' message, we parse the
    json.

    :param resp: the flask request response to handle
    :returns: the parsed json as an object
    """
    if (resp.status_code != 200):
        try:
            # see if we have any json to parse
            r_json = resp.json()
            message = r_json['message']
        except:
            # if not, just raise the regular http error
            resp.raise_for_status()
        else:
            raise DownstreamError(message)

    # status code is 200, we should be good.
    r_json = resp.json()

    return r_json

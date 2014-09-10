#!/usr/bin/env python
# -*- coding: utf-8 -*-


class Py3kException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


class DownstreamError(Py3kException):
    pass


class ConnectError(Py3kException):
    pass

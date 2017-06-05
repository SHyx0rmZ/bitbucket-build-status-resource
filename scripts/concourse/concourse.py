import sys


class ConcourseResource(object):
    def __init__(self, config):
        self.config = config

    def mandatory_sources(self, *names):
        return MandatorySources(self.config, *names)

    def has_param(self, name):
        return name in self.config['params']

    def has_source(self, name):
        return name in self.config['source']

    def param(self, name, default=None):
        return self.config['params'].get(name, default)

    def source(self, name, default=None):
        return self.config['source'].get(name, default)


class MandatorySources(object):
    def __init__(self, config, *names):
        self.config = config
        self.names = names

    def __enter__(self):
        for name in self.names:
            if name not in self.config['source']:
                raise MissingSourceException(name)

    def __exit__(self, exc_type, exc_val, exc_tb):
        return


class MissingSourceException(Exception):
    def __init__(self, name):
        Exception.__init__(self, 'Missing mandatory source: {name}'.format(name=name))


# Convenience method for writing to stderr. Coerces input to a string.
def print_error(txt):
    sys.stderr.write(str(txt) + "\n")

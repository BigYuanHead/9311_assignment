import inspect
import os
from datetime import datetime


SEP_LINE = '-' * 20


class logger_C:

    RESET = '\033[0m'
    GREY = '\033[90m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'

    LEVEL_COLOR = {
        'DEBUG': GREY,
        'INFO': BLUE,
        'SUCCESS': GREEN,
        'WARN': YELLOW,
        'ERROR': RED,
    }

    def __init__(self, name='APP', debug=False, use_color=True):
        self.name = name
        self.debug_mode = debug
        self.use_color = use_color

    def _time_text(self):
        return datetime.now().strftime('%Y%m%d %H:%M:%S')

    def _location_text(self):
        """get caller file and line"""

        frame = inspect.currentframe()

        # current function -> _log -> public function -> real caller
        caller = frame.f_back.f_back.f_back

        filename = os.path.basename(caller.f_code.co_filename)
        line_no = caller.f_lineno

        return '{}:{}'.format(filename, line_no)

    def _color_text(self, level, text):
        if not self.use_color:
            return text

        color = self.LEVEL_COLOR.get(level, self.RESET)
        return '{}{}{}'.format(color, text, self.RESET)

    def _log(self, level, message):
        if level == 'DEBUG' and not self.debug_mode:
            return

        time_text = self._time_text()
        location_text = self._location_text()
        level_text = '[{}]'.format(level)
        name_text = '[{}]'.format(self.name)

        level_text = self._color_text(level, level_text)

        print('{} {} < {} > {}'.format(
            time_text,
            level_text,
            location_text,
            message
        ))

    def debug(self, message):
        self._log('DEBUG', message)

    def info(self, message):
        self._log('INFO', message)

    def success(self, message):
        self._log('SUCCESS', message)

    def warn(self, message):
        self._log('WARN', message)

    def error(self, message):
        self._log('ERROR', message)

    def exception(self, error):
        error_name = type(error).__name__
        message = '{}: {}'.format(error_name, error)
        self._log('ERROR', message)

    def line(self):
        if not self.debug_mode:
            return

        print(SEP_LINE)


default_logger = logger_C()


def debug(message):
    default_logger.debug(message)


def info(message):
    default_logger.info(message)


def success(message):
    default_logger.success(message)


def warn(message):
    default_logger.warn(message)


def error(message):
    default_logger.error(message)


def exception(error):
    default_logger.exception(error)


def line():
    default_logger.line()

import multiprocessing
import os


class Logger:

    info_enabled = 1
    debug_enabled = 1
    output_enabled = 1

    @staticmethod
    def output(prefix, s):
        if Logger.output_enabled:
            print(multiprocessing.current_process().name, prefix, s)

    @staticmethod
    def info(s):
        if Logger.info_enabled:
            Logger.output(" [INFO] ", str(s))

    @staticmethod
    def debug(s):
        if Logger.debug_enabled:
            Logger.output(" [DEBUG] ", str(s))
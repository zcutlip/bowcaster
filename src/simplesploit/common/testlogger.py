#!/usr/bin/env python

from support import Logging


logger=Logging()
logger.log_msg_start("Start message...")

logger.log_msg_end("done.")

logger.log_msg("hello")

logger.LOG_INFO("Info message.")

logger.LOG_WARN("Warning message.")

logger.LOG_DEBUG("Debug message.")

logger.set_log_file("./testlog.log")

logger.LOG_INFO("Info message.")

logger.LOG_WARN("Warning message.")

logger.LOG_DEBUG("Debug message.")



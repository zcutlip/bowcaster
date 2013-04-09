#!/usr/bin/env python
# Copyright (c) 2013
# - Zachary Cutlip <uid000@gmail.com>
# - Tactical Network Solutions, LLC
# 
# See LICENSE.txt for more details.
# 


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



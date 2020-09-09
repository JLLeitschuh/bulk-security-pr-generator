#!/usr/bin/python3

import logging.config

import pom_security_fix
import vulnerability_fix_engine

logging.basicConfig()
logging.getLogger().setLevel(logging.INFO)

vulnerability_fix_engine.do_execute_fix_module(
    pom_security_fix.PomVulnerabilityFixModule()
)

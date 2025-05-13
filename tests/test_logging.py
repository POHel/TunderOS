import sys
import os
INIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INIT_DIR)
from src.libs.logging import Logger

log = Logger("system")
log.debug('debug test')
log.info('test info') 
log.error('test error')
log.warning('test warn')
log.critical('crit err test')
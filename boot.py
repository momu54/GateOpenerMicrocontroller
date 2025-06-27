import supervisor
import storage
from os import getenv

supervisor.runtime.autoreload = False
if getenv("ENVIRONMENT") == 'production':
    storage.remount('/', False)

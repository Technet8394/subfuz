import censys
from censys.search import CensysCerts
from core.env import SIGINT_handler
import signal
from core.logger import Output

NAME        = 'censys'
ARG_HELP    = 'censys subdomain certificates'

handler = SIGINT_handler()
signal.signal(signal.SIGINT, handler.signal_handler)

class CENSYSError(Exception):
   """Base class for censys exceptions"""
   pass

def execute(domain, config, **kwargs):
    if handler.SIGINT:
        Output().warn("Aborted plugin: %s" % NAME, False)
        return None
    try:
        c = CensysCerts(api_id=config['uid'], api_secret=config['secret'])
        fields = [
            "parsed.names",
            "parsed.subject.common_name",
            "parsed.extensions.subject_alt_name.dns_names"
        ]
        results = []
        # Free API does not allow for the fields search.
        # for page in c.search(domain, fields=fields, max_records=config['max_records']):
        for page in c.search(domain, max_records=config['max_records']):
            results.append(page)
        #Flatten json to array
        list = []
        for x in results[0]:
            if x.get('names'):
                list += x.get('names')
        subdomains = []
        for x in list:
            subdomains.append(x.lstrip('*').lstrip('.'))
        subdomains = sorted(set(subdomains))
        return subdomains
    except censys.common.exceptions.CensysUnauthorizedException:
        Output().warn("Incorrect Censys Credentials or API limitations", False)
        return None
    except Exception as E:
        print (E)
        raise

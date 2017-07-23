#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxint as MAXINT
from time import time, sleep

from resources.collections_backport import OrderedDict
from resources.dnslib.RR import *
from resources.dnslib.Header import Header
from resources.dnslib.QE import QE
from resources.inetlib.types import *
from resources.util import *

# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"
ORIGINAL_HEADER = None
ORIGINAL_QUESTION = None
ORIGINAL_ADDRESS = None
END_TIME = 0


class ACacheEntry:
    ALPHA = 0.8

    def __init__(self, dict, srtt = None):
        self._srtt = srtt
        self._dict = dict

    def __repr__(self):
        return "<ACE %s, srtt=%s>" % (self._dict, ("*" if self._srtt is None else self._srtt),)

    def update_rtt(self, rtt):
        old_srtt = self._srtt
        self._srtt = rtt if self._srtt is None else \
            (rtt * (1.0 - self.ALPHA) + self._srtt * self.ALPHA)
        logger.debug(
            "update_rtt: rtt %f updates srtt %s --> %s" % (rtt, ("*" if old_srtt is None else old_srtt), self._srtt,))


class CacheEntry:
    def __init__(self, expiration = MAXINT, authoritative = False):
        self._expiration = expiration
        self._authoritative = authoritative

    def __repr__(self):
        now = int(time())
        return "<CE exp=%ds auth=%s>" % (self._expiration - now, self._authoritative,)


class CnameCacheEntry:
    def __init__(self, cname, expiration = MAXINT, authoritative = False):
        self._cname = cname
        self._expiration = expiration
        self._authoritative = authoritative

    def __repr__(self):
        now = int(time())
        return "<CCE cname=%s exp=%ds auth=%s>" % (self._cname, self._expiration - now, self._authoritative,)


now = int(time())
seed(now)

pp = pprint.PrettyPrinter(indent=3)

# [domain name --> [nsdn --> CacheEntry]]:
nscache = dict(
    [(DomainName("."), OrderedDict([(DomainName(ROOTNS_DN), CacheEntry(expiration=MAXINT, authoritative=True))]))])

# [domain name --> [in_addr --> CacheEntry]]:
acache = dict([(DomainName(ROOTNS_DN),
                ACacheEntry(dict([(InetAddr(ROOTNS_IN_ADDR), CacheEntry(expiration=MAXINT, authoritative=True))])))])

# [domain name --> CnameCacheEntry]
cnamecache = dict([])


# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
    if value < 32768 or value > 61000:
        raise OptionValueError("need 32768 <= port <= 61000")
    parser.values.port = value


parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback", callback=check_port, metavar="PORTNO",
                  default=0, help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()

# Create a server socket to accept incoming connections from DNS
# client resolvers
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

print "%s: listening on port %d" % (sys.argv[0], serverport)
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)


def nscache_insert(ns):
    """
    Inserts a nameserver into the nscache
    """
    now = int(time())
    dn = ns._dn
    nsdn = ns._nsdn
    entry = CacheEntry(expiration=now + ns._ttl)
    if dn in nscache:
        nscache[dn][nsdn] = entry
    else:
        nscache[dn] = OrderedDict([(nsdn, entry)])


def acache_insert(a):
    """
    Inserts an address into the acache
    """
    dn = a._dn
    string_address = InetAddr.fromNetwork(a._addr)
    entry = CacheEntry(expiration=a._ttl)
    acache[dn] = ACacheEntry({string_address: entry})


def get_info(data):
    """
    Parse data and append all relevant information to a dict, caching records as we see them. Returns the dictionary
    """

    # Store data in a map
    records = {}

    # Header
    header = Header.fromData(data)
    records["header"] = header

    # Question
    question = QE.fromData(data, len(header))
    records["question"] = question

    length = len(header) + len(question)
    for i in xrange(0, header._ancount):

        # Get answers
        rr = RR.fromData(data, length)
        length += rr[1]

        if "answer" not in records:
            records["answer"] = []

        records["answer"].append(rr)

    for i in xrange(0, header._nscount):

        # Get nameservers
        rr = RR.fromData(data, length)
        length += rr[1]

        # Only want nameservers
        if rr[0]._type is not RR.TYPE_NS:
            continue
        if "ns" not in records:
            records["ns"] = []

        records["ns"].append(rr)

        # Cache
        nscache_insert(rr[0])

    for i in xrange(0, header._arcount):

        # Get addresses
        rr = RR.fromData(data, length)
        length += rr[1]

        # Only want A records
        if rr[0]._type is not RR.TYPE_A:
            continue
        if "address" not in records:
            records["address"] = []

        records["address"].append(rr[0])

        # Cache
        acache_insert(rr[0])

    return records


def get_ns_ip(ns, index):
    """
    Given a namserver, try to find its ip address. Returns False if otherwise
    """

    # Check to make sure record has not expired
    now = int(time())
    if now >= END_TIME:
        return generate_error_reply("Time elapsed")

    # Check cache
    if ns in acache:
        return acache[ns]

    header = ORIGINAL_HEADER

    # Create new question to try to find the address of the ns
    question = QE(dn=ns)

    # Recursive query
    records = find_recursively(header.pack() + question.pack(), ROOTNS_IN_ADDR, index + 1)
    if not records or records['header']._ancount < 1:
        return False
    else:
        return records["answer"][0][0]._addr


def check_glue_records(records):
    """
    Checks the glue records to see if the query turned up there
    """
    if "address" not in records or records is None:
        return False

    looking_for = records["question"]._dn

    for address in records["address"]:

        # Check if that domain name is there
        if address == looking_for:
            if "answer" not in records:
                records["answer"] = []
            records["answer"].append(address)

    val = records if "answer" in records else False
    return val


def find_recursively(query, address, index):
    """
    Given a query, send's the query to the specified address. If it finds an answer, will call generate_reply,
    otherwise it will recursively call itself with its best guess for how to proceed. Passing an index (i.e. level
    of recursion) into the function prevents infinite loops
    """
    # Check for infinite loop
    if index >= 100:
        records = {}
        records["error"] = True
        return records

    # Satisfy second requirement:
    now = int(time())
    if now >= END_TIME:
        return generate_error_reply("Time elapsed")

    update_cache()

    try:
        cs.sendto(query, (address, 53))
        data, address = cs.recvfrom(512)
        records = get_info(data)

    except timeout:  # TimeoutError
        cs.sendto(query, (ROOTNS_IN_ADDR, 53))

    # Ensure there's no error
    if records["header"]._rcode is not Header.RCODE_NOERR:
        records["error"] = True
        return records

    # Check if there's an obvious answer
    if records["header"]._ancount > 0:
        return records

    # Check in the glue records
    is_in_glue = check_glue_records(records)
    if is_in_glue:
        return is_in_glue

    # Next, go through the addresses in the glue records and query them for
    # the question
    if "address" in records:
        for address in records["address"]:
            # Get the IP address
            addr = inet_ntoa(address._addr)

            return find_recursively(query, addr, index + 1)

    # Answer could lie in a nameserver, let's check those:
    if "ns" in records:
        for ns in records["ns"]:

            # Get its IP address
            ip_address = get_ns_ip(ns[0]._nsdn, index + 1)

            if ip_address:
                return find_recursively(query, inet_ntoa(ip_address), index + 1)

    # Nothing, so dead end
    records["error"] = True
    return records


def get_nameservers(domains):
    """
    Given a set of domains, return all the nameservers which have direct authority over that domain as a tuple
    of (domain, CacheEntry)
    """
    authorities = []
    for domain in domains:
        if domain in nscache:
            authorities.append((domain, nscache[domain]))
    return authorities


def get_additional(nameservers):
    """
    Given a set of nameservers, return a list of tuples containing a (nameserver, ip_address) pair
    """
    addresses = []
    for ns in nameservers:
        ip = get_ns_ip(ns, 0)
        if not ip:
            # Even if we didn't get an address, we should still keep going
            continue
        addresses.append((ns, ip))
    return addresses


def generate_error_reply(message):
    """
    Send an error to the user
    """

    # Construct
    header, question = ORIGINAL_HEADER, ORIGINAL_QUESTION
    header._rcode = Header.RCODE_SRVFAIL
    reply = header.pack() + question.pack()

    # Send
    ss.sendto(reply, ORIGINAL_ADDRESS)


def respond(answers, nameservers, nameserver_data):
    """
    Given the A records and associated nameservers and data, generate a response to the user
    """

    # Response string
    response = ""

    for answer in answers:
        response += answer.pack()

    ns_count = 0
    for ns in nameservers:
        dn = ns[0]
        for nsdn, entry in ns[1].iteritems():
            ns_count += 1

            ttl = entry._expiration
            rec = RR_NS(dn, ttl, nsdn)

            response += rec.pack()

    ar_count = 0
    for dn, value in nameserver_data:
        ar_count += 1
        ttl = int(time())

        if hasattr(value, "_dict"):
            ip_address = inet_aton(str(value._dict.keys()[0]))
        else:
            ip_address = value

        # Construct A record
        rec = RR_A(dn, ttl, ip_address)

        response += rec.pack()

    # Construct header
    header = Header(ORIGINAL_HEADER._id, Header.OPCODE_QUERY, Header.RCODE_NOERR, qdcount=1, ancount=len(answers),
                    nscount=ns_count, arcount=ar_count, qr=1)

    # Retrieve the user query
    question = ORIGINAL_QUESTION

    final_response = header.pack() + question.pack() + response

    # Send!
    ss.sendto(final_response, ORIGINAL_ADDRESS)


def generate_reply(records):
    """
    Given the records returned by find_recursively, does its best to construct a response to send to client
    """

    # Ensure our records are not outdated
    now = int(time())
    if now >= END_TIME:
        return generate_error_reply("Time elapsed")

    if "error" in records:
        return generate_error_reply("Unknown Error Occurred")

    # Easy way to store unique domains
    answer_domains = set()

    # Just the actual RR_A records
    answers = [answer[0] for answer in records["answer"]]

    for answer in answers:
        # Skip anything that's not an A record
        if answer._type is not RR.TYPE_A:
            continue

        # Need to add all our answers to the cache
        acache_insert(answer)

        # Keep track of all the unique domains
        answer_domains.add(answer._dn)

    nameservers = []
    attempted_ns = [dn for dn in answer_domains]

    # Arbitrary finite limit, can't realistically ever be a.b.c.d.e....j.
    for i in range(10):
        nameservers = get_nameservers(attempted_ns)
        if len(nameservers):
            break
        for i in xrange(0, len(attempted_ns)):
            result = get_subdomain_of(str(attempted_ns[i]))
            if not result:
                continue
            attempted_ns[i] = DomainName(result)

    # For each of those nameservers, get their ip address, store in tuple
    ns_domains = []
    for item in nameservers:
        for key in item[1].keys():
            ns_domains.append(key)

    # Get the domain and address of the nameservers to use in the additional
    # section
    nameserver_data = get_additional(ns_domains)

    # Respond
    respond(answers, nameservers, nameserver_data)


def get_subdomain_of(domain):
    """
    Given a domain a.b.c., returns b.c. Returns False if it can't go further'
    """
    if "." not in domain or len(domain) is 0:
        return False

    periods = domain.split(".")
    subdomain = ""

    # Start 1 indice in
    for i in xrange(1, len(periods)):
        subdomain += periods[i]

        # Append period if not last
        if i != len(periods) - 1:
            subdomain += "."

    return subdomain


def update_cache():
    """
    Update all caches, clearing anything whose TTL is expired
    """
    # Get current time
    now = int(time())

    # Check NS cache:
    nsdelete = []
    for key, val in nscache.iteritems():
        for entry in val.iteritems():
            nsdn = entry[0]
            data_for_entry = entry[1]
            if data_for_entry._expiration < now:
                nsdelete.append((key, nsdn))

    for entry in nsdelete:
        dn = entry[0]
        nsdn = entry[1]
        del nscache[dn][nsdn]

    # Check A cache:
    adelete = []
    for entry in acache.iteritems():
        ttl = entry[1]._dict.values()[0]._expiration
        if ttl < now:
            adelete.append(entry[0])
    for item in adelete:
        del acache[item]


def get_response(query):
    """
    Overarching function to handle the inital query from the user. First checks the cache to see if there is
    an answer, otherwise searches recursively to try to find one.
    """

    # Domain name
    dn = query["question"]._dn

    update_cache()

    if dn in acache:

        # Could be multiple answers
        answers = {}

        for entry in acache[dn]._dict.keys():

            new_answer = RR_A(dn, acache[dn]._dict[entry]._expiration - int(time()), inet_aton(str(entry)))

            if "answer" not in answers:
                answers["answer"] = []
            answers['answer'].append((new_answer, len(new_answer)))

        return generate_reply(answers)

    # Attempt recursively
    records = find_recursively(ORIGINAL_HEADER.pack() + ORIGINAL_QUESTION.pack(), ROOTNS_IN_ADDR, 0)

    return generate_reply(records)


while True:
    (data, address,) = ss.recvfrom(512)  # DNS limits UDP msgs to 512 bytes
    if not data:
        generate_error_reply("No data!")
    try:
        ORIGINAL_HEADER = Header.fromData(data)
        ORIGINAL_QUESTION = QE.fromData(data, len(ORIGINAL_HEADER))
        ORIGINAL_ADDRESS = address
    except:
        generate_error_reply("Could not parse query")

    END_TIME = int(time()) + 60
    try:
        user_query = get_info(data)
    except:
        generate_error_reply("Corrupted data")

    get_response(user_query)

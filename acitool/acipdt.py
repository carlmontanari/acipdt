import requests
import json
import sys
import collections
import jinja2
import ipaddress
import pkg_resources
import time

# Global path to main json directory
json_path = pkg_resources.resource_filename('acitool', 'jsondata/')

# Global list of allowed statuses
valid_status = ['created', 'created,modified', 'deleted']


# Exception Classes
class InsufficientArgs(Exception):
    pass


class InvalidArg(Exception):
    pass


# Function to validate input for each method
def process_kwargs(required_args, optional_args, **kwargs):
    # Validate all required kwargs passed
    if all(item in kwargs for item in required_args.keys()) is not True:
        raise InsufficientArgs('Insufficient required arguments.')

    # Load all required args values from kwargs
    for item in kwargs:
        if item in required_args.keys():
            required_args[item] = kwargs[item]
    for item in kwargs:
        if item in optional_args.keys():
            optional_args[item] = kwargs[item]

    # Combine option and required dicts for Jinja template render
    templateVars = {**required_args, **optional_args}
    return(templateVars)


# Function to execute HTTP Post
def post(apic, payload, cookies, uri, section):
    s = requests.Session()
    r = ''
    while r == '':
        try:
            r = s.post('https://{}/api/node/{}.json'.format(apic, uri),
                       data=payload, cookies=cookies, verify=False)
            status = r.status_code
        except requests.exceptions.ConnectionError as e:
            print("Connection error, pausing before retrying. Error: {}"
                  .format(e))
            time.sleep(5)
        except Exception as e:
            print("Method {} failed. Exception: {}".format(section[:-5], e))
            status = 666
            return(status)
    return status


# Class must be instantiated with APIC IP address, username, and password
# the login method returns the APIC cookies.
class FabLogin(object):
    def __init__(self, apic, user, pword):
        self.apic = apic
        self.user = user
        self.pword = pword

    def login(self):
        # Load login json payload
        payload = '''
        {{
            "aaaUser": {{
                "attributes": {{
                    "name": "{user}",
                    "pwd": "{pword}"
                }}
            }}
        }}
        '''.format(user=self.user, pword=self.pword)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        # Try the request, if exception, exit program w/ error
        try:
            # Verify is disabled as there are issues if it is enabled
            r = s.post('https://{}/api/mo/aaaLogin.json'.format(self.apic),
                       data=json.dumps(payload), verify=False)
            # Capture HTTP status code from the request
            status = r.status_code
            # Capture the APIC cookie for all other future calls
            cookies = r.cookies
            # Log login status/time(?) somewhere
            if status == 400:
                print("Error 400 - Bad Request - ABORT!")
                print("Probably have a bad URL")
                sys.exit()
            if status == 401:
                print("Error 401 - Unauthorized - ABORT!")
                print("Probably have incorrect credentials")
                sys.exit()
            if status == 403:
                print("Error 403 - Forbidden - ABORT!")
                print("Server refuses to handle your request")
                sys.exit()
            if status == 404:
                print("Error 404 - Not Found - ABORT!")
                print("Seems like you're trying to POST to a page that doesn't"
                      " exist.")
                sys.exit()
        except Exception as e:
            print("Something went wrong logging into the APIC - ABORT!")
            # Log exit reason somewhere
            sys.exit(e)
        return cookies


# Class must be instantiated with APIC IP address and cookies
class FabPodPol(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies
        self.templateLoader = jinja2.FileSystemLoader(
            searchpath=(json_path + 'FabPodPol/'))
        self.templateEnv = jinja2.Environment(loader=self.templateLoader)

    # Method must be called with the following kwargs.
    # name: Name of the node being deployed
    # id: ID of the node being deploeyd as an integer (i.e. 101)
    # serial: Serial number of device being deployed
    # descr: (Optional) Description of the node
    # fabric: (Optional) Default is 1 - will be relevant for xconnect
    # pod: (Optional) Default is 1 - will be relevant for multipod
    def comission_hw(self, **kwargs):
        # Dicts for required and optional args
        required_args = {'name': '',
                         'id': '',
                         'serial': ''}
        optional_args = {'descr': '',
                         'fabric': '1',
                         'pod': '1'}

        # Validate inputs, return dict of template vars
        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        # Validate inputs
        if not int(templateVars['id']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['id'] = int(templateVars['id'])
        if not int(templateVars['fabric']):
            raise InvalidArg('Fabric ID must be an integer')
        else:
            templateVars['fabric'] = int(templateVars['fabric'])
        if not int(templateVars['pod']):
            raise InvalidArg('Pod ID must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])

        # Locate template for method
        template_file = "comission_hw.json"
        template = self.templateEnv.get_template(template_file)

        # Render template w/ values from dicts
        payload = template.render(templateVars)

        # Handle request
        uri = 'mo/uni'
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # address: Name/IP of the NTP server
    # status: created | created,modified | deleted
    def ntp(self, **kwargs):
        required_args = {'address': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not ipaddress.ip_address(templateVars['address']):
            raise InvalidArg('Address must be a valid IPv4 address')
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "ntp.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni'
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the node being deployed
    # address: IP of DNS Server
    # status: (Of the DNS Server) created | created,modified | deleted
    # domain: (Optional) DNS Domain
    # domain_status: (Optional) created | created,modified | deleted
    # preferred: (Optional) yes | no
    # domain_default: (Optional) yes | no
    def dns(self, **kwargs):
        required_args = {'address': '',
                         'status': ''}
        optional_args = {'domain': '',
                         'domain_status': 'deleted',
                         'preferred': 'no',
                         'domain_default': 'no'}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not ipaddress.ip_address(templateVars['address']):
            raise InvalidArg('Address must be a valid IPv4 address')
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "dns.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/fabric/dnsp-default'
        status = post(self.apic, payload, self.cookies, uri, template_file)

        template_file = "dns_profile.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/fabric/dnsp-default/rsProfileToEpg'
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # asn: Fabric BGP ASN as an integer
    # status: created | created,modified | deleted
    def fabric_bgp(self, **kwargs):
        required_args = {'asn': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not (int(templateVars['asn']) in range(1, 65536)):
            raise InvalidArg('Invalid BGP ASN')
        else:
            templateVars['asn'] = int(templateVars['asn'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "fabric_bgp.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/fabric/bgpInstP-default/as'
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # rr: ID of node to be route reflector
    # status: created | created,modified | deleted
    def fabric_rr(self, **kwargs):
        required_args = {'rr': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['rr']):
            raise InvalidArg('Route Reflector ID must be an integer')
        else:
            templateVars['rr'] = int(templateVars['rr'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "fabric_rr.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/fabric/bgpInstP-default/rr/node-{}'.format(
              templateVars['rr'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of pod-policy to be created
    # status: created | created,modified | deleted
    def pod_pol(self, **kwargs):
        required_args = {'name': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "pod_pol.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/fabric/funcprof'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)

        template_file = "pod_pol_assign.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/fabric/podprof-default/pods-default-typ-ALL/rspodPGrp'
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status


# Class must be instantiated with APIC IP address and cookies
class FabAccPol(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies
        self.templateLoader = jinja2.FileSystemLoader(
            searchpath=(json_path + 'FabAccPol/'))
        self.templateEnv = jinja2.Environment(loader=self.templateLoader)

    # Method must be called with the following kwargs.
    # name: The name of the CDP policy
    # state: enabled | disabled
    # status: created | created,modified | deleted
    def cdp(self, **kwargs):
        required_args = {'name': '',
                         'state': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "cdp.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/cdpIfP-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: The name of the LLDP policy
    # state: enabled | disabled
    #   Note: The configured state is deployed to both Tx and Rx
    # status: created | created,modified | deleted
    def lldp(self, **kwargs):
        required_args = {'name': '',
                         'state': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "lldp.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/lldpIfP-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: The name of the Link policy
    # auto_neg: on | off
    # speed: 100M | 1G | 10G | 40G | auto
    #   Note: 100G should be available soon if not already in some versions
    # status: created | created,modified | deleted
    def link(self, **kwargs):
        required_args = {'name': '',
                         'auto_neg': '',
                         'speed': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "link.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/hintfpol-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: The name of the Port-Channel policy
    # mode: off | mac-pin | active
    #   Note: 'off' = static mode-on
    # state: enabled | disabled
    #   Note: The configured state is deployed to both Tx and Rx
    # status: created | created,modified | deleted
    def pc(self, **kwargs):
        required_args = {'name': '',
                         'mode': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "pc.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/lacplagp-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: The name of the Per Port VLAN policy
    # state: enabled | disabled
    # status: created | created,modified | deleted
    def ppv(self, **kwargs):
        required_args = {'name': '',
                         'state': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "ppv.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/l2IfP-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: The name of the Per Port VLAN policy
    # state: enabled | disabled
    # status: created | created,modified | deleted
    def mcp_intf(self, **kwargs):
        required_args = {'name': '',
                         'state': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "mcp_intf.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/mcpIfP-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # password: string for global MCP password
    # state: enabled | disabled
    def mcp_global(self, **kwargs):
        required_args = {'password': '',
                         'state': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        template_file = "mcp_global.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/mcpInstP-default'
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # event: mcp-loop | ep-move | bpduguard
    # state: true | false
    def err_disable(self, **kwargs):
        required_args = {'event': '',
                         'state': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        template_file = "err_disable.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/infra/edrErrDisRecoverPol-default/edrEventP-event-{}'
               .format(templateVars['event']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: The name of the parent VLAN Pool
    # mode: static | dynamic
    # range_mode: static | dynamic
    # start: Starting VLAN - as an integer
    # end: Ending VLAN - as an integer
    # status: created | created,modified | deleted
    def vl_pool(self, **kwargs):
        required_args = {'name': '',
                         'mode': '',
                         'range_mode': '',
                         'start': '',
                         'end': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['start']):
            raise InvalidArg('VLAN IDs must be an integer')
        else:
            templateVars['start'] = int(templateVars['start'])
        if not int(templateVars['end']):
            raise InvalidArg('VLAN IDs must be an integer')
        else:
            templateVars['end'] = int(templateVars['end'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "vl_pool.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/infra/vlanns-[{}]-{}'
               .format(templateVars['name'], templateVars['mode']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: The name of the AEP
    # status: created | created,modified | deleted
    # infra: created | created,modified | deleted
    #   Note: This should be 'deleted' if no infra VLAN is needed
    #         or it should be 'created,modified' if there is a infra VLAN
    # infra_vlan: (optional) infastructure vlan as an integer
    # override: (optional) created | created,modified | deleted
    #   Note: This should be 'deleted' if no infra override is needed
    #         or it should be 'created,modified' if there is an override policy
    # override_pc: (optional) Name of the port-channel policy
    # override_cdp: (optional) Name of the cdp policy
    # override_lldp: (optional) Name of the lldp policy
    def aep(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'infra': 'deleted'}
        optional_args = {'infra_vlan': '0',
                         'override': 'deleted',
                         'override_pc': '',
                         'override_cdp': '',
                         'override_lldp': ''}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['infra'] == 'created,modified':
            if not int(templateVars['infra_vlan']):
                raise InvalidArg('Infra VLAN ID must be an integer')
            else:
                templateVars['infra_vlan'] = int(templateVars['infra_vlan'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')
        if templateVars['infra'] not in valid_status:
            raise InvalidArg('Status invalid')
        if templateVars['override'] not in valid_status:
            raise InvalidArg('Status invalid')

        if templateVars['override'] == 'created,modified':
            template_file = "aep_override.json"
        else:
            template_file = "aep_no_override.json"

        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/attentp-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the L3-Out Domain
    # status: created | created,modified | deleted
    # vlan_pool: Name of the VLAN pool to associate to the L3 Out
    def l3_dom(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'vlan_pool': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "l3_dom.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/l3dom-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the Physical Domain
    # status: created | created,modified | deleted
    # vlan_pool: Name of the VLAN pool to associate to the Physical Domain
    def phys_dom(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'vlan_pool': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "phys_dom.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/phys-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the AEP
    # status: created | created,modified | deleted
    # l3_dom: Name of the L3 Domain to be hooked to the AEP
    def l3_aep(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'l3_dom': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "l3_aep.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/attentp-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the AEP
    # status: created | created,modified | deleted
    # dom_name: Name of the L3 Domain to be hooked to the AEP
    def phys_aep(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'dom_name': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "phys_aep.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/attentp-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the vPC
    # id: vPC ID as an integer
    # status: created | created,modified | deleted
    # sw1: Node 1 in integer (i.e. 101)
    # sw2: Node 2 in integer (i.e. 102)
    def vpc(self, **kwargs):
        required_args = {'name': '',
                         'id': '',
                         'status': '',
                         'sw1': '',
                         'sw2': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['id']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['id'] = int(templateVars['id'])
        if not int(templateVars['sw1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw1'] = int(templateVars['sw1'])
        if not int(templateVars['sw2']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw2'] = int(templateVars['sw2'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "vpc.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/fabric/protpol/expgep-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # This method creates a switch profile for a pair of switches (vPC)
    # name: Name of the Switch Profile
    # status: created | created,modified | deleted
    # sw1: Node 1 in integer (i.e. 101)
    # sw2: Node 2 in integer (i.e. 102)
    def sw_pro_vpc(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'sw1': '',
                         'sw2': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['sw1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw1'] = int(templateVars['sw1'])
        if not int(templateVars['sw2']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw2'] = int(templateVars['sw2'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "sw_pro_vpc.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/nprof-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # This method creates a switch profile for a signle switch
    # name: Name of the Switch Profile
    # status: created | created,modified | deleted
    # sw1: Node 1 in integer (i.e. 101)
    def sw_pro_single(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'sw1': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['sw1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw1'] = int(templateVars['sw1'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "sw_pro_single.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/nprof-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the Interface Policy Group
    # status: created | created,modified | deleted
    # lag_type: node | link
    #   Note: Node = vPC, Link = PC
    # lldp: Name of LLDP Policy
    # cdp: Name of CDP Policy
    # aep: Name of AEP
    # mcp: Name of MCP Policy
    # lag: Name of Port-Channel Policy
    # link: Name of Link Policy
    def int_pol_grp_vpc(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'lag_type': '',
                         'lldp': '',
                         'cdp': '',
                         'aep': '',
                         'mcp': '',
                         'lag': '',
                         'link': ''}
        optional_args = {'ppv': '',
                         'storm': ''}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "int_pol_grp_vpc.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/funcprof/accbundle-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the Interface Policy Group
    # status: created | created,modified | deleted
    # lldp: Name of LLDP Policy
    # cdp: Name of CDP Policy
    # aep: Name of AEP
    # mcp: Name of MCP Policy
    # link: Name of Link Policy
    def int_pol_grp_access(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'lldp': '',
                         'cdp': '',
                         'aep': '',
                         'mcp': '',
                         'link': ''}
        optional_args = {'ppv': '',
                         'storm': ''}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "int_pol_grp_access.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/infra/funcprof/accportgrp-{}'
               .format(templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the Interface Profile
    # status: created | created,modified | deleted
    def int_profile(self, **kwargs):
        required_args = {'name': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "int_profile.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/accportprof-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the Interface Selector
    # status: created | created,modified | deleted
    # port_name: Name of the port selector in the Interface Profile
    # port_type: accportgrp | accbundle
    #   Note: accportgrp = Access Port
    #   Note: accbundle = vPC or Port Channel
    # pol_group: Name of the Policy Group to apply
    # mod_start: Starting mod as an integer (almost always 1)
    # mod_end: Ending mod as an integer (almost always 1)
    # port_start: Starting port as an integer
    # port_end: Ending port as an integer
    def int_selector(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'port_name': '',
                         'port_type': '',
                         'pol_group': '',
                         'mod_start': '1',
                         'mod_end': '1',
                         'port_start': '',
                         'port_end': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['mod_start']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['mod_start'] = int(templateVars['mod_start'])
        if not int(templateVars['mod_end']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['mod_end'] = int(templateVars['mod_end'])
        if not int(templateVars['port_start']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port_start'] = int(templateVars['port_start'])
        if not int(templateVars['port_end']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port_end'] = int(templateVars['port_end'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "int_selector.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/accportprof-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the Switch Profile
    # status: created | created,modified | deleted
    # int_profile: Name of the Interface Profile to hook to Switch Selector
    def int_selector_sw_profile(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'int_profile': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "int_selector_sw_profile.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/nprof-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the Interface Selector
    # fex_pol_grp: Name of the FEX Policy Group
    # status: created | created,modified | deleted
    def fex_profile(self, **kwargs):
        required_args = {'name': '',
                         'fex_pol_grp': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "fex_profile.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/fexprof-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the Interface Selector
    # status: created | created,modified | deleted
    # port_name: Name of the port selector in the Interface Profile
    # port_type: accportgrp | accbundle
    #   Note: accportgrp = Access Port
    #   Note: accbundle = vPC or Port Channel
    # pol_group: Name of the Policy Group to apply
    # mod_start: Starting mod as an integer (almost always 1)
    # mod_end: Ending mod as an integer (almost always 1)
    # port_start: Starting port as an integer
    # port_end: Ending port as an integer
    def fex_int_profile(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'port_name': '',
                         'port_type': '',
                         'pol_group': '',
                         'port_start': '',
                         'port_end': '',
                         'fex_id': ''}
        optional_args = {'mod_start': '1',
                         'mod_end': '1'}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['mod_start']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['mod_start'] = int(templateVars['mod_start'])
        if not int(templateVars['mod_end']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['mod_end'] = int(templateVars['mod_end'])
        if not int(templateVars['port_start']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port_start'] = int(templateVars['port_start'])
        if not int(templateVars['port_end']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port_end'] = int(templateVars['port_end'])
        if not int(templateVars['fex_id']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['fex_id'] = int(templateVars['fex_id'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "fex_int_profile.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/infra/fexprof-{}/hports-{}-typ-range'
               .format(templateVars['name'], templateVars['port_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: Name of the Interface Selector
    # status: created | created,modified | deleted
    # port_name: Name of the port selector in the Interface Profile
    # mod_start: Starting mod as an integer (almost always 1)
    # mod_end: Ending mod as an integer (almost always 1)
    # port_start: Starting port as an integer
    # port_end: Ending port as an integer
    # fex_id: Integer ID of the FEX
    # fex_pol_grp: Name of FEX Policy Group
    # fex_prof: Name of the FEX Profile
    def fex_leaf_profile(self, **kwargs):
        required_args = {'name': '',
                         'status': '',
                         'port_name': '',
                         'port_start': '',
                         'port_end': '',
                         'fex_id': '',
                         'fex_prof': '',
                         'fex_pol_grp': ''}
        optional_args = {'mod_start': '1',
                         'mod_end': '1'}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['mod_start']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['mod_start'] = int(templateVars['mod_start'])
        if not int(templateVars['mod_end']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['mod_end'] = int(templateVars['mod_end'])
        if not int(templateVars['port_start']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port_start'] = int(templateVars['port_start'])
        if not int(templateVars['port_end']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port_end'] = int(templateVars['port_end'])
        if not int(templateVars['fex_id']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['fex_id'] = int(templateVars['fex_id'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "fex_leaf_profile.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/infra/accportprof-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status


# Class must be instantiated with APIC IP address and cookies
class FabTnPol(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies
        self.templateLoader = jinja2.FileSystemLoader(
            searchpath=(json_path + 'FabTnPol/'))
        self.templateEnv = jinja2.Environment(loader=self.templateLoader)

    # Method must be called with the following kwargs.
    # name: The name of the Tenant
    # status: created | created,modified | deleted
    def tenant(self, **kwargs):
        required_args = {'name': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "tenant.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/tn-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # name: Name of the VRF
    # enforce: enforced | unenforced
    # status: created | created,modified | deleted
    def vrf(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'enforce': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "vrf.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ctx-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # name: Name of the VRF
    # contract: Name of the Contract
    # status: created | created,modified | deleted
    def vz_any_provide(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'contract': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "vz_any_provide.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ctx-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # name: Name of the VRF
    # contract: Name of the Contract
    # status: created | created,modified | deleted
    def vz_any_consume(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'contract': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "vz_any_consume.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ctx-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # name: Name of the VRF
    # prefgrp: disabled | enabled
    def prefgrp(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'prefgrp': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        template_file = "prefgrp.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ctx-{}/any'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # name: Name of the BD
    # arp: yes | no
    # mdest: bd-flood | drop | encap-flood
    # mcast: flood | opt-flood
    # unicast: yes | no
    # unk_unicast: proxy | flood
    # vrf: Name of associated VRF
    # status: created | created,modified | deleted
    def bd(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'arp': '',
                         'mdest': '',
                         'mcast': '',
                         'unicast': '',
                         'unk_unicast': '',
                         'vrf': '',
                         'status': ''}
        optional_args = {'limitlearn': 'yes'}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "bd.json"

        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/BD-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # name: Name of the BD
    # subnet: Subnet in CIDR: ex: 1.1.1.1/24
    # preferred: yes | no
    # scope: public | private | shared | public,shared | private,shared
    # status: created | created,modified | deleted
    def bd_subnet(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'subnet': '',
                         'scope': '',
                         'preferred': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "bd_subnet.json"

        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/BD-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # name: Name of the BD
    # l3_out: Name of the associated L3 Out
    # status: created | created,modified | deleted
    def bd_l3_out(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'l3_out': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "bd_l3_out.json"

        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/BD-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # name: Name of the Filter
    # dst_start: unspecified | port number as an integer
    # dst_end: unspecified | port number as an integer
    # src_start: unspecified | port number as an integer
    # src_end: unspecified | port number as an integer
    # ethertype: commonly IP or unspecified
    # protocol: if IP commonly tcp | udp | unspecified
    #   Note: ACI is case sensitive, use all lower case!
    # status: created | created,modified | deleted
    def filter(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'dst_start': '',
                         'dst_end': '',
                         'src_start': '',
                         'src_end': '',
                         'ethertype': '',
                         'protocol': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not (templateVars['dst_start'] == 'unspecified'):
            try:
                templateVars['dst_start'] = int(templateVars['dst_start'])
            except Exception as e:
                print(e)
                raise InvalidArg("Filter port must be 'unspecified' or an integer")
        if not (templateVars['dst_end'] == 'unspecified'):
            try:
                templateVars['dst_end'] = int(templateVars['dst_end'])
            except Exception as e:
                print(e)
                raise InvalidArg("Filter port must be 'unspecified' or an integer")
        if not (templateVars['src_start'] == 'unspecified'):
            try:
                templateVars['src_start'] = int(templateVars['src_start'])
            except Exception as e:
                print(e)
                raise InvalidArg("Filter port must be 'unspecified' or an integer")
        if not (templateVars['src_end'] == 'unspecified'):
            try:
                templateVars['src_end'] = int(templateVars['src_end'])
            except Exception as e:
                print(e)
                raise InvalidArg("Filter port must be 'unspecified' or an integer")
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "filter.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/flt-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # name: Name of the Contract
    # scope: context | global | tenant | application-profile
    # subject: Name of the Subject
    # filter: Name of the Filter being referenced
    # reverse_filter: yes | no
    # status: created | created,modified | deleted
    def contract(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'scope': '',
                         'subject': '',
                         'filter': '',
                         'reverse_filter': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "contract.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/brc-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # name: Name of the Application Profile
    # status: created | created,modified | deleted
    def app_profile(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "app_profile.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ap-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # name: Name of the EPG
    # bd: Name of associated BD
    # status: created | created,modified | deleted
    def epg(self, **kwargs):
        required_args = {'tn_name': '',
                         'ap_name': '',
                         'name': '',
                         'bd': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "epg.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ap-{}/epg-{}'
               .format(templateVars['tn_name'], templateVars['ap_name'],
                       templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # name: Name of the EPG
    # prfgrp: include | exclude
    def epg_prfgrp(self, **kwargs):
        required_args = {'tn_name': '',
                         'ap_name': '',
                         'name': '',
                         'prfgrp': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        template_file = "epg_prfgrp.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ap-{}/epg-{}'
               .format(templateVars['tn_name'], templateVars['ap_name'],
                       templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # phys_dom: Name of the Physical Domain
    # deploy: lazy | immediate
    # resolve: lazy | immediate | on-demand
    # status: created | created,modified | deleted
    def epg_phys_dom(self, **kwargs):
        required_args = {'tn_name': '',
                         'ap_name': '',
                         'epg_name': '',
                         'phys_dom': '',
                         'deploy': '',
                         'resolve': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "epg_phys_dom.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ap-{}/epg-{}'
               .format(templateVars['tn_name'], templateVars['ap_name'],
                       templateVars['epg_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # vmm_dom: Name of the VMM Domain
    # deploy: lazy | immediate
    # resolve: lazy | immediate | pre-provision
    # status: created | created,modified | deleted
    def epg_vmm_dom(self, **kwargs):
        required_args = {'tn_name': '',
                         'ap_name': '',
                         'epg_name': '',
                         'vmm_dom': '',
                         'deploy': '',
                         'resolve': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "epg_vmm_dom.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ap-{}/epg-{}'
               .format(templateVars['tn_name'], templateVars['ap_name'],
                       templateVars['epg_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # contract: Name of the Contract
    # status: created | created,modified | deleted
    def provide_contract(self, **kwargs):
        required_args = {'tn_name': '',
                         'ap_name': '',
                         'epg_name': '',
                         'contract': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "provide_contract.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ap-{}/epg-{}/rsprov-{}'
               .format(templateVars['tn_name'], templateVars['ap_name'],
                       templateVars['epg_name'], templateVars['contract']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # contract: Name of the Contract
    # status: created | created,modified | deleted
    def consume_contract(self, **kwargs):
        required_args = {'tn_name': '',
                         'ap_name': '',
                         'epg_name': '',
                         'contract': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "consume_contract.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ap-{}/epg-{}/rscons-{}'
               .format(templateVars['tn_name'], templateVars['ap_name'],
                       templateVars['epg_name'], templateVars['contract']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # pod (optional): Integer ID of the pod
    # sw1: Switch 1 of the vPC (node ID) as an integer
    # sw2: Switch 2 of the vPC (node ID) as an integer
    # vpc: Name of the vPC
    # encap: Encapsulation VLAN ID as an integer
    # deploy: lazy | immediate
    # status: created | created,modified | deleted
    def static_path_vpc(self, **kwargs):
        required_args = {'tn_name': '',
                         'ap_name': '',
                         'epg_name': '',
                         'sw1': '',
                         'sw2': '',
                         'vpc': '',
                         'encap': '',
                         'deploy': '',
                         'status': ''}
        optional_args = {'pod': '1'}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['sw1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw1'] = int(templateVars['sw1'])
        if not int(templateVars['sw2']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw2'] = int(templateVars['sw2'])
        if not int(templateVars['encap']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['encap'] = int(templateVars['encap'])
        if not int(templateVars['pod']):
            raise InvalidArg('Pod ID must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "static_path_vpc.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ap-{}/epg-{}'
               .format(templateVars['tn_name'], templateVars['ap_name'],
                       templateVars['epg_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # pod (optional): Integer ID of the pod
    # sw1: Switch 1 of the vPC (node ID) as an integer
    # port: Port ID as an integer (i.e. 1 or 2)
    # encap: Encapsulation VLAN ID as an integer
    # deploy: lazy | immediate
    # status: created | created,modified | deleted
    def static_path_access(self, **kwargs):
        required_args = {'tn_name': '',
                         'ap_name': '',
                         'epg_name': '',
                         'sw1': '',
                         'port': '',
                         'encap': '',
                         'deploy': '',
                         'status': ''}
        optional_args = {'pod': '1'}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['sw1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw1'] = int(templateVars['sw1'])
        if not int(templateVars['port']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port'] = int(templateVars['port'])
        if not int(templateVars['encap']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['encap'] = int(templateVars['encap'])
        if not int(templateVars['pod']):
            raise InvalidArg('Pod ID must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "static_path_access.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ap-{}/epg-{}'
               .format(templateVars['tn_name'], templateVars['ap_name'],
                       templateVars['epg_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # pod (optional): Integer ID of the pod
    # sw1: Switch 1 of the vPC (node ID) as an integer
    # port: Port ID as an integer (i.e. 1 or 2)
    # encap: Encapsulation VLAN ID as an integer
    # deploy: lazy | immediate
    # mode: native | regular (dot1p, trunk)
    # status: created | created,modified | deleted
    def static_path(self, **kwargs):
        required_args = {'tn_name': '',
                         'ap_name': '',
                         'epg_name': '',
                         'sw1': '',
                         'port': '',
                         'encap': '',
                         'deploy': '',
                         'mode': '',
                         'status': ''}
        optional_args = {'pod': '1'}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['sw1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw1'] = int(templateVars['sw1'])
        if not int(templateVars['port']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port'] = int(templateVars['port'])
        if not int(templateVars['encap']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['encap'] = int(templateVars['encap'])
        if not int(templateVars['pod']):
            raise InvalidArg('Pod ID must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "static_path.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ap-{}/epg-{}'
               .format(templateVars['tn_name'], templateVars['ap_name'],
                       templateVars['epg_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # NOTE: At this time this only supports external DHCP servers (ext to fab)
    # tn_name: The name of the Tenant
    # relay_name: Name of the DHCP Label/Provider
    # dhcp_ip: IP of the DHCP server
    # l3_tn: Name of the Tenant containing the L3 out used to reach DHCP server
    # l3_out: Name of the L3 out used to reach DHCP server
    # l3_network: Name of the L3 out Network used to reach DHCP server
    # status: created | created,modified | deleted
    def dhcp_relay(self, **kwargs):
        required_args = {'tn_name': '',
                         'relay_name': '',
                         'dhcp_ip': '',
                         'l3_tn': '',
                         'l3_network': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not ipaddress.ip_address(templateVars['dhcp_ip']):
            raise InvalidArg('Address must be a valid IPv4 address')
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "dhcp_relay.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/relayp-{}'
               .format(templateVars['tn_name'], templateVars['relay_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # relay_name: Name of the DHCP Label/Provider
    # dhcp_ip: IP of the DHCP server
    # dhcp_tn_name: Name of the Tenant containing the DHCP server
    # dhcp_ap_name: Name of the AP containing the DHCP server
    # dhcp_epg_name: Name of the EPG containing the DHCP server
    # status: created | created,modified | deleted
    def dhcp_relay_tn(self, **kwargs):
        required_args = {'tn_name': '',
                         'relay_name': '',
                         'dhcp_ip': '',
                         'dhcp_tn_name': '',
                         'dhcp_ap_name': '',
                         'dhcp_epg_name': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not ipaddress.ip_address(templateVars['dhcp_ip']):
            raise InvalidArg('Address must be a valid IPv4 address')
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "dhcp_relay_tn.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/relayp-{}'
               .format(templateVars['tn_name'], templateVars['relay_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # bd_name: Name of BD to deploy DHCP label to
    # relay_name: Name of the DHCP Label/Provider
    # status: created | created,modified | deleted
    # scope (optional): infra | tenant, defaults to tenant
    def dhcp_label(self, **kwargs):
        required_args = {'tn_name': '',
                         'bd_name': '',
                         'relay_name': '',
                         'status': '',
                         'scope': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "dhcp_label.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/BD-{}'
               .format(templateVars['tn_name'], templateVars['bd_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # pod (optional): Integer ID of the pod
    # fex_id: Integer ID of the FEX
    # sw1: Switch 1 of the vPC (node ID) as an integer
    # port: Port ID as an integer (i.e. 1 or 2)
    # encap: Encapsulation VLAN ID as an integer
    # deploy: lazy | immediate
    # mdoe: native | regular (dot1p / trunk)
    # status: created | created,modified | deleted
    def fex_static_path(self, **kwargs):
        required_args = {'tn_name': '',
                         'ap_name': '',
                         'epg_name': '',
                         'sw1': '',
                         'fex_id': '',
                         'port': '',
                         'encap': '',
                         'deploy': '',
                         'mode': '',
                         'status': ''}
        optional_args = {'pod': '1'}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['sw1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw1'] = int(templateVars['sw1'])
        if not int(templateVars['port']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port'] = int(templateVars['port'])
        if not int(templateVars['encap']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['encap'] = int(templateVars['encap'])
        if not int(templateVars['pod']):
            raise InvalidArg('Pod ID must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if not int(templateVars['fex_id']):
            raise InvalidArg('FEX ID must be an integer')
        else:
            templateVars['fex_id'] = int(templateVars['fex_id'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "fex_static_path.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ap-{}/epg-{}'
               .format(templateVars['tn_name'], templateVars['ap_name'],
                       templateVars['epg_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status


# Class must be instantiated with APIC IP address and cookies
class FabL3Pol(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies
        self.templateLoader = jinja2.FileSystemLoader(
            searchpath=(json_path + 'FabL3Pol/'))
        self.templateEnv = jinja2.Environment(loader=self.templateLoader)

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # domain: Name of the External L3 Domain
    # vrf: Name of associated VRF
    # status: created | created,modified | deleted
    def l3_out(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'domain': '',
                         'vrf': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "l3_out.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # area: backbone | area id as an integer | area id as dotted decimal
    # area_type: regular | nssa
    # status: created | created,modified | deleted
    def ospf(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'area': '',
                         'area_type': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "ospf.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # status: created | created,modified | deleted (of the BGP process)
    def bgp(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "bgp.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # node_name: Name of the Node Profile
    # pod: ID of the pod
    # sw1: Node ID of first switch as an integer
    # sw2: Node ID of second switch as an integer
    # sw1_loop: IP of node1 loopback as a dotted decimal (no mask)
    # sw2: Node ID of first switch as an integer
    # loopback: yes | no
    # status: created | created,modified | deleted
    def node_profile(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'node_name': '',
                         'pod': '',
                         'sw1': '',
                         'sw2': '',
                         'sw1_loop': '',
                         'sw2_loop': '',
                         'loopback': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['pod']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if not int(templateVars['sw1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw1'] = int(templateVars['sw1'])
        if not int(templateVars['sw2']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw2'] = int(templateVars['sw2'])
        if not ipaddress.ip_address(templateVars['sw1_loop']):
            raise InvalidArg('Address must be a valid IPv4 address')
        if not ipaddress.ip_address(templateVars['sw2_loop']):
            raise InvalidArg('Address must be a valid IPv4 address')
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "node_profile.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # pod: ID of the pod
    # node_name: Name of the Node Profile
    # sw: Node ID of the switch as an integer
    # prefix: Prefix in CIDR format (i.e. 0.0.0.0/0)
    # next_hop: IP of the next hop in dotted decimal format (i.e. 1.1.1.1)
    # status: created | created,modified | deleted
    def static_routes(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'pod': '',
                         'node_name': '',
                         'sw': '',
                         'prefix': '',
                         'next_hop': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['pod']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if not int(templateVars['sw']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw'] = int(templateVars['sw'])
        if not ipaddress.ip_address(templateVars['next_hop']):
            raise InvalidArg('Address must be a valid IPv4 address')
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "static_routes.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # pod: ID of the pod
    # node_name: Name of the Node Profile
    # int_profile: Name of the Interface Profile
    # sw: Node ID of the switch as an integer
    # port: Port number as an integer
    # ip: IP of the interface in dotted decimal format (i.e. 1.1.1.1)
    # int_profile_status created | created,modified | deleted of the Int Pro
    # status: created | created,modified | deleted of the Interface itself
    def routed_ints(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'pod': '',
                         'node_name': '',
                         'int_profile': '',
                         'sw': '',
                         'port': '',
                         'ip': '',
                         'int_profile': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['pod']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if not int(templateVars['sw']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw'] = int(templateVars['sw'])
        if not int(templateVars['port']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port'] = int(templateVars['port'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "routed_ints.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}/lnodep-{}/lifp-{}'
               .format(templateVars['tn_name'], templateVars['name'],
                       templateVars['node_name'], templateVars['int_profile']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # pod: ID of the pod
    # node_name: Name of the Node Profile
    # int_profile: Name of the Interface Profile
    # sw: Node ID of the switch as an integer
    # port: Port number as an integer
    # vlan: VLAN ID as an integer
    # ip: IP of the interface in dotted decimal format (i.e. 1.1.1.1)
    # int_profile_status created | created,modified | deleted of the Interface Profile
    # status: created | created,modified | deleted of the Interface itself
    def routed_sub_ints(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'pod': '',
                         'node_name': '',
                         'int_profile': '',
                         'sw': '',
                         'port': '',
                         'vlan': '',
                         'ip': '',
                         'int_profile': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['pod']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if not int(templateVars['sw']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw'] = int(templateVars['sw'])
        if not int(templateVars['port']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port'] = int(templateVars['port'])
        if not int(templateVars['vlan']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['vlan'] = int(templateVars['vlan'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "routed_sub_ints.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}/lnodep-{}/lifp-{}'
               .format(templateVars['tn_name'], templateVars['name'],
                       templateVars['node_name'], templateVars['int_profile']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # pod: ID of the pod
    # node_name: Name of the Node Profile
    # int_profile: Name of the Interface Profile
    # sw1: Switch-1 ID of the switch as an integer
    # sw2: Switch-2 ID of the switch as an integer
    # sw1_ip: IP of Switch-1 in dotted-decimal
    # sw2_ip: IP of Switch-2 in dotted-decimal
    # vlan: VLAN ID as an integer
    # vpc: Name of associated vPC
    # int_profile_status: created | created,modified | deleted of the Int Pro
    # status: created | created,modified | deleted of the Interface itself
    def svi(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'pod': '',
                         'node_name': '',
                         'int_profile': '',
                         'sw1': '',
                         'sw2': '',
                         'sw1_ip': '',
                         'sw2_ip': '',
                         'vlan': '',
                         'vpc': '',
                         'int_profile_status': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['pod']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if not int(templateVars['sw1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw1'] = int(templateVars['sw1'])
        if not int(templateVars['sw2']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw2'] = int(templateVars['sw2'])
        if not int(templateVars['vlan']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['vlan'] = int(templateVars['vlan'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "svi.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}/lnodep-{}/lifp-{}'
               .format(templateVars['tn_name'], templateVars['name'],
                       templateVars['node_name'], templateVars['int_profile']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # pod: ID of the pod
    # node_name: Name of the Node Profile
    # int_profile: Name of the Interface Profile
    # sw1: Switch-1 ID of the switch as an integer
    # sw2: Switch-2 ID of the switch as an integer
    # vpc: Name of associated vPC
    # status: created | created,modified | deleted of the VIP itself
    def svi_vip(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'pod': '',
                         'node_name': '',
                         'int_profile': '',
                         'sw1': '',
                         'sw2': '',
                         'vpc': '',
                         'vip': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['pod']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if not int(templateVars['sw1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw1'] = int(templateVars['sw1'])
        if not int(templateVars['sw2']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw2'] = int(templateVars['sw2'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "svi_vip.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}/lnodep-{}/lifp-{}/rspathL3OutAtt-[topology'
               '/pod-{}/protpaths-{}-{}/pathep-[{}]]'
               .format(templateVars['tn_name'], templateVars['name'],
                       templateVars['node_name'], templateVars['int_profile'],
                       templateVars['pod'], templateVars['sw1'],
                       templateVars['sw2'], templateVars['vpc']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # epg_name: Name of the Prefix Based EPG
    # subnet: Subent in CIDR format
    # status: created | created,modified | deleted of the EPG itself
    # subnet_status created | created,modified | deleted of the subnet
    def network_epg(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'epg_name': '',
                         'subnet': '',
                         'status': '',
                         'subnet_status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')
        if templateVars['subnet_status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "network_epg.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}/instP-{}'
               .format(templateVars['tn_name'], templateVars['name'],
                       templateVars['epg_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # pol_name: The name of the Interface Policy
    # hello: hello interval in seconds as an integer
    # dead: dead interval in seconds as an integer
    # net_type: p2p | bcast | unspecified
    # status: created | created,modified | deleted
    def ospf_int_pol(self, **kwargs):
        required_args = {'tn_name': '',
                         'pol_name': '',
                         'hello': '',
                         'dead': '',
                         'net_type': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['hello']):
            raise InvalidArg('Value must be an integer')
        else:
            templateVars['hello'] = int(templateVars['hello'])
        if not int(templateVars['dead']):
            raise InvalidArg('Value must be an integer')
        else:
            templateVars['dead'] = int(templateVars['dead'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "ospf_int_pol.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/ospfIfPol-{}'
               .format(templateVars['tn_name'], templateVars['pol_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3 Out
    # node_name: Name of the Node Profile
    # int_profile: Name of the Interface Profile
    # pol_type: ospf | eigrp | bgp
    # pol_name: Name of the Interface Policy to be applied
    # status: created | created,modified | deleted
    def deploy_int_pol(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'node_name': '',
                         'int_profile': '',
                         'pol_type': '',
                         'pol_name': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "deploy_int_pol.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}/lnodep-{}/lifp-{}'
               .format(templateVars['tn_name'], templateVars['name'],
                       templateVars['node_name'],
                       templateVars['int_profile']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3 Out
    # node_name: Name of the Node Profile
    # peer: BGP Peer address in dotted decimal
    # local_asn: Local BGP ASN as an integer
    # remote_asn: Remote BGP ASN as an integer
    # status: created | created,modified | deleted
    def bgp_peer_loopback(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'node_name': '',
                         'peer': '',
                         'local_asn': '',
                         'remote_asn': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not ipaddress.ip_address(templateVars['peer']):
            raise InvalidArg('Address must be a valid IPv4 address')
        if not (int(templateVars['local_asn']) in range(1, 65535)):
            raise InvalidArg('Invalid BGP ASN')
        else:
            templateVars['local_asn'] = int(templateVars['local_asn'])
        if not (int(templateVars['remote_asn']) in range(1, 65535)):
            raise InvalidArg('Invalid BGP ASN')
        else:
            templateVars['remote_asn'] = int(templateVars['remote_asn'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "bgp_peer_loopback.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}'
               .format(templateVars['tn_name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant
    # name: The name of the L3 Out
    # pod: ID of the pod
    # node_name: Name of the Node Profile
    # int_profile: Name of the Interface Profile
    # sw1: Node ID of the first switch as an integer
    # sw1: Node ID of the second switch as an integer
    # vpc: Name of the associated vPC
    # peer: BGP Peer address in dotted decimal
    # local_asn: Local BGP ASN as an integer
    # remote_asn: Remote BGP ASN as an integer
    # status: created | created,modified | deleted
    def bgp_peer_svi(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'pod': '',
                         'node_name': '',
                         'int_profile': '',
                         'sw1': '',
                         'sw2': '',
                         'vpc': '',
                         'peer': '',
                         'local_asn': '',
                         'remote_asn': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['pod']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if not int(templateVars['sw1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw1'] = int(templateVars['sw1'])
        if not int(templateVars['sw2']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['sw2'] = int(templateVars['sw2'])
        if not ipaddress.ip_address(templateVars['peer']):
            raise InvalidArg('Address must be a valid IPv4 address')
        if not (int(templateVars['local_asn']) in range(1, 65535)):
            raise InvalidArg('Invalid BGP ASN')
        else:
            templateVars['local_asn'] = int(templateVars['local_asn'])
        if not (int(templateVars['remote_asn']) in range(1, 65535)):
            raise InvalidArg('Invalid BGP ASN')
        else:
            templateVars['remote_asn'] = int(templateVars['remote_asn'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "bgp_peer_loopback.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}/lnodep-{}'
               .format(templateVars['tn_name'], templateVars['name'],
                       templateVars['node_name'], templateVars['int_profile']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # tn_name: Name of the Tenant
    # name: The name of the L3 Out
    # epg_name: Name of the L3 Out EPG (Network object)
    # contract: Name of the contract to provide
    # status: created | created,modified | deleted
    def l3_provide_contract(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'epg_name': '',
                         'contract': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "l3_provide_contract.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}/instP-{}'
               .format(templateVars['tn_name'], templateVars['name'],
                       templateVars['epg_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # tn_name: Name of the Tenant
    # name: The name of the L3 Out
    # epg_name: Name of the L3 Out EPG (Network object)
    # contract: Name of the contract to consume
    # status: created | created,modified | deleted
    def l3_consume_contract(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'epg_name': '',
                         'contract': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "l3_consume_contract.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/out-{}/instP-{}'
               .format(templateVars['tn_name'], templateVars['name'],
                       templateVars['epg_name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status


# Class must be instantiated with APIC IP address and cookies
class TshootPol(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies
        self.templateLoader = jinja2.FileSystemLoader(
            searchpath=(json_path + 'TshootPol/'))
        self.templateEnv = jinja2.Environment(loader=self.templateLoader)

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant (for source of SPAN)
    # name: Name of the SPAN Source (automatically append -Group where appropriate)
    # admin: enabled | disabled
    # direction: both | in | out
    # ap: Name of Application Profile (for source of SPAN)
    # epg: Name of EPG (for source of SPAN)
    # dest: Name of SPAN Destination, -Group is automatically appended
    # status: created | created,modified | deleted
    def span_src(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'admin': '',
                         'direction': '',
                         'ap': '',
                         'epg': '',
                         'dest': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "span_src.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/srcgrp-{}-Group'
               .format(templateVars['name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # tn_name: Name of the Tenant (where you are building the SPAN)
    # name: The name of the SPAN Destination Group
    # tn_dest: Name of the Tenant where the SPAN destination resides
    # ap: Name of Application Profile (for destination of SPAN)
    # epg: Name of EPG (for destination of SPAN)
    # dest_ip: IP address of device terminating SPAN
    # src_ip: IP address of ACI ERSPAN source
    # status: created | created,modified | deleted
    def span_dst(self, **kwargs):
        required_args = {'tn_name': '',
                         'name': '',
                         'tn_dest': '',
                         'ap': '',
                         'epg': '',
                         'dest_ip': '',
                         'src_ip': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not ipaddress.ip_address(templateVars['dest_ip']):
            raise InvalidArg('Address must be a valid IPv4 address')
        if not ipaddress.ip_address(templateVars['src_ip']):
            raise InvalidArg('Address must be a valid IPv4 address')
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "span_dst.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-{}/destgrp-{}-Group'
               .format(templateVars['name'], templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status


# Class must be instantiated with APIC IP address and cookies
class Query(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies

    # Method must be called with the following kwargs.
    # dn: DN of object you would like to query
    # Returns status code and json payload of query
    def query_dn(self, dn):
        s = requests.Session()
        try:
            r = s.get('https://{}/api/node/mo/{}.json'.format(self.apic, dn),
                      cookies=self.cookies, verify=False)
            status = r.status_code
            payload = json.loads(r.text)
        except Exception as e:
            print("Failed to query DN. Exception: {}".format(e))
            status = 666
        return (status, payload)

    def query_class(self, query_class):
        s = requests.Session()
        try:
            r = s.get('https://{}/api/node/class/{}.json'.format(self.apic,
                      query_class), cookies=self.cookies, verify=False)
            status = r.status_code
            payload = json.loads(r.text)
        except Exception as e:
            print("Failed to query Class. Exception: {}".format(e))
            status = 666
        return (status, payload)


# Class must be instantiated with APIC IP address and cookies
class FabCfgMgmt(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies
        self.templateLoader = jinja2.FileSystemLoader(
            searchpath=(json_path + 'FabCfgMgmt/'))
        self.templateEnv = jinja2.Environment(loader=self.templateLoader)

    # Method must be called with the following kwargs. Note only supports
    # SCP at this time (could easily add SFTP or FTP if needed though)
    # name = name of the remote location
    # ip = IP of the remote location (note, module does no validation)
    # path = Path on the remote location
    # user = username for remote location
    # pword = password (sent in clear text) for the remote location
    # status = created | created,modified | deleted
    def remote_path(self, **kwargs):
        required_args = {'name': '',
                         'ip': '',
                         'path': '',
                         'user': '',
                         'pword': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not ipaddress.ip_address(templateVars['ip']):
            raise InvalidArg('Address must be a valid IPv4 address')
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "remote_path.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/fabric/path-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name = name of the snapshot itself
    # snapshot = true | false - if true it creates an export policy and
    # takes a snapshot, if false it simply creates an export policy
    # status = created | created,modified | deleted
    # path = (Optional) remote path for export (can be left blank for snapshot)
    def backup(self, **kwargs):
        required_args = {'name': '',
                         'snapshot': '',
                         'status': ''}
        optional_args = {'path': ''}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "backup.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/fabric/configexp-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name = name of the import object itself
    # filename = name of the file to import
    # path = name of the remote path object where the file lives
    def replace(self, **kwargs):
        required_args = {'name': '',
                         'filename': '',
                         'path': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        template_file = "replace.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/fabric/configimp-{}'.format(templateVars['name'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name = name of the snapshot itself (note you need to put the file
    # extension in yourself)
    def snapback(self, **kwargs):
        required_args = {'name': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        template_file = "snapback.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/fabric/configimp-default'
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status


# Class must be instantiated with APIC IP address and cookies
class FabAdminMgmt(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies
        self.templateLoader = jinja2.FileSystemLoader(
            searchpath=(json_path + 'FabAdminMgmt/'))
        self.templateEnv = jinja2.Environment(loader=self.templateLoader)

    # Method must be called with the following kwargs.
    # user: Username for user to be created/modified
    # status: created | created,modified | deleted
    # pwd: Password of user
    def user(self, **kwargs):
        required_args = {'user': '',
                         'status': '',
                         'pwd': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "user.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = 'mo/uni/userext/user-{}'.format(templateVars['user'])
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # address: node ip
    # gateway: gateway IP
    # pod: Pod Node Lives in
    # id: Node id
    def oob_mgmt(self, **kwargs):
        required_args = {'address': '',
                         'gateway': '',
                         'pod': '',
                         'status': '',
                         'id': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['id']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['id'] = int(templateVars['id'])
        if not int(templateVars['pod']):
            raise InvalidArg('Pod must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "oob_mgmt.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)
        uri = 'mo/uni/tn-mgmt'
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: name of in band EPG
    # vlan: vlan to be used for inb
    # status: created | created,modified | deleted
    def inb_epg(self, **kwargs):
        required_args = {'name': '',
                         'vlan': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['vlan']):
            raise InvalidArg('VLAN IDs must be an integer')
        else:
            templateVars['vlan'] = int(templateVars['vlan'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "inb_epg.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)
        uri = 'mo/uni/tn-mgmt'
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: name of in band EPG
    # contract: contract to be applied
    # status: created | created,modified | deleted
    def inb_epg_consume(self, **kwargs):
        required_args = {'name': '',
                         'contract': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "inb_epg_consume.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)
        uri = 'mo/uni/tn-mgmt'
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: name of in band EPG
    # contract: contract to be applied
    # status: created | created,modified | deleted
    def inb_epg_provide(self, **kwargs):
        required_args = {'name': '',
                         'contract': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "inb_epg_provide.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)
        uri = 'mo/uni/tn-mgmt'
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # address: node ip
    # gateway: gateway IP
    # pod: Pod Node Lives in
    # id: Node id
    def inb_mgmt(self, **kwargs):
        required_args = {'address': '',
                         'gateway': '',
                         'inb_epg_name': '',
                         'status': '',
                         'id': ''}
        optional_args = {'pod': '1'}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['id']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['id'] = int(templateVars['id'])
        if not int(templateVars['pod']):
            raise InvalidArg('Pod must be an integer')
        else:
            templateVars['pod'] = int(templateVars['pod'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "inb_mgmt.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)
        uri = 'mo/uni/tn-mgmt'
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status


# Class must be instantiated with APIC IP address and cookies
class FabVMM(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies
        self.templateLoader = jinja2.FileSystemLoader(
            searchpath=(json_path + 'FabVMM/'))
        self.templateEnv = jinja2.Environment(loader=self.templateLoader)

    # Method must be called with the following kwargs.
    # name: The name of the VMware VMM Domain to create
    # host: IP of the vCenter
    # dc: Name of the datacenetr in vCenter (case sensitive)
    # user: vCenter user name (must have correct permissions)
    # pwd: vCenter user password
    # status: created | created,modified | deleted
    def vcenter(self, **kwargs):
        required_args = {'name': '',
                         'host': '',
                         'vl_pool': '',
                         'dc': '',
                         'user': '',
                         'pwd': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "vcenter.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/vmmp-VMware/dom-{}'
               .format(templateVars['name']))

        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: The name of the VMware VMM Domain to create
    # aep: The name of the AEP to associate to the VMM Domain
    # status: created | created,modified | deleted
    def vcenter_aep(self, **kwargs):
        required_args = {'name': '',
                         'aep': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "vcenter_aep.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/infra/attentp-{}'
               .format(templateVars['aep']))

        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: The name of the VMM Domain
    # status: created | created,modified | deleted
    def vswitch_pol(self, **kwargs):
        required_args = {'name': '',
                         'status': ''}
        optional_args = {'cdp_pol': 'CDP-Enabled',
                         'lldp_pol': 'LLDP-Disabled',
                         'dom_type': 'VMware'}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "vswitch_pol.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/vmmp-VMware/dom-{}-vCenter'
               .format(templateVars['name']))

        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status


# Class must be instantiated with APIC IP address and cookies
class Mpod(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies
        self.templateLoader = jinja2.FileSystemLoader(
            searchpath=(json_path + 'Mpod/'))
        self.templateEnv = jinja2.Environment(loader=self.templateLoader)

    # Method must be called with the following kwargs.
    # name: name of the spine policy group
    # cdp: name of the cdp policy
    # aep: name of the AEP
    # int: name of the interface policy
    # status: created | created,modified | deleted
    def spine_pol_grp(self, **kwargs):
        required_args = {'name': '',
                         'cdp': '',
                         'aep': '',
                         'int': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "spine_pol_grp.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/infra/funcprof/spaccportgrp-{}'
               .format(templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: name of the spine interface profile
    # port_name: name of the interface selector
    # mod_start: integer for starting module (blade)
    # mod_end: integer for ending module (blade)
    # port_start: integer for starting port id
    # port_end: integer for ending port id
    # status: created | created,modified | deleted
    def spine_int_pro(self, **kwargs):
        required_args = {'name': '',
                         'port_name': '',
                         'mod_start': '',
                         'mod_end': '',
                         'port_start': '',
                         'port_end': '',
                         'pol_grp': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['mod_start']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['mod_start'] = int(templateVars['mod_start'])
        if not int(templateVars['mod_end']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['mod_end'] = int(templateVars['mod_end'])
        if not int(templateVars['port_start']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port_start'] = int(templateVars['port_start'])
        if not int(templateVars['port_end']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['port_end'] = int(templateVars['port_end'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "spine_int_pro.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/infra/spaccportprof-{}'
               .format(templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # name: name of the spine switch profile
    # spine_sel_name: name of the spine selector
    # id: integer id of the spine node
    # int_sel: name of the spine interface selector
    # status: created | created,modified | deleted
    def spine_sw_pro(self, **kwargs):
        required_args = {'name': '',
                         'spine_sel_name': '',
                         'id': '',
                         'int_sel': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['id']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['id'] = int(templateVars['id'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "spine_sw_pro.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/infra/spprof-{}'
               .format(templateVars['name']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # pod_id: integer of the pod ID to initialize
    # tep_pool: CIDR notation for pod TEP pool range
    # status: created | created,modified | deleted
    def init_pod(self, **kwargs):
        required_args = {'pod_id': '',
                         'tep_pool': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['pod_id']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['pod_id'] = int(templateVars['pod_id'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "init_pod.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/controller/setuppol/setupp-{}'
               .format(templateVars['pod_id']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # EXPERIMENTAL: No support for multiple IPN connections per pod
    # conn_id: integer of the pod ID to initialize
    # name: Name of the IPN Profile
    # rt: (optional) default is the fabric default (as2-nn4:5:16)
    # pod1_dtep: IP for pod1 DTEP
    # pod2_dtep: IP for pod2 DTEP
    # route_prof_name: (optional) Name of the route Prof
    # subnet1: CIDR for Pod1 peering
    # subnet2: CIDR for Pod2 peering
    # status: created | created,modified | deleted
    def create_mpod(self, **kwargs):
        required_args = {'conn_id': '',
                         'name': '',
                         'pod1_dtep': '',
                         'pod2_dtep': '',
                         'subnet1': '',
                         'subnet2': '',
                         'status': ''}
        optional_args = {'rt': 'extended:as2-nn4:5:16',
                         'route_prof_name': 'MpodRouteProf'}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['conn_id']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['conn_id'] = int(templateVars['conn_id'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "create_mpod.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-infra/fabricExtConnP-{}'
               .format(templateVars['conn_id']))
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

    # Method must be called with the following kwargs.
    # EXPERIMENTAL: No support for multiple IPN connections per pod
    # pod1_spine1:
    # pod1_spine1_int1:
    # pod1_spine1_int1_ip:
    # pod1_spine1_rtrid:
    # pod2_spine1:
    # pod2_spine1_int1:
    # pod2_spine1_int1_ip:
    # pod2_spine1_rtrid:
    # status: created | created,modified | deleted
    def mpod_l3_out(self, **kwargs):
        required_args = {'pod1_spine1': '',
                         'pod1_spine1_int1': '',
                         'pod1_spine1_int1_ip': '',
                         'pod1_spine1_rtrid': '',
                         'pod2_spine1': '',
                         'pod2_spine1_int1': '',
                         'pod2_spine1_int1_ip': '',
                         'pod2_spine1_rtrid': '',
                         'status': ''}
        optional_args = {}

        templateVars = process_kwargs(required_args, optional_args, **kwargs)

        if not int(templateVars['pod1_spine1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['pod1_spine1'] = int(templateVars['pod1_spine1'])
        if not int(templateVars['pod2_spine1']):
            raise InvalidArg('ID must be an integer')
        else:
            templateVars['pod2_spine1'] = int(templateVars['pod2_spine1'])
        if templateVars['status'] not in valid_status:
            raise InvalidArg('Status invalid')

        template_file = "mpod_l3_out.json"
        template = self.templateEnv.get_template(template_file)

        payload = template.render(templateVars)

        uri = ('mo/uni/tn-infra/out-multipod')
        status = post(self.apic, payload, self.cookies, uri, template_file)
        return status

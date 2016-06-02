import requests
import json
import sys


'''
Notes:

- Feature Add: Untagged, Access, Trunk on access port static path bindings
- Feature Add: Validate input for things that have exacting requirements -
    i.e. OSPF can be 'backbone' or dotted decimal or an integer
- Note: If/when modular leafs become a thing, will have to tweak the static
    path binding for access ports - URI is hard coded to be module 1
- Feature Add: Add capability to make a L3 Out Node Profile for only a single
    switch
- Feature Add: Multipod support (pod #)
- Feature Add: OSPF MTU Ignore support on Interface Policy
- Note: Validate options for L3 Interface Policy type (i.e. OSPF, EIGRP, BPG?)
    May want/need to break this back into dedicated types - one for OSPF one
    for EIGRP etc. due to differences in authentication etc.
- Feature Add: Need significant improvements to BGP Peer setup eventually

General Information:

Contains classes to deploy policies to an ACI fabric. Each class must be
instantiated with the APIC IP address and challenge cookie (which is returned
from the login class. Where applicable, functions will try to validate integers
are indeed integers, and will fail out with a status of 667 if that try fails.
All functions return status on aforementioned fail, or the status code from
the POST to the fabric. This information can then be stored to have a record
of which POSTS succeeded and which failed.

Generally speaking this is a "replacement" for Postman/Runner with respect to
an ACI deployment. The idea is to feed a script an excel workbook with the
appropriate variables into this to deploy a fabric from scratch.

'''


# Class must be instantiated with APIC IP address, username, and password
# the login function returns the APIC cookies.
class FabLogin(object):
    def __init__(self, apic, user, pword):
        self.apic = apic
        self.user = user
        self.pword = pword

    def login(self):
        # Load login json payload
        payload = {
            'aaaUser': {
                'attributes': {
                    'name': self.user,
                    'pwd': self.pword
                }
            }
        }
        s = requests.Session()
        # Try the request, if exception, exit program w/ error
        try:
            # Verify is disabled as there are issues if it is enabled
            r = s.post('https://%s/api/mo/aaaLogin.json' % self.apic,
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
        except Exception, e:
            print("Something went wrong logging into the APIC - ABORT!")
            # Log exit reason somewhere
            sys.exit(e)
        return cookies


# Class must be instantiated with APIC IP address and cookies
class FabPodPol(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies

    # Method must be called with the following data.
    # name: Name of the node being deployed
    # id: ID of the node being deploeyd as an integer (i.e. 101)
    # serial: Serial number of device being deployed
    # descr: (Optional) Description of the node
    # fabric: (Optional) Default is 1 - will be relevant for multipod
    # pod: (Optional) Default is 1 - will be relevant for multipod
    def comission_hw(self, name, id, serial, descr='', fabric='1', pod='1'):
        try:
            id = int(id)
            if fabric == '':
                fabric = 1
            if pod == '':
                pod = 1
            fabric = int(fabric)
            pod = int(pod)
        except:
            status = 667
            return status
        payload = {
            "polUni": {
                "attributes": {
                    "dn": "uni"
                },
                "children": [
                    {
                        "ctrlrInst": {
                            "attributes": {
                                "ownerKey": "",
                                "ownerTag": ""
                            },
                            "children": [
                                {
                                    "fabricNodeIdentPol": {
                                        "attributes": {
                                            "name": "default",
                                            "ownerKey": "",
                                            "ownerTag": ""
                                        },
                                        "children": [
                                            {
                                                "fabricNodeIdentP": {
                                                    "attributes": {
                                                        "name": "%s" % name,
                                                        "nodeId": "%s" % id,
                                                        "serial": "%s" % serial,
                                                        "descr": "%s" % descr,
                                                        "fabricId": "%s" % fabric,
                                                        "podId": "%s" % pod
                                                    }
                                                }
                                            },
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni.json'
                       % (self.apic), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Hadrware Failed to provision. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # address: Name/IP of the NTP server
    # status: created | created,modified | deleted
    def ntp(self, address, status):
        payload = {
            "datetimeNtpProv": {
                "attributes": {
                    "dn": "uni/fabric/time-default/ntpprov-%s" % address,
                    "name": "%s" % address,
                    "rn": "ntpprov-%s" % address,
                    "status": "%s" % status
                },
                "children": [
                    {
                        "datetimeRsNtpProvToEpg": {
                            "attributes": {
                                "tDn": "uni/tn-mgmt/mgmtp-default/oob-default",
                                "status": "created,modified"
                            },
                            "children": []
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni.json'
                       % (self.apic), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("NTP Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the node being deployed
    # address: IP of DNS Server
    # status: (Of the DNS Server) created | created,modified | deleted
    # domain: (Optional) DNS Domain
    # domain_status: (Optional) created | created,modified | deleted
    # preferred: (Optional) yes | no
    # domain_default: (Optional) yes | no
    def dns(self, address, status, domain='', domain_status='deleted',
            preferred='no', domain_default='no'):
        if domain_status == '':
            domain_status = 'deleted'
        if preferred == '':
            preferred = 'no'
        if domain_default == '':
            domain_default = 'no'
        payload = {
            "dnsProfile": {
                "attributes": {
                    "dn": "uni/fabric/dnsp-default",
                    "name": "default",
                    "status": "created,modified"
                },
                "children": [
                    {
                        "dnsProv": {
                            "attributes": {
                                "addr": "%s" % address,
                                "preferred": "%s" % preferred,
                                "status": "%s" % status,
                                "rn": "prov-[%s]" % address
                            }
                        }
                    },
                    {
                        "dnsDomain": {
                            "attributes": {
                                "isDefault": "%s" % domain_default,
                                "name": "%s" % domain,
                                "rn": "dom-%s" % domain,
                                "status": "%s" % domain_status
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/fabric/dnsp-default.json'
                       % (self.apic), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("DNS Server Failed to deploy. Exception: %s" % e)
            status = 666
        payload = {
            "dnsRsProfileToEpg": {
                "attributes": {
                    "tDn": "uni/tn-mgmt/mgmtp-default/oob-default",
                    "status": "created,modified"
                },
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/fabric/dnsp-default/rsProfileToEpg.json'
                       % (self.apic), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
        except Exception, e:
            print("DNS to OOB EPG Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # asn: Fabric BGP ASN as an integer
    # status: created | created,modified | deleted
    def fabric_bgp(self, asn, status,):
        try:
            asn = int(asn)
        except:
            status = 667
            return status
        payload = {
            "bgpAsP": {
                "attributes": {
                    "dn": "uni/fabric/bgpInstP-default/as",
                    "asn": "%s" % asn,
                    "rn": "as",
                    "status": "%s" % status
                },
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/fabric/bgpInstP-default/as.json'
                       % (self.apic), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Fabric BGP Policy Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # asn: Fabric route reflector ID as an integer
    # status: created | created,modified | deleted
    def fabric_rr(self, rr, status):
        try:
            rr = int(rr)
        except:
            status = 667
            return status
        payload = {
            "bgpRRNodePEp": {
                "attributes": {
                    "dn": "uni/fabric/bgpInstP-default/rr/node-%s" % rr,
                    "id": "%s" % rr,
                    "rn": "node-%s" % rr,
                    "status": "%s" % status
                },
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/fabric/bgpInstP-default/rr/node-%s.json'
                       % (self.apic, rr), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Fabric Route Reflector Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    def pod_pol(self, name, status):
        payload = {
            "fabricPodPGrp": {
                "attributes": {
                    "dn": "uni/fabric/funcprof/podpgrp-%s" % name,
                    "name": "%s" % name,
                    "rn": "podpgrp-%s" % name,
                    "status": "%s" % status
                },
                "children": [
                    {
                        "fabricRsTimePol": {
                            "attributes": {
                                "tnDatetimePolName": "default",
                                "status": "created,modified"
                            },
                        }
                    },
                    {
                        "fabricRsPodPGrpIsisDomP": {
                            "attributes": {
                                "tnIsisDomPolName": "default",
                                "status": "created,modified"
                            },
                        }
                    },
                    {
                        "fabricRsPodPGrpCoopP": {
                            "attributes": {
                                "tnCoopPolName": "default",
                                "status": "created,modified"
                            },
                        }
                    },
                    {
                        "fabricRsPodPGrpBGPRRP": {
                            "attributes": {
                                "tnBgpInstPolName": "default",
                                "status": "created,modified"
                            },
                        }
                    },
                    {
                        "fabricRsCommPol": {
                            "attributes": {
                                "tnCommPolName": "default",
                                "status": "created,modified"
                            },
                        }
                    },
                    {
                        "fabricRsSnmpPol": {
                            "attributes": {
                                "tnSnmpPolName": "default",
                                "status": "created,modified"
                            },
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/fabric/funcprof/podpgrp-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Fabric Pod Policy Failed to deploy. Exception: %s" % e)
            status = 666
        payload = {
            "fabricRsPodPGrp": {
                "attributes": {
                    "tDn": "uni/fabric/funcprof/podpgrp-%s" % name,
                    "status": "created,modified"
                },
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/fabric/podprof-default/pods-default-typ-ALL/rspodPGrp.json'
                       % (self.apic), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Assigning Pod Policy Failed. Exception: %s" % e)
            status = 666
        return status


# Class must be instantiated with APIC IP address and cookies
class FabAccPol(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies

    # Method must be called with the following data.
    # name: The name of the CDP policy
    # state: enabled | disabled
    # status: created | created,modified | deleted
    def cdp(self, name, state, status):
        payload = {
            'cdpIfPol': {
                'attributes': {
                    'dn': 'uni/infra/cdpIfP-%s' % name,
                    'name': '%s' % name,
                    'adminSt': '%s' % state,
                    'rn': 'cdpIfP-%s' % name,
                    'status': '%s' % status
                },
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/cdpIfP-%s.json' %
                       (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("CDP Policy Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: The name of the LLDP policy
    # state: enabled | disabled
    #   Note: The configured state is deployed to both Tx and Rx
    # status: created | created,modified | deleted
    def lldp(self, name, state, status):
        payload = {
            'lldpIfPol': {
                'attributes': {
                    'dn': 'uni/infra/lldpIfP-%s' % name,
                    'name': '%s' % name,
                    'adminRxSt': '%s' % state,
                    'adminTxSt': '%s' % state,
                    'rn': 'lldpIfP-%s' % name,
                    'status': '%s' % status
                },
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/lldpIfP-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("LLDP Policy Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: The name of the Link policy
    # auto_neg: on | off
    # speed: 100M | 1G | 10G | 40G | auto
    #   Note: 100G should be available soon if not already in some versions
    # status: created | created,modified | deleted
    def link(self, name, auto_neg, speed, status):
        payload = {
            'fabricHIfPol': {
                'attributes': {
                    'dn': 'uni/infra/hintfpol-%s' % name,
                    'name': '%s' % name,
                    'autoNeg': '%s' % auto_neg,
                    'speed': '%s' % speed,
                    'status': '%s' % status
                }
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/hintfpol-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Link Policy Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: The name of the Port-Channel policy
    # mode: off | mac-pin | active
    #   Note: 'off' = static mode-on
    # state: enabled | disabled
    #   Note: The configured state is deployed to both Tx and Rx
    # status: created | created,modified | deleted
    def pc(self, name, mode, status):
        payload = {
            'lacpLagPol': {
                'attributes': {
                    'dn': 'uni/infra/lacplagp-%s' % name,
                    'name': '%s' % name,
                    'ctrl': 'fast-sel-hot-stdby,graceful-conv,susp-individual',
                    'name': '%s' % name,
                    'status': '%s' % status,
                    'mode': '%s' % mode
                },
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/lacplagp-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Port Channel Policy Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: The name of the Per Port VLAN policy
    # state: enabled | disabled
    # status: created | created,modified | deleted
    def ppv(self, name, state, status):
        payload = {
            'l2IfPol': {
                'attributes': {
                    'dn': 'uni/infra/l2IfP-%s' % name,
                    'name': '%s' % name,
                    'vlanScope': '%s' % state,
                    'status': '%s' % status
                }
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/l2IfP-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Per Port VLAN Policy Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: The name of the Per Port VLAN policy
    # state: enabled | disabled
    # status: created | created,modified | deleted
    def mcp_intf(self, name, state, status):
        payload = {
            'mcpIfPol': {
                'attributes': {
                    'dn': 'uni/infra/mcpIfP-%s' % name,
                    'name': '%s' % name,
                    'status': '%s' % status,
                    'adminSt': '%s' % state
                }
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/mcpIfP-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("MCP Interface Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # password: string for global MCP password
    # state: enabled | disabled
    def mcp_global(self, password, state):
        payload = {
            'mcpInstPol': {
                'attributes': {
                    'dn': 'uni/infra/mcpInstP-default',
                    'key': '%s' % password,
                    'adminSt': '%s' % state
                }
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/mcpInstP-default.json'
                       % self.apic, data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("MCP Global Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # event: mcp-loop | ep-move | bpduguard
    # state: true | false
    def err_disable(self, event, state):
        payload = {
            'edrEventP': {
                'attributes': {
                    'dn': 'uni/infra/edrErrDisRecoverPol-default/edrEventP-event-%s' % event,
                    'recover': '%s' % state
                },
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/edrErrDisRecoverPol-default/edrEventP-event-%s.json'
                       % (self.apic, event), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Error Disable Policy Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: The name of the parent VLAN Pool
    # mode: static | dynamic
    # range_mode: static | dynamic
    # start: Starting VLAN - as an integer
    # end: Ending VLAN - as an integer
    # status: created | created,modified | deleted
    def vl_pool(self, name, mode, range_mode, start, end, status):
        try:
            start = int(start)
            end = int(end)
        except:
            status = 667
            return status
        payload = {
            'fvnsVlanInstP': {
                'attributes': {
                    'allocMode': '%s' % mode,
                    'dn': 'uni/infra/vlanns-[%s]-%s' % (name, mode),
                    'name': '%s' % name,
                    'status': '%s' % status
                },
                'children': [
                    {
                        'fvnsEncapBlk': {
                            'attributes': {
                                'allocMode': '%s' % range_mode,
                                'from': 'vlan-%s' % start,
                                'to': 'vlan-%s' % end,
                                'status': '%s' % status
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/vlanns-[%s]-%s.json'
                       % (self.apic, name, mode), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("VLAN Pool Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
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
    def aep(self, name, status, infra, infra_vlan='0', override='deleted',
            override_pc='', override_cdp='', override_lldp=''):
        if infra_vlan == '':
            infra_vlan = 0
        try:
            infra_vlan = int(infra_vlan)
        except:
            status = 667
            return status
        if override == 'created,modified':
            payload = {
                'infraAttEntityP': {
                    'attributes': {
                        'dn': 'uni/infra/attentp-%s' % name,
                        'name': '%s' % name,
                        'status': '%s' % status
                    },
                    'children': [
                        {
                            'infraContNS': {
                                'attributes': {
                                    'rn': 'nscont',
                                    'status': '%s' % status
                                }
                            }
                        },
                        {
                            'infraContDomP': {
                                'attributes': {
                                    'rn': 'dompcont',
                                    'status': '%s' % status
                                }
                            }
                        },
                        {
                            'infraProvAcc': {
                                'attributes': {
                                    'name': 'default',
                                    'rn': 'provacc',
                                    'status': '%s' % infra
                                },
                                'children': [
                                    {
                                        'dhcpInfraProvP': {
                                            'attributes': {
                                                'mode': 'controller',
                                                'rn': 'infraprovp',
                                                'status': '%s' % infra
                                            }
                                        }
                                    },
                                    {
                                        'infraRsFuncToEpg': {
                                            'attributes': {
                                                'encap': 'vlan-%s' % infra_vlan,
                                                'rn': 'rsfuncToEpg-[uni/tn-infra/ap-access/epg-default]',
                                                'status': '%s' % infra
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            'infraAttPolicyGroup': {
                                'attributes': {
                                    'rn': 'attpolgrp',
                                    'status': '%s' % override
                                },
                                'children': [
                                    {
                                        'infraRsOverrideCdpIfPol': {
                                            'attributes': {
                                                'rn': 'rsoverrideCdpIfPol',
                                                'status': '%s' % override,
                                                'tnCdpIfPolName': '%s' % override_cdp
                                            }
                                        }
                                    },
                                    {
                                        'infraRsOverrideLacpPol': {
                                            'attributes': {
                                                'rn': 'rsoverrideLacpPol',
                                                'status': '%s' % override,
                                                'tnLacpLagPolName': '%s' % override_pc
                                            }
                                        }
                                    },
                                    {
                                        'infraRsOverrideLldpIfPol': {
                                            'attributes': {
                                                'rn': 'rsoverrideLldpIfPol',
                                                'status': '%s' % override,
                                                'tnLldpIfPolName': '%s' % override_lldp
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        else:
            payload = {
                'infraAttEntityP': {
                    'attributes': {
                        'dn': 'uni/infra/attentp-%s' % name,
                        'name': '%s' % name,
                        'status': '%s' % status
                    },
                    'children': [
                        {
                            'infraContNS': {
                                'attributes': {
                                    'rn': 'nscont',
                                    'status': '%s' % status
                                }
                            }
                        },
                        {
                            'infraContDomP': {
                                'attributes': {
                                    'rn': 'dompcont',
                                    'status': '%s' % status
                                }
                            }
                        },
                        {
                            'infraProvAcc': {
                                'attributes': {
                                    'name': 'default',
                                    'rn': 'provacc',
                                    'status': '%s' % infra
                                },
                                'children': [
                                    {
                                        'dhcpInfraProvP': {
                                            'attributes': {
                                                'mode': 'controller',
                                                'rn': 'infraprovp',
                                                'status': '%s' % infra
                                            }
                                        }
                                    },
                                    {
                                        'infraRsFuncToEpg': {
                                            'attributes': {
                                                'encap': 'vlan-%s' % infra_vlan,
                                                'rn': 'rsfuncToEpg-[uni/tn-infra/ap-access/epg-default]',
                                                'status': '%s' % infra
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                    ]
                }
            }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/attentp-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("AEP Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the L3-Out Domain
    # status: created | created,modified | deleted
    # vlan_pool: Name of the VLAN pool to associate to the L3 Out
    def l3_dom(self, name, status, vlan_pool):
        payload = {
            'l3extDomP': {
                'attributes': {
                    'dn': 'uni/l3dom-%s' % name,
                    'name': '%s' % name,
                    'status': '%s' % status
                },
                'children': [
                    {
                        'infraRsVlanNs': {
                            'attributes': {
                                'rn': 'rsvlanNs',
                                'status': '%s' % status,
                                'tDn': 'uni/infra/vlanns-[%s]-dynamic' % vlan_pool
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/l3dom-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Domain Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the Physical Domain
    # status: created | created,modified | deleted
    # vlan_pool: Name of the VLAN pool to associate to the Physical Domain
    def phys_dom(self, name, status, vlan_pool):
        payload = {
            'physDomP': {
                'attributes': {
                    'dn': 'uni/phys-%s' % name,
                    'name': '%s' % name,
                    'status': '%s' % status
                },
                'children': [
                    {
                        'infraRsVlanNs': {
                            'attributes': {
                                'rn': 'rsvlanNs',
                                'status': '%s' % status,
                                'tDn': 'uni/infra/vlanns-[%s]-dynamic' % vlan_pool
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/phys-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Physical Domain Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the AEP
    # status: created | created,modified | deleted
    # l3_dom: Name of the L3 Domain to be hooked to the AEP
    def l3_aep(self, name, status, l3_dom):
        payload = {
            'infraAttEntityP': {
                'attributes': {
                    'dn': 'uni/infra/attentp-%s' % name,
                    'name': '%s' % name,
                    'status': 'created,modified'
                },
                'children': [
                    {
                        'infraRsDomP': {
                            'attributes': {
                                'rn': 'rsdomP-[uni/l3dom-%s]' % l3_dom,
                                'status': '%s' % status,
                                'tDn': 'uni/l3dom-%s' % l3_dom
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/attentp-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Domain to AEP Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the AEP
    # status: created | created,modified | deleted
    # l3_dom: Name of the L3 Domain to be hooked to the AEP
    def phys_aep(self, name, dom_name, status):
        payload = {
            'infraAttEntityP': {
                'attributes': {
                    'dn': 'uni/infra/attentp-%s' % name,
                    'name': '%s' % name,
                    'status': 'created,modified'
                },
                'children': [
                    {
                        'infraRsDomP': {
                            'attributes': {
                                'rn': 'rsdomP-[uni/phys-%s]' % dom_name,
                                'status': '%s' % status,
                                'tDn': 'uni/phys-%s' % dom_name
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/attentp-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Physical Domain to AEP Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the vPC
    # id: vPC ID as an integer
    # status: created | created,modified | deleted
    # sw1: Node 1 in integer (i.e. 101)
    # sw2: Node 2 in integer (i.e. 102)
    def vpc(self, name, id, status, sw1, sw2):
        try:
            id = int(id)
            sw1 = int(sw1)
            sw2 = int(sw2)
        except:
            status = 667
            return status
        payload = {
            'fabricExplicitGEp': {
                'attributes': {
                    'dn': 'uni/fabric/protpol/expgep-%s' % name,
                    'name': '%s' % name,
                    'id': '%s' % id,
                    'rn': 'expgep-%s' % name,
                    'status': '%s' % status
                },
                'children': [
                    {
                        'fabricNodePEp': {
                            'attributes': {
                                'dn': 'uni/fabric/protpol/expgep-%s/nodepep-%s' % (name, sw1),
                                'id': '%s' % sw1,
                                'status': '%s' % status,
                                'rn': 'nodepep-%s' % sw1
                            },
                        }
                    },
                    {
                        'fabricNodePEp': {
                            'attributes': {
                                'dn': 'uni/fabric/protpol/expgep-%s/nodepep-%s' % (name, sw2),
                                'id': '%s' % sw2,
                                'status': '%s' % status,
                                'rn': 'nodepep-%s' % sw2
                            },
                        }
                    },
                    {
                        'fabricRsVpcInstPol': {
                            'attributes': {
                                'tnVpcInstPolName': 'default',
                                'status': '%s' % status
                            },
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/fabric/protpol/expgep-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("vPC Policy Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # This method creates a switch profile for a pair of switches (vPC)
    # name: Name of the Switch Profile
    # status: created | created,modified | deleted
    # sw1: Node 1 in integer (i.e. 101)
    # sw2: Node 2 in integer (i.e. 102)
    def sw_pro_vpc(self, name, status, sw1, sw2):
        try:
            sw1 = int(sw1)
            sw2 = int(sw2)
        except:
            status = 667
            return status
        payload = {
            'infraNodeP': {
                'attributes': {
                    'dn': 'uni/infra/nprof-%s' % name,
                    'name': '%s' % name,
                    'rn': 'nprof-%s' % name,
                    'status': '%s' % status
                },
                'children': [
                    {
                        'infraLeafS': {
                            'attributes': {
                                'dn': 'uni/infra/nprof-%s/leaves-%s-typ-range' % (name, name),
                                'type': 'range',
                                'name': '%s' % name,
                                'rn': 'leaves-%s-typ-range' % name,
                                'status': '%s' % status
                            },
                            'children': [
                                {
                                    'infraNodeBlk': {
                                        'attributes': {
                                            'dn': 'uni/infra/nprof-%s/leaves-%s-typ-range/nodeblk-L%s' % (name, name, sw1),
                                            'from_': '%s' % sw1,
                                            'to_': '%s' % sw1,
                                            'name': 'L%s' % sw1,
                                            'rn': 'nodeblk-L%s' % sw1,
                                            'status': '%s' % status
                                        },
                                    }
                                },
                                {
                                    'infraNodeBlk': {
                                        'attributes': {
                                            'dn': 'uni/infra/nprof-%s/leaves-%s-typ-range/nodeblk-L%s'  % (name, name, sw2),
                                            'from_': '%s' % sw2,
                                            'to_': '%s' % sw2,
                                            'name': 'L%s' % sw2,
                                            'rn': 'nodeblk-L%s' % sw2,
                                            'status': '%s' % status
                                        },
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/nprof-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Switch Profile (vPC) Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # This method creates a switch profile for a signle switch
    # name: Name of the Switch Profile
    # status: created | created,modified | deleted
    # sw1: Node 1 in integer (i.e. 101)
    def sw_pro_single(self, name, status, sw1):
        try:
            sw1 = int(sw1)
        except:
            status = 667
            return status
        payload = {
            'infraNodeP': {
                'attributes': {
                    'dn': 'uni/infra/nprof-%s' % name,
                    'name': '%s' % name,
                    'rn': 'nprof-%s' % name,
                    'status': '%s' % status
                },
                'children': [
                    {
                        'infraLeafS': {
                            'attributes': {
                                'dn': 'uni/infra/nprof-%s/leaves-%s-typ-range' % (name, name),
                                'type': 'range',
                                'name': '%s' % name,
                                'rn': 'leaves-%s-typ-range' % name,
                                'status': '%s' % status
                            },
                            'children': [
                                {
                                    'infraNodeBlk': {
                                        'attributes': {
                                            'dn': 'uni/infra/nprof-%s/leaves-%s-typ-range/nodeblk-L%s' % (name, name, sw1),
                                            'from_': '%s' % sw1, 'to_': '%s' % sw1,
                                            'name': 'L%s' % sw1,'rn': 'nodeblk-L%s' % sw1,
                                            'status': '%s' % status
                                        },
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/nprof-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Switch Profile (single switch) Failed to deploy. "
                  "Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
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
    def int_pol_grp_vpc(self, name, status, lag_type, lldp, cdp, aep, mcp,
                        lag, link, ppv='', storm=''):
        '''
        Special Note - L2 and Storm Control policies are optional, var_qty
        represents first 9 required vars, and ignores the optional values
        '''
        payload = {
            'infraAccBndlGrp': {
                'attributes': {
                    'dn': 'uni/infra/funcprof/accbundle-%s' % name,
                    'lagT': '%s' % lag_type,
                    'name': '%s' % name,
                    'rn': 'accbundle-%s' % name,
                    'status': '%s' % status
                },
                'children': [
                    {
                        'infraRsMonIfInfraPol': {
                            'attributes': {
                                'tnMonInfraPolName': ''
                            }
                        }
                    },
                    {
                        'infraRsLldpIfPol': {
                            'attributes': {
                                'tnLldpIfPolName': '%s' % lldp
                            }
                        }
                    },
                    {
                        'infraRsStpIfPol': {
                            'attributes': {
                                'tnStpIfPolName': ''
                            }
                        }
                    },
                    {
                        'infraRsCdpIfPol': {
                            'attributes': {
                                'tnCdpIfPolName': '%s' % cdp
                            }
                        }
                    },
                    {
                        'infraRsAttEntP': {
                            'attributes': {
                                'tDn': 'uni/infra/attentp-%s' % aep
                            }
                        }
                    },
                    {
                        'infraRsMcpIfPol': {
                            'attributes': {
                                'tnMcpIfPolName': '%s' % mcp
                            }
                        }
                    },
                    {
                        'infraRsStormctrlIfPol': {
                            'attributes': {
                                'tnStormctrlIfPolName': '%s' % storm
                            }
                        }
                    },
                    {
                        'infraRsL2IfPol': {
                            'attributes': {
                                'tnL2IfPolName': '%s' % ppv,
                            }
                        }
                    },
                    {
                        'infraRsLacpPol': {
                            'attributes': {
                                'tnLacpLagPolName': '%s' % lag
                            }
                        }
                    },
                    {
                        'infraRsHIfPol': {
                            'attributes': {
                                'tnFabricHIfPolName': '%s' % link
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/funcprof/accbundle-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Interface Policy Group (vPC) Failed to deploy. "
                  "Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the Interface Policy Group
    # status: created | created,modified | deleted
    # lldp: Name of LLDP Policy
    # cdp: Name of CDP Policy
    # aep: Name of AEP
    # mcp: Name of MCP Policy
    # link: Name of Link Policy
    def int_pol_grp_access(self, name, status, lldp, cdp, aep, mcp, link,
                           ppv='', storm=''):
        '''
        Special Note - L2 and Storm Control policies are optional, var_qty
        represents first 9 required vars, and ignores the optional values
        '''
        payload = {
            'infraAccPortGrp': {
                'attributes': {
                    'dn': 'uni/infra/funcprof/accportgrp-%s' % name,
                    'name': '%s' % name,
                    'rn': 'accportgrp-%s' % name,
                    'status': '%s' % status
                },
                'children': [
                    {
                        'infraRsMonIfInfraPol': {
                            'attributes': {
                                'tnMonInfraPolName': ''
                            }
                        }
                    },
                    {
                        'infraRsLldpIfPol': {
                            'attributes': {
                                'tnLldpIfPolName': '%s' % lldp
                            }
                        }
                    },
                    {
                        'infraRsStpIfPol': {
                            'attributes': {
                                'tnStpIfPolName': ''
                            }
                        }
                    },
                    {
                        'infraRsCdpIfPol': {
                            'attributes': {
                                'tnCdpIfPolName': '%s' % cdp
                            }
                        }
                    },
                    {
                        'infraRsAttEntP': {
                            'attributes': {
                                'tDn': 'uni/infra/attentp-%s' % aep
                            }
                        }
                    },
                    {
                        'infraRsMcpIfPol': {
                            'attributes': {
                                'tnMcpIfPolName': '%s' % mcp
                            }
                        }
                    },
                    {
                        'infraRsL2IfPol': {
                            'attributes': {
                                'tnL2IfPolName': '%s' % ppv,
                            }
                        }
                    },
                    {
                        'infraRsStormctrlIfPol': {
                            'attributes': {
                                'tnStormctrlIfPolName': '%s' % storm
                            }
                        }
                    },
                    {
                        'infraRsHIfPol': {
                            'attributes': {
                                'tnFabricHIfPolName': '%s' % link
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/funcprof/accportgrp-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Interface Policy Group (Access) Failed to deploy. "
                  "Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the Interface Profile
    # status: created | created,modified | deleted
    def int_profile(self, name, status):
        payload = {
            "infraAccPortP": {
                "attributes": {
                    "dn": "uni/infra/accportprof-%s" % name,
                    "name": "%s" % name,
                    "status": "%s" % status
                }
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/accportprof-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Interface Profile Failed to deploy. "
                  "Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
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
    def int_selector(self, name, status, port_name, port_type, pol_group,
                     mod_start, mod_end, port_start, port_end):
        try:
            mod_start = int(mod_start)
            mod_end = int(mod_end)
            port_start = int(port_start)
            port_end = int(port_end)
        except:
            status = 667
            return status
        payload = {
            "infraHPortS": {
                "attributes": {
                    "name": "%s" % port_name,
                    "rn": "hports-%s-typ-range" % port_name,
                    "status": "%s" % status,
                    "type": "range"
                },
                "children": [
                    {
                        "infraRsAccBaseGrp": {
                            "attributes": {
                                "fexId": "101",
                                "rn": "rsaccBaseGrp",
                                "tDn": "uni/infra/funcprof/%s-%s" % (port_type, pol_group),
                                "status": "created,modified"
                            }
                        }
                    },
                    {
                        "infraPortBlk": {
                            "attributes": {
                                "fromCard": "%s" % mod_start,
                                "toCard": "%s" % mod_end,
                                "fromPort": "%s" % port_start,
                                "toPort": "%s" % port_end,
                                "name": "block2",
                                "rn": "portblk-block2",
                                "status": "created,modified"
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/accportprof-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Interface Selector Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the Switch Profile
    # status: created | created,modified | deleted
    # int_profile: Name of the Interface Profile to hook to Switch Selector
    def int_selector_sw_profile(self, name, status, int_profile):
        payload = {
            "infraNodeP": {
                "attributes": {
                    "dn": "uni/infra/nprof-%s" % name,
                    "name": "%s" % name
                },
                "children": [
                    {
                        "infraLeafS": {
                            "attributes": {
                                "name": "%s" % name,
                                "type": "range"
                            },
                        }
                    },
                    {
                        "infraRsAccPortP": {
                            "attributes": {
                                "tDn": "uni/infra/accportprof-%s" % int_profile,
                                "status": "%s" % status
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/infra/nprof-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Switch Profile Failed to deploy. Exception: %s" % e)
            status = 666
        return status


# Class must be instantiated with APIC IP address and cookies
class FabTnPol(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies

    # Method must be called with the following data.
    # name: The name of the Tenant
    # status: created | created,modified | deleted
    def tenant(self, name, status):
        payload = {
            'fvTenant': {
                'attributes': {
                    'dn': 'uni/tn-%s' % name,
                    'name': '%s' % name,
                    'status': '%s' % status
                }
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s.json'
                       % (self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Tenant Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # name: Name of the VRF
    # enforce: enforced | unenforced
    # status: created | created,modified | deleted
    def vrf(self, tn_name, name, enforce, status):
        payload = {
            'fvCtx': {
                'attributes': {
                    'dn': 'uni/tn-%s/ctx-%s' % (tn_name, name),
                    'knwMcastAct': 'permit',
                    'name': '%s' % name,
                    'pcEnfPref': '%s' % enforce,
                    'status': '%s' % status
                },
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/ctx-%s.json'
                       % (self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("VRF Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # name: Name of the BD
    # arp: yes | no
    # mdest: bd-flood | drop | encap-flood
    # mcast: flood | opt-flood
    # unicast: yes | no
    # unk_unicast: proxy | flood
    # vrf: Name of associated VRF
    # l3-out: Name of associated L3-Out
    # subnet: Subnet in CIDR: ex: 1.1.1.1/24
    # scope: public | private | shared | public,shared | private,shared
    # status: created | created,modified | deleted
    def bd(self, tn_name, name, arp, mdest, mcast, unicast, unk_unicast, vrf,
           l3_out, subnet, scope, status):
        payload = {
            'fvBD': {
                'attributes': {
                    'arpFlood': '%s' % arp,
                    'dn': 'uni/tn-%s/BD-%s' % (tn_name, name),
                    'epMoveDetectMode': '',
                    'limitIpLearnToSubnets': 'no',
                    'llAddr': '::',
                    'mac': '00:22:BD:F8:19:FF',
                    'multiDstPktAct': '%s' % mdest,
                    'name': '%s' % name,
                    'status': '%s' % status,
                    'unicastRoute': '%s' % unicast,
                    'unkMacUcastAct': '%s' % unk_unicast,
                    'unkMcastAct': '%s' % mcast
                },
                'children': [
                    {
                        'fvRsBDToOut': {
                            'attributes': {
                                'rn': 'rsBDToOut-%s' % l3_out,
                                'status': 'created,modified',
                                'tnL3extOutName': '%s' % l3_out
                            }
                        }
                    },
                    {
                        'fvRsCtx': {
                            'attributes': {
                                'rn': 'rsctx',
                                'status': 'crated,modified',
                                'tnFvCtxName': '%s' % vrf
                            }
                        }
                    },
                    {
                        'fvSubnet': {
                            'attributes': {
                                'ctrl': '',
                                'ip': '%s' % subnet,
                                'name': '',
                                'preferred': 'yes',
                                'rn': 'subnet-[%s]' % subnet,
                                'scope': '%s' % scope,
                                'status': 'created,modified'
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/BD-%s.json'
                       % (self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("BD Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
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
    def filter(self, tn_name, name, dst_start, dst_end, src_start, src_end,
               ethertype, protocol, status):
        if dst_start and dst_end == 'unspecified':
            pass
        else:
            try:
                dst_start = int(dst_start)
            except:
                print("Filter dest port (start) not 'unspecified' or valid "
                      "integer. Changing filter source to '53'. "
                      "Please update workbook.")
                dst_start = 53
            try:
                dst_end = int(dst_end)
            except:
                print("Filter dest port (end) not 'unspecified' or valid "
                      "integer. Changing filter source to '53'. "
                      "Please update workbook.")
                dst_end = 53
        if src_start and src_end == 'unspecified':
            pass
        else:
            try:
                src_start = int(src_start)
            except:
                print("Filter source port (start) not 'unspecified' or valid "
                      "integer. Changing filter source to '53'. "
                      "Please update workbook.")
                src_start = 53
            try:
                src_end = int(src_end)
            except:
                print("Filter source port (end) not 'unspecified' or valid "
                      "integer. Changing filter source to '53'. "
                      "Please update workbook.")
                src_end = 53
        payload = {
            'vzFilter': {
                'attributes': {
                    'dn': 'uni/tn-%s/flt-%s' % (tn_name, name),
                    'name': '%s' % name,
                    'status': '%s' % status
                },
                'children': [
                    {
                        'vzEntry': {
                            'attributes': {
                                'applyToFrag': 'no',
                                'arpOpc': 'unspecified',
                                'dFromPort': '%s' % dst_start,
                                'dToPort': '%s' % dst_end,
                                'etherT': '%s' % ethertype,
                                'icmpv4T': 'unspecified',
                                'icmpv6T': 'unspecified',
                                'name': '%s' % name,
                                'prot': '%s' % protocol,
                                'rn': 'e-%s' % name,
                                'sFromPort': '%s' % src_start,
                                'sToPort': '%s' % src_end,
                                'stateful': 'no',
                                'status': '%s' % status,
                                'tcpRules': ''
                            }
                        }
                    },
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/flt-%s.json'
                       % (self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Filter Policy Failed to deploy. "
                  "Check your payload and URL.")
        except Exception, e:
            print("Filter Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # name: Name of the Contract
    # scope: context | global | tenant | application-profile
    # subject: Name of the Subject
    # filter: Name of the Filter being referenced
    # reverse_filter: yes | no
    # status: created | created,modified | deleted
    def contract(self, tn_name, name, scope, subject, filter, reverse_filter,
                 status):
        payload = {
            "vzBrCP": {
                "attributes": {
                    "dn": "uni/tn-%s/brc-%s" % (tn_name, name),
                    "name": "%s" % name,
                    "prio": "unspecified",
                    "scope": "%s" % scope,
                    "status": "%s" % status
                },
                "children": [
                    {
                        "vzSubj": {
                            "attributes": {
                                "consMatchT": "AtleastOne",
                                "name": "%s" % subject,
                                "prio": "unspecified",
                                "provMatchT": "AtleastOne",
                                "revFltPorts": "%s" % reverse_filter,
                                "rn": "subj-%s" % subject,
                                "status": "%s" % status
                            },
                            "children": [
                                {
                                    "vzRsSubjFiltAtt": {
                                        "attributes": {
                                            "rn": "rssubjFiltAtt-%s" % filter,
                                            "status": "%s" % status,
                                            "tnVzFilterName": "%s" % filter
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/brc-%s.json'
                       % (self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Contract Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # name: Name of the Application Profile
    # status: created | created,modified | deleted
    def app_profile(self, tn_name, name, status):
        payload = {
            "fvAp": {
                "attributes": {
                    "dn": "uni/tn-%s/ap-%s" % (tn_name, name),
                    "name": "%s" % name,
                    "status": "%s" % status
                }
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/ap-%s.json'
                       % (self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("App Profile failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # name: Name of the EPG
    # bd: Name of associated BD
    # status: created | created,modified | deleted
    def epg(self, tn_name, ap_name, name, bd, status):
        payload = {
            "fvAEPg": {
                "attributes": {
                    "dn": "uni/tn-%s/ap-%s/epg-%s" % (tn_name, ap_name, name),
                    "name": "%s" % name,
                    "rn": "epg-%s" % name,
                    "status": "%s" % status
                },
                "children": [
                    {
                        "fvRsBd": {
                            "attributes": {
                                "tnFvBDName": "%s" % bd,
                                "status": "%s" % status
                            },
                        }
                    },
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/ap-%s/epg-%s.json'
                       % (self.apic, tn_name, ap_name, name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("EPG failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # phys_dom: Name of the Physical Domain
    # deploy: lazy | immediate
    # resolve: lazy | immediate | on-demand
    # status: created | created,modified | deleted
    def epg_phys_dom(self, tn_name, ap_name, epg_name, phys_dom, deploy,
                     resolve, status):
        payload = {
            "fvRsDomAtt": {
                "attributes": {
                    "childAction": "",
                    "dn": "uni/tn-%s/ap-%s/epg-%s/rsdomAtt-[uni/phys-%s]" % (tn_name, ap_name, epg_name, phys_dom),
                    "instrImedcy": "%s" % deploy,
                    "resImedcy": "%s" % resolve,
                    "status": "%s" % status
                }
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/ap-%s/epg-%s/rsdomAtt-[uni/phys-%s].json'
                       % (self.apic, tn_name, ap_name, epg_name, phys_dom),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("EPG to Phys Dom failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # vmm_dom: Name of the VMM Domain
    # deploy: lazy | immediate
    # resolve: lazy | immediate | on-demand
    # status: created | created,modified | deleted
    def epg_vmm_dom(self, tn_name, ap_name, epg_name, vmm_dom, deploy,
                    resolve, status):
        payload = {
            "fvRsDomAtt": {
                "attributes": {
                    "childAction": "",
                    "dn": "uni/tn-%s/ap-%s/epg-%s/rsdomAtt-[uni/vmmp-VMware/dom-%s]" % (tn_name, ap_name, epg_name, vmm_dom),
                    "instrImedcy": "%s" % deploy,
                    "resImedcy": "%s" % resolve,
                    "status": "%s" % status
                },
                "children": [
                    {
                        "vmmSecP": {
                            "attributes": {
                                "allowPromiscuous": "reject",
                                "forgedTransmits": "reject",
                                "macChanges": "reject",
                                "rn": "sec",
                                "status": "created,modified"
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/ap-%s/epg-%s/rsdomAtt-[uni/phys-%s].json'
                       % (self.apic, tn_name, ap_name, epg_name, vmm_dom),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("EPG to VMM Dom failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # contract: Name of the Contract
    # status: created | created,modified | deleted
    def provide_contract(self, tn_name, ap_name, epg_name, contract, status):
        payload = {
            "fvRsProv": {
                "attributes": {
                    "childAction": "",
                    "dn": "uni/tn-%s/ap-%s/epg-%s/rsprov-%s" % (tn_name, ap_name, epg_name, contract),
                    "prio": "unspecified",
                    "status": "%s" % status,
                    "tnVzBrCPName": "%s" % contract
                }
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/ap-%s/epg-%s/rsprov-%s.json'
                       % (self.apic, tn_name, ap_name, epg_name, contract), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("Provide Contract failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # contract: Name of the Contract
    # status: created | created,modified | deleted
    def consume_contract(self, tn_name, ap_name, epg_name, contract, status):
        payload = {
            "fvRsCons": {
                "attributes": {
                    "childAction": "",
                    "dn": "uni/tn-%s/ap-%s/epg-%s/rsprov-%s" % (tn_name, ap_name, epg_name, contract),
                    "prio": "unspecified",
                    "status": "%s" % status,
                    "tnVzBrCPName": "%s" % contract
                }
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/ap-%s/epg-%s/rscons-%s.json'
                       % (self.apic, tn_name, ap_name, epg_name, contract),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("Consume Contract failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # sw1: Switch 1 of the vPC (node ID) as an integer
    # sw2: Switch 2 of the vPC (node ID) as an integer
    # vpc: Name of the vPC
    # encap: Encapsulation VLAN ID as an integer
    # deploy: lazy | immediate
    # status: created | created,modified | deleted
    def static_path_vpc(self, tn_name, ap_name, epg_name, sw1, sw2, vpc, encap,
                        deploy, status):
        try:
            sw1 = int(sw1)
            sw2 = int(sw2)
            encap = int(encap)
        except:
            status = 667
            return status
        payload = {
            "fvAEPg": {
                "attributes": {
                    "dn": "uni/tn-%s/ap-%s/epg-%s" % (tn_name, ap_name, epg_name),
                    "name": "%s" % epg_name,
                    "rn": "epg-%s" % epg_name,
                    "status": "created,modified"
                },
                "children": [
                    {
                        "fvRsPathAtt": {
                            "attributes": {
                                "tDn": "topology/pod-1/protpaths-%s-%s/pathep-[%s]" % (sw1, sw2, vpc),
                                "encap": "vlan-%s" % encap,
                                "instrImedcy": "%s" % deploy,
                                "status": "%s" % status
                            },
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/ap-%s/epg-%s.json'
                       % (self.apic, tn_name, ap_name, epg_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("Static path binding (vPC) failed to deploy. Exception: %s"
                  % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # sw1: Switch 1 of the vPC (node ID) as an integer
    # port: Port ID as an integer (i.e. 1 or 2)
    # encap: Encapsulation VLAN ID as an integer
    # deploy: lazy | immediate
    # status: created | created,modified | deleted
    def static_path_access(self, tn_name, ap_name, epg_name, sw1, port, encap,
                           deploy, status):
        try:
            sw1 = int(sw1)
            encap = int(encap)
        except:
            status = 667
            return status
        payload = {
            "fvAEPg": {
                "attributes": {
                    "dn": "uni/tn-%s/ap-%s/epg-%s" % (tn_name, ap_name, epg_name),
                    "name": "%s" % epg_name,
                    "rn": "epg-%s" % epg_name,
                    "status": "created,modified"
                },
                "children": [
                    {
                        "fvRsPathAtt": {
                            "attributes": {
                                "dn": "uni/tn-%s/ap-%s/epg-%s/rspathAtt-[topology/pod-1/paths-%s/pathep-[eth1/%s]]" % (tn_name, ap_name, epg_name, sw1, port),
                                "encap": "vlan-%s" % encap,
                                "instrImedcy": "%s" % deploy,
                                "status": "%s" % status
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/ap-%s/epg-%s.json'
                       % (self.apic, tn_name, ap_name, epg_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("Static path binding (access) failed to deploy. Exception: "
                  "%s" % e)
            status = 666
        return status


# Class must be instantiated with APIC IP address and cookies
class FabL3Pol(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # domain: Name of the External L3 Domain
    # vrf: Name of associated VRF
    # status: created | created,modified | deleted
    def l3_out(self, tn_name, name, domain, vrf, status):
        payload = {
            "l3extOut": {
                "attributes": {
                    "enforceRtctrl": "export",
                    "name": "%s" % name,
                    "status": "%s" % status,
                    "targetDscp": "unspecified"
                },
                "children": [
                    {
                        "l3extRsEctx": {
                            "attributes": {
                                "rn": "rsectx",
                                "status": "%s" % status,
                                "tnFvCtxName": "%s" % vrf
                            }
                        }
                    },
                    {
                        "l3extRsL3DomAtt": {
                            "attributes": {
                                "rn": "rsl3DomAtt",
                                "status": "%s" % status,
                                "tDn": "uni/l3dom-%s" % domain
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/out-%s.json'
                       % (self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (initial setup) Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # area: backbone | area id as an integer | area id as dotted decimal
    # area_type: regular | nssa
    # vrf: Name of associated VRF
    # status: created | created,modified | deleted
    def ospf(self, tn_name, name, area, area_type, status):
        payload = {
            "l3extOut": {
                "attributes": {
                    "dn": "uni/tn-%s/out-%s" % (tn_name, name),
                    "enforceRtctrl": "export",
                    "name": "%s" % name,
                    "status": "created,modified"
                },
                "children": [
                    {
                        "ospfExtP": {
                            "attributes": {
                                "areaCost": "1",
                                "areaCtrl": "redistribute,summary",
                                "areaId": "%s" % area,
                                "areaType": "%s" % area_type,
                                "rn": "ospfExtP",
                                "status": "%s" % status
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/out-%s.json'
                       % (self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (OSPF) Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # status: created | created,modified | deleted (of the BGP process)
    def bgp(self, tn_name, name, status):
        payload = {
            "l3extOut": {
                "attributes": {
                    "dn": "uni/tn-%s/out-%s" % (tn_name, name),
                    "enforceRtctrl": "export",
                    "name": "%s" % name,
                    "status": "created,modified"
                },
                "children": [
                    {
                        "bgpExtP": {
                            "attributes": {
                                "rn": "bgpExtP",
                                "status": "%s" % status
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/out-%s.json'
                       % (self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (BGP) Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # node_name: Name of the Node Profile
    # sw1: Node ID of first switch as an integer
    # sw2: Node ID of second switch as an integer
    # sw1_loop: IP of node1 loopback as a dotted decimal (no mask)
    # sw2: Node ID of first switch as an integer
    # loopback: yes | no
    # status: created | created,modified | deleted
    def node_profile(self, tn_name, name, node_name, sw1, sw2, sw1_loop,
                     sw2_loop, loopback, status):
        try:
            sw1 = int(sw1)
            sw2 = int(sw2)
        except:
            status = 667
            return status
        payload = {
            "l3extLNodeP": {
                "attributes": {
                    "dn": "uni/tn-%s/out-%s/lnodep-%s" % (tn_name, name, node_name),
                    "name": "%s" % node_name,
                    "status": "%s" % status,
                    "tag": "yellow-green",
                    "targetDscp": "unspecified"
                },
                "children": [
                    {
                        "l3extRsNodeL3OutAtt": {
                            "attributes": {
                                "rn": "rsnodeL3OutAtt-[topology/pod-1/node-%s]" % sw1,
                                "rtrId": "%s" % sw1_loop,
                                "rtrIdLoopBack": "%s" % loopback,
                                "status": "created,modified"
                            },
                            "children": [
                                {
                                    "l3extLoopBackIfP": {
                                        "attributes": {
                                            "addr": "%s" % sw1_loop,
                                            "rn": "lbp-[%s]" % sw1_loop,
                                            "status": "created,modified"
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    {
                        "l3extRsNodeL3OutAtt": {
                            "attributes": {
                                "rn": "rsnodeL3OutAtt-[topology/pod-1/node-%s]" % sw2,
                                "rtrId": "%s" % sw2_loop,
                                "rtrIdLoopBack": "%s" % loopback,
                                "status": "created,modified"
                            },
                            "children": [
                                {
                                    "l3extLoopBackIfP": {
                                        "attributes": {
                                            "addr": "%s" % sw2_loop,
                                            "rn": "lbp-[%s]" % sw2_loop,
                                            "status": "created,modified"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/out-%s.json'
                       % (self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (Node Profile) Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # node_name: Name of the Node Profile
    # sw: Node ID of the switch as an integer
    # prefix: Prefix in CIDR format (i.e. 0.0.0.0/0)
    # next_hop: IP of the next hop in dotted decimal format (i.e. 1.1.1.1)
    # status: created | created,modified | deleted
    def static_routes(self, tn_name, name, node_name, sw, prefix, next_hop,
                      status):
        try:
            sw = int(sw)
        except:
            status = 667
            return status
        payload = {
            "l3extRsNodeL3OutAtt": {
                "attributes": {
                    "dn": "uni/tn-%s/out-%s/lnodep-%s/rsnodeL3OutAtt-[topology/pod-1/node-%s]" % (tn_name, name, node_name, sw),
                    "status": "created,modified"
                },
                "children": [
                    {
                        "ipRouteP": {
                            "attributes": {
                                "aggregate": "no",
                                "ip": "%s" % prefix,
                                "pref": "1",
                                "rn": "rt-[%s]" % prefix,
                                "status": "%s" % status
                            },
                            "children": [
                                {
                                    "ipNexthopP": {
                                        "attributes": {
                                            "nhAddr": "%s" % next_hop,
                                            "rn": "nh-[%s]" % next_hop,
                                            "status": "%s" % status
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/out-%s.json'
                       % (self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (Static Route) Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # node_name: Name of the Node Profile
    # int_profile: Name of the Interface Profile
    # sw: Node ID of the switch as an integer
    # port: Port number as an integer
    # ip: IP of the interface in dotted decimal format (i.e. 1.1.1.1)
    # int_profile_status created | created,modified | deleted of the Int Pro
    # status: created | created,modified | deleted of the Interface itself
    def routed_ints(self, tn_name, name, node_name, int_profile, sw, port,
                    ip, int_profile_status, status):
        try:
            sw = int(sw)
            port = int(port)
        except:
            status = 667
            return status
        payload = {
            "l3extLIfP": {
                "attributes": {
                    "dn": "uni/tn-%s/out-%s/lnodep-%s/lifp-%s" % (tn_name, name, node_name, int_profile),
                    "name": "%s" % int_profile,
                    "status": "%s" % int_profile_status
                },
                "children": [
                    {
                        "l3extRsNdIfPol": {
                            "attributes": {
                                "status": "created,modified"
                            }
                        }
                    },
                    {
                        "l3extRsPathL3OutAtt": {
                            "attributes": {
                                "addr": "%s" % ip,
                                "encap": "unknown",
                                "ifInstT": "l3-port",
                                "llAddr": "::",
                                "mac": "00:22:BD:F8:19:FF",
                                "mode": "regular",
                                "mtu": "inherit",
                                "rn": "rspathL3OutAtt-[topology/pod-1/paths-%s/pathep-[eth1/%s]]" % (sw, port),
                                "status": "%s" % status,
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/out-%s/lnodep-%s/lifp-%s.json'
                       % (self.apic, tn_name, name, node_name, int_profile),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (Routed Ints) Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # node_name: Name of the Node Profile
    # int_profile: Name of the Interface Profile
    # sw: Node ID of the switch as an integer
    # port: Port number as an integer
    # vlan: VLAN ID as an integer
    # ip: IP of the interface in dotted decimal format (i.e. 1.1.1.1)
    # int_profile_status created | created,modified | deleted of the Interface Profile
    # status: created | created,modified | deleted of the Interface itself
    def routed_sub_ints(self, tn_name, name, node_name, int_profile, sw,
                        port, vlan, ip, int_profile_status, status):
        try:
            sw = int(sw)
            port = int(port)
            vlan = int(vlan)
        except:
            status = 667
            return status
        payload = {
            "l3extLIfP": {
                "attributes": {
                    "dn": "uni/tn-%s/out-%s/lnodep-%s/lifp-%s" % (tn_name, name, node_name, int_profile),
                    "name": "%s" % int_profile,
                    "status": "%s" % int_profile_status
                },
                "children": [
                    {
                        "l3extRsNdIfPol": {
                            "attributes": {
                            "status": "created,modified"
                            }
                        }
                    },
                    {
                        "l3extRsPathL3OutAtt": {
                            "attributes": {
                                "addr": "%s" % ip,
                                "encap": "vlan-%s" % vlan,
                                "ifInstT": "sub-interface",
                                "llAddr": "::",
                                "mac": "00:22:BD:F8:19:FF",
                                "mode": "regular",
                                "mtu": "inherit",
                                "rn": "rspathL3OutAtt-[topology/pod-1/paths-%s/pathep-[eth1/%s]]" % (sw, port),
                                "status": "%s" % status,
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/out-%s/lnodep-%s/lifp-%s.json'
                       % (self.apic, tn_name, name, node_name, int_profile),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (Routed Ints) Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # node_name: Name of the Node Profile
    # int_profile: Name of the Interface Profile
    # sw1: Switch-1 ID of the switch as an integer
    # sw2: Switch-2 ID of the switch as an integer
    # sw1_ip: IP of Switch-1 in dotted-decimal
    # sw2_ip: IP of Switch-2 in dotted-decimal
    # vlan: VLAN ID as an integer
    # vpc: Name of associated vPC
    # int_profile_status created | created,modified | deleted of the Int Pro
    # status: created | created,modified | deleted of the Interface itself
    def svi(self, tn_name, name, node_name, int_profile, sw1, sw2, sw1_ip,
            sw2_ip, vlan, vpc, int_profile_status, status):
        try:
            sw1 = int(sw1)
            sw2 = int(sw2)
            vlan = int(vlan)
        except:
            status = 667
            return status
        payload = {
            "l3extLIfP": {
                "attributes": {
                    "dn": "uni/tn-%s/out-%s/lnodep-%s/lifp-%s" % (tn_name, name, node_name, int_profile),
                    "name": "%s" % int_profile,
                    "status": "%s" % int_profile_status
                },
                "children": [
                    {
                        "l3extRsNdIfPol": {
                            "attributes": {
                                "status": "created,modified"
                            }
                        }
                    },
                    {
                        "l3extRsPathL3OutAtt": {
                            "attributes": {
                                "encap": "vlan-%s" % vlan,
                                "ifInstT": "ext-svi",
                                "llAddr": "::",
                                "mac": "00:22:BD:F8:19:FF",
                                "mode": "regular",
                                "mtu": "inherit",
                                "status": "%s" % status,
                                "tDn": "topology/pod-1/protpaths-%s-%s/pathep-[%s]" % (sw1, sw2, vpc),
                                "targetDscp": "unspecified"
                            },
                            "children": [
                                {
                                    "l3extMember": {
                                        "attributes": {
                                            "addr": "%s" % sw2_ip,
                                            "llAddr": "::",
                                            "rn": "mem-B",
                                            "side": "B",
                                            "status": "created,modified"
                                        }
                                    }
                                },
                                {
                                    "l3extMember": {
                                        "attributes": {
                                            "addr": "%s" % sw1_ip,
                                            "llAddr": "::",
                                            "rn": "mem-A",
                                            "side": "A",
                                            "status": "created,modified"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/out-%s/lnodep-%s/lifp-%s.json'
                       % (self.apic, tn_name, name, node_name, int_profile),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (SVIs) Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # epg_name: Name of the Prefix Based EPG
    # subnet: Subent in CIDR format
    # status: created | created,modified | deleted of the EPG itself
    # subnet_status created | created,modified | deleted of the subnet
    def network_epg(self, tn_name, name, epg_name, subnet, status,
                    subnet_status):
        payload = {
            "l3extInstP": {
                "attributes": {
                    "dn": "uni/tn-%s/out-%s/instP-%s" % (tn_name, name, epg_name),
                    "matchT": "AtleastOne",
                    "name": "%s" % epg_name,
                    "status": "%s" % status
                },
                "children": [
                    {
                        "l3extConfigOutDef": {
                            "attributes": {
                                "rn": "configOutDef",
                                "status": "created,modified"
                            }
                        }
                    },
                    {
                        "l3extSubnet": {
                            "attributes": {
                                "aggregate": "",
                                "ip": "%s" % subnet,
                                "name": "",
                                "rn": "extsubnet-[%s]" % subnet,
                                "scope": "import-security",
                                "status": "%s" % subnet_status
                            }
                        }
                    },
                    {
                        "fvRsCustQosPol": {
                            "attributes": {
                                "status": "created,modified",
                                "tnQosCustomPolName": ""
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/out-%s/instP-%s.json'
                       % (self.apic, tn_name, name, epg_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (Prefix Based EPG) Failed to deploy. Exception: %s"
                  % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # pol_name: The name of the Interface Policy
    # hello: hello interval in seconds as an integer
    # dead: dead interval in seconds as an integer
    # net_type: p2p | bcast | unspecified
    # status: created | created,modified | deleted
    def ospf_int_pol(self, tn_name, pol_name, hello, dead, net_type, status):
        try:
            hello = int(hello)
            dead = int(dead)
        except:
            status = 667
            return status
        payload = {
            "ospfIfPol": {
                "attributes": {
                    "cost": "unspecified",
                    "ctrl": "mtu-ignore",
                    "deadIntvl": "%s" % dead,
                    "dn": "uni/tn-%s/ospfIfPol-%s" % (tn_name, pol_name),
                    "helloIntvl": "%s" % hello,
                    "name": "%s" % pol_name,
                    "nwT": "%s" % net_type,
                    "prio": "1",
                    "rexmitIntvl": "5",
                    "status": "%s" % status,
                    "xmitDelay": "1"
                }
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/ospfIfPol-%s.json'
                       % (self.apic, tn_name, pol_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (OSPF Interface Policy) Failed to deploy. "
                  "Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3 Out
    # node_name: Name of the Node Profile
    # int_profile: Name of the Interface Profile
    # pol_type: ospf | eigrp | bgp
    # pol_name: Name of the Interface Policy to be applied
    # status: created | created,modified | deleted
    def deploy_int_pol(self, tn_name, name, node_name, int_profile, pol_type,
                       pol_name, status):
        payload = {
            "ospfIfP": {
                "attributes": {
                    "authKeyId": "1",
                    "authType": "none",
                    "dn": "uni/tn-%s/out-%s/lnodep-%s/lifp-%s/%sIfP" % (tn_name, name, node_name, int_profile, pol_type),
                    "status": "created,modified"
                },
                "children": [
                    {
                        "ospfRsIfPol": {
                            "attributes": {
                                "rn": "rsIfPol",
                                "status": "%s" % status,
                                "tnOspfIfPolName": "%s" % pol_name
                            }
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/%sIfPol-%s.json'
                       % (self.apic, tn_name, pol_type, pol_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (Deploy Interface Policy) Failed to deploy. "
                  "Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3 Out
    # node_name: Name of the Node Profile
    # peer: BGP Peer address in dotted decimal
    # local_asn: Local BGP ASN as an integer
    # remote_asn: Remote BGP ASN as an integer
    # status: created | created,modified | deleted
    def bgp_peer_loopback(self, tn_name, name, node_name, peer, local_asn,
                          remote_asn, status):
        try:
            local_asn = int(local_asn)
            remote_asn = int(remote_asn)
        except:
            status = 667
            return status
        payload = {
            "l3extLNodeP": {
                "attributes": {
                    "dn": "uni/tn-%s/out-%s/lnodep-%s" % (tn_name, name, node_name),
                    "name": "%s" % node_name,
                    "status": "created,modified"
                },
                "children": [
                    {
                        "bgpPeerP": {
                            "attributes": {
                                "addr": "%s" % peer,
                                "allowedSelfAsCnt": "3",
                                "ctrl": "",
                                "peerCtrl": "",
                                "rn": "peerP-[%s]" % peer,
                                "status": "%s" % status,
                                "ttl": "1"
                            },
                            "children": [
                                {
                                    "bgpRsPeerPfxPol": {
                                        "attributes": {
                                            "rn": "rspeerPfxPol",
                                            "status": "created,modified",
                                            "tnBgpPeerPfxPolName": ""
                                        }
                                    }
                                },
                                {
                                    "bgpLocalAsnP": {
                                        "attributes": {
                                            "asnPropagate": "none",
                                            "localAsn": "%s" % local_asn,
                                            "rn": "localasn",
                                            "status": "created,modified"
                                        }
                                    }
                                },
                                {
                                    "bgpAsP": {
                                        "attributes": {
                                            "asn": "%s" % remote_asn,
                                            "rn": "as",
                                            "status": "created,modified"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/out-%s.json'
                       % (self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (BGP Peer - Loopback) Failed to deploy. "
                  "Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3 Out
    # node_name: Name of the Node Profile
    # int_profile: Name of the Interface Profile
    # sw1: Node ID of the first switch as an integer
    # sw1: Node ID of the second switch as an integer
    # vpc: Name of the associated vPC
    # peer: BGP Peer address in dotted decimal
    # local_asn: Local BGP ASN as an integer
    # remote_asn: Remote BGP ASN as an integer
    # status: created | created,modified | deleted
    def bgp_peer_svi(self, tn_name, name, node_name, int_profile, sw1, sw2,
                     vpc, peer, local_asn, remote_asn, status):
        try:
            sw1 = int(sw1)
            sw2 = int(sw2)
            local_asn = int(local_asn)
            remote_asn = int(remote_asn)
        except:
            status = 667
            return status
        payload = {
            "l3extLIfP": {
                "attributes": {
                    "name": "%s" % int_profile,
                    "status": "created,modified"
                },
                "children": [
                    {
                        "l3extRsPathL3OutAtt": {
                            "attributes": {
                                "rn": "rspathL3OutAtt-[topology/pod-1/protpaths-%s-%s/pathep-[%s]]" % (sw1, sw2, vpc),
                                "status": "created,modified"
                            },
                            "children": [
                                {
                                    "bgpPeerP": {
                                        "attributes": {
                                            "addr": "%s" % peer,
                                            "allowedSelfAsCnt": "3",
                                            "ctrl": "",
                                            "peerCtrl": "",
                                            "rn": "peerP-[%s]" % peer,
                                            "status": "%s" % status,
                                            "ttl": "1"
                                        },
                                        "children": [
                                            {
                                                "bgpRsPeerPfxPol": {
                                                    "attributes": {
                                                        "rn": "rspeerPfxPol",
                                                        "status": "",
                                                        "tnBgpPeerPfxPolName": ""
                                                    }
                                                }
                                            },
                                            {
                                                "bgpLocalAsnP": {
                                                    "attributes": {
                                                        "asnPropagate": "none",
                                                        "localAsn": "%s" % local_asn,
                                                        "rn": "localasn",
                                                        "status": "created,modified"
                                                    }
                                                }
                                            },
                                            {
                                                "bgpAsP": {
                                                    "attributes": {
                                                        "asn": "%s" % remote_asn,
                                                        "rn": "as",
                                                        "status": "created,modified"
                                                    }
                                                }
                                            }
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
        s = requests.Session()
        try:
            r = s.post('https://%s/api/node/mo/uni/tn-%s/out-%s/lnodep-%s/lifp-%s.json'
                       % (self.apic, tn_name, name, node_name, int_profile),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception, e:
            print("L3 Out (BGP Peer - SVI) Failed to deploy. "
                  "Exception: %s" % e)
            status = 666
        return status

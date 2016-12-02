import requests
import json
import sys
import collections


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
        payload = '''
        {{
            "polUni": {{
                "attributes": {{
                    "dn": "uni"
                }},
                "children": [
                    {{
                        "ctrlrInst": {{
                            "attributes": {{
                                "ownerKey": "",
                                "ownerTag": ""
                            }},
                            "children": [
                                {{
                                    "fabricNodeIdentPol": {{
                                        "attributes": {{
                                            "name": "default",
                                            "ownerKey": "",
                                            "ownerTag": ""
                                        }},
                                        "children": [
                                            {{
                                                "fabricNodeIdentP": {{
                                                    "attributes": {{
                                                        "name": "{name}",
                                                        "nodeId": "{id}",
                                                        "serial": "{serial}",
                                                        "descr": "{descr}",
                                                        "fabricId": "{fabric}",
                                                        "podId": "{pod}"
                                                    }}
                                                }}
                                            }}
                                        ]
                                    }}
                                }}
                            ]
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, id=id, serial=serial, descr=descr, fabric=fabric,
                   pod=pod)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni.json'.format(self.apic),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("Hardware Failed to provision. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # address: Name/IP of the NTP server
    # status: created | created,modified | deleted
    def ntp(self, address, status):
        payload = '''
        {{
            "datetimeNtpProv": {{
                "attributes": {{
                    "dn": "uni/fabric/time-default/ntpprov-{address}",
                    "name": "{address}",
                    "rn": "ntpprov-{address}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "datetimeRsNtpProvToEpg": {{
                            "attributes": {{
                                "tDn": "uni/tn-mgmt/mgmtp-default/oob-default",
                                "status": "created,modified"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(address=address, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni.json'.format(self.apic),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("NTP Failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "dnsProfile": {{
                "attributes": {{
                    "dn": "uni/fabric/dnsp-default",
                    "name": "default",
                    "status": "created,modified"
                }},
                "children": [
                    {{
                        "dnsProv": {{
                            "attributes": {{
                                "addr": "{address}",
                                "preferred": "{preferred}",
                                "status": "{status}",
                                "rn": "prov-[{address}]"
                            }}
                        }}
                    }},
                    {{
                        "dnsDomain": {{
                            "attributes": {{
                                "isDefault": "{domain_default}",
                                "name": "{domain}",
                                "rn": "dom-{domain}",
                                "status": "{domain_status}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(address=address, preferred=preferred, status=status,
                   domain_default=domain_default, domain=domain,
                   domain_status=domain_status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/fabric/dnsp-default.json'
                       .format(self.apic), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("DNS Server Failed to deploy. Exception: {}".format(e))
            status = 666
        payload = '''
        {
            "dnsRsProfileToEpg": {
                "attributes": {
                    "tDn": "uni/tn-mgmt/mgmtp-default/oob-default",
                    "status": "created,modified"
                }
            }
        }
        '''
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/fabric/dnsp-default/rsProfi'
                       'leToEpg.json'.format(self.apic),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
        except Exception as e:
            print("DNS to OOB EPG Failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "bgpAsP": {{
                "attributes": {{
                    "dn": "uni/fabric/bgpInstP-default/as",
                    "asn": "{asn}",
                    "rn": "as",
                    "status": "{status}"
                }}
            }}
        }}
        '''.format(asn=asn, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/fabric/bgpInstP-default/as.'
                       'json'.format(self.apic), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Fabric BGP Policy Failed to deploy. Exception: {}"
                  .format(e))
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
        payload = '''
        {{
            "bgpRRNodePEp": {{
                "attributes": {{
                    "dn": "uni/fabric/bgpInstP-default/rr/node-{rr}",
                    "id": "{rr}",
                    "rn": "node-{rr}",
                    "status": "{status}"
                }}
            }}
        }}
        '''.format(rr=rr, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/fabric/bgpInstP-default/rr/'
                       'node-{}.json'.format(self.apic, rr),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("Fabric Route Reflector Failed to deploy. Exception: {}"
                  .format(e))
            status = 666
        return status

    def pod_pol(self, name, status):
        payload = '''
        {{
            "fabricPodPGrp": {{
                "attributes": {{
                    "dn": "uni/fabric/funcprof/podpgrp-{name}",
                    "name": "{name}",
                    "rn": "podpgrp-{name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "fabricRsTimePol": {{
                            "attributes": {{
                                "tnDatetimePolName": "default",
                                "status": "created,modified"
                            }}
                        }}
                    }},
                    {{
                        "fabricRsPodPGrpIsisDomP": {{
                            "attributes": {{
                                "tnIsisDomPolName": "default",
                                "status": "created,modified"
                            }}
                        }}
                    }},
                    {{
                        "fabricRsPodPGrpCoopP": {{
                            "attributes": {{
                                "tnCoopPolName": "default",
                                "status": "created,modified"
                            }}
                        }}
                    }},
                    {{
                        "fabricRsPodPGrpBGPRRP": {{
                            "attributes": {{
                                "tnBgpInstPolName": "default",
                                "status": "created,modified"
                            }}
                        }}
                    }},
                    {{
                        "fabricRsCommPol": {{
                            "attributes": {{
                                "tnCommPolName": "default",
                                "status": "created,modified"
                            }}
                        }}
                    }},
                    {{
                        "fabricRsSnmpPol": {{
                            "attributes": {{
                                "tnSnmpPolName": "default",
                                "status": "created,modified"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/fabric/funcprof/podpgrp-{}.'
                       'json'.format(self.apic, name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("Fabric Pod Policy Failed to deploy. Exception: {}"
                  .format(e))
            status = 666
        payload = '''
        {{
            "fabricRsPodPGrp": {{
                "attributes": {{
                    "tDn": "uni/fabric/funcprof/podpgrp-{name}",
                    "status": "created,modified"
                }}
            }}
        }}
        '''.format(name=name)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/fabric/podprof-default/pods'
                       '-default-typ-ALL/rspodPGrp.json'.format(self.apic),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("Assigning Pod Policy Failed. Exception: {}".format(e))
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
        payload = '''
        {{
            "cdpIfPol": {{
                "attributes": {{
                    "dn": "uni/infra/cdpIfP-{name}",
                    "name": "{name}",
                    "adminSt": "{state}",
                    "rn": "cdpIfP-{name}",
                    "status": "{status}"
                }}
            }}
        }}
        '''.format(name=name, state=state, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/cdpIfP-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("CDP Policy Failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # name: The name of the LLDP policy
    # state: enabled | disabled
    #   Note: The configured state is deployed to both Tx and Rx
    # status: created | created,modified | deleted
    def lldp(self, name, state, status):
        payload = '''
        {{
            "lldpIfPol": {{
                "attributes": {{
                    "dn": "uni/infra/lldpIfP-{name}",
                    "name": "{name}",
                    "adminRxSt": "{state}",
                    "adminTxSt": "{state}",
                    "rn": "lldpIfP-{name}",
                    "status": "{status}"
                }}
            }}
        }}
        '''.format(name=name, state=state, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/lldpIfP-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("LLDP Policy Failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # name: The name of the Link policy
    # auto_neg: on | off
    # speed: 100M | 1G | 10G | 40G | auto
    #   Note: 100G should be available soon if not already in some versions
    # status: created | created,modified | deleted
    def link(self, name, auto_neg, speed, status):
        payload = '''
        {{
            "fabricHIfPol": {{
                "attributes": {{
                    "dn": "uni/infra/hintfpol-{name}",
                    "name": "{name}",
                    "autoNeg": "{auto_neg}",
                    "speed": "{speed}",
                    "status": "{status}"
                }}
            }}
        }}
        '''.format(name=name, auto_neg=auto_neg, speed=speed, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/hintfpol-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Link Policy Failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "lacpLagPol": {{
                "attributes": {{
                    "dn": "uni/infra/lacplagp-{name}",
                    "name": "{name}",
                    "ctrl": "fast-sel-hot-stdby,graceful-conv,susp-individual",
                    "name": "{name}",
                    "status": "{status}",
                    "mode": "{mode}"
                }}
            }}
        }}
        '''.format(name=name, status=status, mode=mode)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/lacplagp-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Port Channel Policy Failed to deploy. Exception: {e}"
                  .format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # name: The name of the Per Port VLAN policy
    # state: enabled | disabled
    # status: created | created,modified | deleted
    def ppv(self, name, state, status):
        payload = '''
        {{
            "l2IfPol": {{
                "attributes": {{
                    "dn": "uni/infra/l2IfP-{name}",
                    "name": "{name}",
                    "vlanScope": "{state}",
                    "status": "{status}"
                }}
            }}
        }}
        '''.format(name=name, state=state, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/l2IfP-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Per Port VLAN Policy Failed to deploy. Exception: {}"
                  .format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # name: The name of the Per Port VLAN policy
    # state: enabled | disabled
    # status: created | created,modified | deleted
    def mcp_intf(self, name, state, status):
        payload = '''
        {{
            "mcpIfPol": {{
                "attributes": {{
                    "dn": "uni/infra/mcpIfP-{name}",
                    "name": "{name}",
                    "status": "{status}",
                    "adminSt": "{state}"
                }}
            }}
        }}
        '''.format(name=name, status=status, state=state)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/mcpIfP-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("MCP Interface Failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # password: string for global MCP password
    # state: enabled | disabled
    def mcp_global(self, password, state):
        payload = '''
        {{
            "mcpInstPol": {{
                "attributes": {{
                    "dn": "uni/infra/mcpInstP-default",
                    "key": "{password}",
                    "adminSt": "{state}"
                }}
            }}
        }}
        '''.format(password=password, state=state)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/mcpInstP-default.json'
                       .format(self.apic), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("MCP Global Failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # event: mcp-loop | ep-move | bpduguard
    # state: true | false
    def err_disable(self, event, state):
        payload = '''
        {{
            "edrEventP": {{
                "attributes": {{
                    "dn": "uni/infra/edrErrDisRecoverPol-default/edrEventP-event-{event}",
                    "recover": "{state}"
                }}
            }}
        }}
        '''.format(event=event, state=state)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/edrErrDisRecoverPol-d'
                       'efault/edrEventP-event-{}.json'
                       .format(self.apic, event), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Error Disable Policy Failed to deploy. Exception: {}"
                  .format(e))
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
        payload = '''
        {{
            "fvnsVlanInstP": {{
                "attributes": {{
                    "allocMode": "{mode}",
                    "dn": "uni/infra/vlanns-[{name}]-{mode}",
                    "name": "{name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "fvnsEncapBlk": {{
                            "attributes": {{
                                "allocMode": "{range_mode}",
                                "from": "vlan-{start}",
                                "to": "vlan-{end}",
                                "status": "{status}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(mode=mode, name=name, status=status, range_mode=range_mode,
                   start=start, end=end)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/vlanns-[{}]-{}.json'
                       .format(self.apic, name, mode),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("VLAN Pool Failed to deploy. Exception: {}".format(e))
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
            payload = '''
            {{
                "infraAttEntityP": {{
                    "attributes": {{
                        "dn": "uni/infra/attentp-{name}",
                        "name": "{name}",
                        "status": "{status}"
                    }},
                    "children": [
                        {{
                            "infraContNS": {{
                                "attributes": {{
                                    "rn": "nscont",
                                    "status": "{status}"
                                }}
                            }}
                        }},
                        {{
                            "infraContDomP": {{
                                "attributes": {{
                                    "rn": "dompcont",
                                    "status": "{status}"
                                }}
                            }}
                        }},
                        {{
                            "infraProvAcc": {{
                                "attributes": {{
                                    "name": "default",
                                    "rn": "provacc",
                                    "status": "{infra}"
                                }},
                                "children": [
                                    {{
                                        "dhcpInfraProvP": {{
                                            "attributes": {{
                                                "mode": "controller",
                                                "rn": "infraprovp",
                                                "status": "{infra}"
                                            }}
                                        }}
                                    }},
                                    {{
                                        "infraRsFuncToEpg": {{
                                            "attributes": {{
                                                "encap": "vlan-{infra_vlan}",
                                                "rn": "rsfuncToEpg-[uni/tn-infra/ap-access/epg-default]",
                                                "status": "{infra}"
                                            }}
                                        }}
                                    }}
                                ]
                            }}
                        }},
                        {{
                            "infraAttPolicyGroup": {{
                                "attributes": {{
                                    "rn": "attpolgrp",
                                    "status": "{override}"
                                }},
                                "children": [
                                    {{
                                        "infraRsOverrideCdpIfPol": {{
                                            "attributes": {{
                                                "rn": "rsoverrideCdpIfPol",
                                                "status": "{override}",
                                                "tnCdpIfPolName": "{override_cdp}"
                                            }}
                                        }}
                                    }},
                                    {{
                                        "infraRsOverrideLacpPol": {{
                                            "attributes": {{
                                                "rn": "rsoverrideLacpPol",
                                                "status": "{override}",
                                                "tnLacpLagPolName": "{override_pc}"
                                            }}
                                        }}
                                    }},
                                    {{
                                        "infraRsOverrideLldpIfPol": {{
                                            "attributes": {{
                                                "rn": "rsoverrideLldpIfPol",
                                                "status": "{override}",
                                                "tnLldpIfPolName": "{override_lldp}"
                                            }}
                                        }}
                                    }}
                                ]
                            }}
                        }}
                    ]
                }}
            }}
            '''.format(name=name, status=status, infra=infra,
                       infra_vlan=infra_vlan, override=override,
                       override_pc=override_pc, override_cdp=override_cdp,
                       override_lldp=override_lldp)
        else:
            payload = '''
            {{
                "infraAttEntityP": {{
                    "attributes": {{
                        "dn": "uni/infra/attentp-{name}",
                        "name": "{name}",
                        "status": "{status}"
                    }},
                    "children": [
                        {{
                            "infraContNS": {{
                                "attributes": {{
                                    "rn": "nscont",
                                    "status": "{status}"
                                }}
                            }}
                        }},
                        {{
                            "infraContDomP": {{
                                "attributes": {{
                                    "rn": "dompcont",
                                    "status": "{status}"
                                }}
                            }}
                        }},
                        {{
                            "infraProvAcc": {{
                                "attributes": {{
                                    "name": "default",
                                    "rn": "provacc",
                                    "status": "{infra}"
                                }},
                                "children": [
                                    {{
                                        "dhcpInfraProvP": {{
                                            "attributes": {{
                                                "mode": "controller",
                                                "rn": "infraprovp",
                                                "status": "{infra}"
                                            }}
                                        }}
                                    }},
                                    {{
                                        "infraRsFuncToEpg": {{
                                            "attributes": {{
                                                "encap": "vlan-{infra_vlan}",
                                                "rn": "rsfuncToEpg-[uni/tn-infra/ap-access/epg-default]",
                                                "status": "{infra}"
                                            }}
                                        }}
                                    }}
                                ]
                            }}
                        }}
                    ]
                }}
            }}
            '''.format(name=name, status=status, infra=infra,
                       infra_vlan=infra_vlan, override=override,
                       override_pc=override_pc, override_cdp=override_cdp,
                       override_lldp=override_lldp)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/attentp-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("AEP Failed to deploy. Exception: %s" % e)
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the L3-Out Domain
    # status: created | created,modified | deleted
    # vlan_pool: Name of the VLAN pool to associate to the L3 Out
    def l3_dom(self, name, status, vlan_pool):
        payload = '''
        {{
            "l3extDomP": {{
                "attributes": {{
                    "dn": "uni/l3dom-{name}",
                    "name": "{name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "infraRsVlanNs": {{
                            "attributes": {{
                                "rn": "rsvlanNs",
                                "status": "{status}",
                                "tDn": "uni/infra/vlanns-[{vlan_pool}]-dynamic"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, status=status, vlan_pool=vlan_pool)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/l3dom-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Domain Failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the Physical Domain
    # status: created | created,modified | deleted
    # vlan_pool: Name of the VLAN pool to associate to the Physical Domain
    def phys_dom(self, name, status, vlan_pool):
        payload = '''
        {{
            "physDomP": {{
                "attributes": {{
                    "dn": "uni/phys-{name}",
                    "name": "{name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "infraRsVlanNs": {{
                            "attributes": {{
                                "rn": "rsvlanNs",
                                "status": "{status}",
                                "tDn": "uni/infra/vlanns-[{vlan_pool}]-dynamic"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, status=status, vlan_pool=vlan_pool)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/phys-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Physical Domain Failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the AEP
    # status: created | created,modified | deleted
    # l3_dom: Name of the L3 Domain to be hooked to the AEP
    def l3_aep(self, name, status, l3_dom):
        payload = '''
        {{
            "infraAttEntityP": {{
                "attributes": {{
                    "dn": "uni/infra/attentp-{name}",
                    "name": "{name}",
                    "status": "created,modified"
                }},
                "children": [
                    {{
                        "infraRsDomP": {{
                            "attributes": {{
                                "rn": "rsdomP-[uni/l3dom-{l3_dom}]",
                                "status": "{status}",
                                "tDn": "uni/l3dom-{l3_dom}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, status=status, l3_dom=l3_dom)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/attentp-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Domain to AEP Failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the AEP
    # status: created | created,modified | deleted
    # l3_dom: Name of the L3 Domain to be hooked to the AEP
    def phys_aep(self, name, dom_name, status):
        payload = '''
        {{
            "infraAttEntityP": {{
                "attributes": {{
                    "dn": "uni/infra/attentp-{name}",
                    "name": "{name}",
                    "status": "created,modified"
                }},
                "children": [
                    {{
                        "infraRsDomP": {{
                            "attributes": {{
                                "rn": "rsdomP-[uni/phys-{dom_name}]",
                                "status": "{status}",
                                "tDn": "uni/phys-{dom_name}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, dom_name=dom_name, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/attentp-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Physical Domain to AEP Failed to deploy. Exception: {}"
                  .format(e))
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
        payload = '''
        {{
            "fabricExplicitGEp": {{
                "attributes": {{
                    "dn": "uni/fabric/protpol/expgep-{name}",
                    "name": "{name}",
                    "id": "{id}",
                    "rn": "expgep-{name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "fabricNodePEp": {{
                            "attributes": {{
                                "dn": "uni/fabric/protpol/expgep-{name}/nodepep-{sw1}",
                                "id": "{sw1}",
                                "status": "{status}",
                                "rn": "nodepep-{sw1}"
                            }}
                        }}
                    }},
                    {{
                        "fabricNodePEp": {{
                            "attributes": {{
                                "dn": "uni/fabric/protpol/expgep-{name}/nodepep-{sw2}",
                                "id": "{sw2}",
                                "status": "{status}",
                                "rn": "nodepep-{sw2}"
                            }}
                        }}
                    }},
                    {{
                        "fabricRsVpcInstPol": {{
                            "attributes": {{
                                "tnVpcInstPolName": "default",
                                "status": "{status}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, id=id, status=status, sw1=sw1, sw2=sw2)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/fabric/protpol/expgep-{}.jso'
                       'n'.format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("vPC Policy Failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "infraNodeP": {{
                "attributes": {{
                    "dn": "uni/infra/nprof-{name}",
                    "name": "{name}",
                    "rn": "nprof-{name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "infraLeafS": {{
                            "attributes": {{
                                "dn": "uni/infra/nprof-{name}/leaves-{name}-typ-range",
                                "type": "range",
                                "name": "{name}",
                                "rn": "leaves-{name}-typ-range",
                                "status": "{status}"
                            }},
                            "children": [
                                {{
                                    "infraNodeBlk": {{
                                        "attributes": {{
                                            "dn": "uni/infra/nprof-{name}/leaves-{name}-typ-range/nodeblk-L{sw1}",
                                            "from_": "{sw1}",
                                            "to_": "{sw1}",
                                            "name": "L{sw1}",
                                            "rn": "nodeblk-L{sw1}",
                                            "status": "{status}"
                                        }}
                                    }}
                                }},
                                {{
                                    "infraNodeBlk": {{
                                        "attributes": {{
                                            "dn": "uni/infra/nprof-{name}/leaves-{name}-typ-range/nodeblk-L{sw2}",
                                            "from_": "{sw2}",
                                            "to_": "{sw2}",
                                            "name": "L{sw2}",
                                            "rn": "nodeblk-L{sw2}",
                                            "status": "{status}"
                                        }}
                                    }}
                                }}
                            ]
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, status=status, sw1=sw1, sw2=sw2)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/nprof-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Switch Profile (vPC) Failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "infraNodeP": {{
                "attributes": {{
                    "dn": "uni/infra/nprof-{name}",
                    "name": "{name}",
                    "rn": "nprof-{name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "infraLeafS": {{
                            "attributes": {{
                                "dn": "uni/infra/nprof-{name}/leaves-{name}-typ-range",
                                "type": "range",
                                "name": "{name}",
                                "rn": "leaves-{name}-typ-range",
                                "status": "{status}"
                            }},
                            "children": [
                                {{
                                    "infraNodeBlk": {{
                                        "attributes": {{
                                            "dn": "uni/infra/nprof-{name}/leaves-{name}-typ-range/nodeblk-L{sw1}",
                                            "from_": "{sw1}", "to_": "{sw1}",
                                            "name": "L{sw1}","rn": "nodeblk-L{sw1}",
                                            "status": "{status}"
                                        }}
                                    }}
                                }}
                            ]
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, status=status, sw1=sw1)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/nprof-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Switch Profile (single switch) Failed to deploy. "
                  "Exception: {}".format(e))
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
        payload = '''
        {{
            "infraAccBndlGrp": {{
                "attributes": {{
                    "dn": "uni/infra/funcprof/accbundle-{name}",
                    "lagT": "{lag_type}",
                    "name": "{name}",
                    "rn": "accbundle-{name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "infraRsMonIfInfraPol": {{
                            "attributes": {{
                                "tnMonInfraPolName": ""
                            }}
                        }}
                    }},
                    {{
                        "infraRsLldpIfPol": {{
                            "attributes": {{
                                "tnLldpIfPolName": "{lldp}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsStpIfPol": {{
                            "attributes": {{
                                "tnStpIfPolName": ""
                            }}
                        }}
                    }},
                    {{
                        "infraRsCdpIfPol": {{
                            "attributes": {{
                                "tnCdpIfPolName": "{cdp}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsAttEntP": {{
                            "attributes": {{
                                "tDn": "uni/infra/attentp-{aep}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsMcpIfPol": {{
                            "attributes": {{
                                "tnMcpIfPolName": "{mcp}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsStormctrlIfPol": {{
                            "attributes": {{
                                "tnStormctrlIfPolName": "{storm}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsL2IfPol": {{
                            "attributes": {{
                                "tnL2IfPolName": "{ppv}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsLacpPol": {{
                            "attributes": {{
                                "tnLacpLagPolName": "{lag}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsHIfPol": {{
                            "attributes": {{
                                "tnFabricHIfPolName": "{link}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, status=status, lag_type=lag_type, lldp=lldp,
                   cdp=cdp, aep=aep, mcp=mcp, lag=lag, link=link, ppv=ppv,
                   storm=storm)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/funcprof/accbundle-{}'
                       '.json'.format(self.apic, name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("Interface Policy Group (vPC) Failed to deploy. "
                  "Exception: {}".format(e))
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
        payload = '''
        {{
            "infraAccPortGrp": {{
                "attributes": {{
                    "dn": "uni/infra/funcprof/accportgrp-{name}",
                    "name": "{name}",
                    "rn": "accportgrp-{name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "infraRsMonIfInfraPol": {{
                            "attributes": {{
                                "tnMonInfraPolName": ""
                            }}
                        }}
                    }},
                    {{
                        "infraRsLldpIfPol": {{
                            "attributes": {{
                                "tnLldpIfPolName": "{lldp}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsStpIfPol": {{
                            "attributes": {{
                                "tnStpIfPolName": ""
                            }}
                        }}
                    }},
                    {{
                        "infraRsCdpIfPol": {{
                            "attributes": {{
                                "tnCdpIfPolName": "{cdp}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsAttEntP": {{
                            "attributes": {{
                                "tDn": "uni/infra/attentp-{aep}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsMcpIfPol": {{
                            "attributes": {{
                                "tnMcpIfPolName": "{mcp}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsL2IfPol": {{
                            "attributes": {{
                                "tnL2IfPolName": "{ppv}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsStormctrlIfPol": {{
                            "attributes": {{
                                "tnStormctrlIfPolName": "{storm}"
                            }}
                        }}
                    }},
                    {{
                        "infraRsHIfPol": {{
                            "attributes": {{
                                "tnFabricHIfPolName": "{link}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, status=status, lldp=lldp, cdp=cdp, aep=aep,
                   mcp=mcp, link=link, ppv=ppv, storm=storm)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/funcprof/accportgrp-'
                       '{}.json'.format(self.apic, name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("Interface Policy Group (Access) Failed to deploy. "
                  "Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the Interface Profile
    # status: created | created,modified | deleted
    def int_profile(self, name, status):
        payload = '''
        {{
            "infraAccPortP": {{
                "attributes": {{
                    "dn": "uni/infra/accportprof-{name}",
                    "name": "{name}",
                    "status": "{status}"
                }}
            }}
        }}
        '''.format(name=name, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/accportprof-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Interface Profile Failed to deploy. "
                  "Exception: {}".format(e))
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
        payload = '''
        {{
            "infraHPortS": {{
                "attributes": {{
                    "name": "{port_name}",
                    "rn": "hports-{port_name}-typ-range",
                    "status": "{status}",
                    "type": "range"
                }},
                "children": [
                    {{
                        "infraRsAccBaseGrp": {{
                            "attributes": {{
                                "fexId": "101",
                                "rn": "rsaccBaseGrp",
                                "tDn": "uni/infra/funcprof/{port_type}-{pol_group}",
                                "status": "created,modified"
                            }}
                        }}
                    }},
                    {{
                        "infraPortBlk": {{
                            "attributes": {{
                                "fromCard": "{mod_start}",
                                "toCard": "{mod_end}",
                                "fromPort": "{port_start}",
                                "toPort": "{port_end}",
                                "name": "block2",
                                "rn": "portblk-block2",
                                "status": "created,modified"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, status=status, port_name=port_name,
                   port_type=port_type, pol_group=pol_group,
                   mod_start=mod_start, mod_end=mod_end, port_start=port_start,
                   port_end=port_end)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/accportprof-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Interface Selector Failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # name: Name of the Switch Profile
    # status: created | created,modified | deleted
    # int_profile: Name of the Interface Profile to hook to Switch Selector
    def int_selector_sw_profile(self, name, status, int_profile):
        payload = '''
        {{
            "infraNodeP": {{
                "attributes": {{
                    "dn": "uni/infra/nprof-{name}",
                    "name": "{name}"
                }},
                "children": [
                    {{
                        "infraLeafS": {{
                            "attributes": {{
                                "name": "{name}",
                                "type": "range"
                            }}
                        }}
                    }},
                    {{
                        "infraRsAccPortP": {{
                            "attributes": {{
                                "tDn": "uni/infra/accportprof-{int_profile}",
                                "status": "{status}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, status=status, int_profile=int_profile)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/infra/nprof-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Switch Profile Failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "fvTenant": {{
                "attributes": {{
                    "dn": "uni/tn-{name}",
                    "name": "{name}",
                    "status": "{status}"
                }}
            }}
        }}
        '''.format(name=name, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Tenant Failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # name: Name of the VRF
    # enforce: enforced | unenforced
    # status: created | created,modified | deleted
    def vrf(self, tn_name, name, enforce, status):
        payload = '''
        {{
            "fvCtx": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/ctx-{name}",
                    "knwMcastAct": "permit",
                    "name": "{name}",
                    "pcEnfPref": "{enforce}",
                    "status": "{status}"
                }}
            }}
        }}
        '''.format(tn_name=tn_name, name=name, enforce=enforce, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/ctx-{}.json'
                       .format(self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("VRF Failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "fvBD": {{
                "attributes": {{
                    "arpFlood": "{arp}",
                    "dn": "uni/tn-{tn_name}/BD-{name}",
                    "epMoveDetectMode": "",
                    "limitIpLearnToSubnets": "no",
                    "llAddr": "::",
                    "mac": "00:22:BD:F8:19:FF",
                    "multiDstPktAct": "{mdest}",
                    "name": "{name}",
                    "status": "{status}",
                    "unicastRoute": "{unicast}",
                    "unkMacUcastAct": "{unk_unicast}",
                    "unkMcastAct": "{mcast}"
                }},
                "children": [
                    {{
                        "fvRsBDToOut": {{
                            "attributes": {{
                                "rn": "rsBDToOut-{l3_out}",
                                "status": "created,modified",
                                "tnL3extOutName": "{l3_out}"
                            }}
                        }}
                    }},
                    {{
                        "fvRsCtx": {{
                            "attributes": {{
                                "rn": "rsctx",
                                "status": "crated,modified",
                                "tnFvCtxName": "{vrf}"
                            }}
                        }}
                    }},
                    {{
                        "fvSubnet": {{
                            "attributes": {{
                                "ctrl": "",
                                "ip": "{subnet}",
                                "name": "",
                                "preferred": "yes",
                                "rn": "subnet-[{subnet}]",
                                "scope": "{scope}",
                                "status": "created,modified"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, arp=arp, mdest=mdest,
                   mcast=mcast, unicast=unicast, unk_unicast=unk_unicast,
                   vrf=vrf, l3_out=l3_out, subnet=subnet, scope=scope,
                   status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/BD-{}.json'
                       .format(self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("BD Failed to deploy. Exception: {}".format(e))
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
                dst_end = int(dst_end)
            except:
                status = 667
                return status
        if src_start and src_end == 'unspecified':
            pass
        else:
            try:
                src_start = int(src_start)
                src_end = int(src_end)
            except:
                status = 667
                return status
        payload = '''
        {{
            "vzFilter": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/flt-{name}",
                    "name": "{name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "vzEntry": {{
                            "attributes": {{
                                "applyToFrag": "no",
                                "arpOpc": "unspecified",
                                "dFromPort": "{dst_start}",
                                "dToPort": "{dst_end}",
                                "etherT": "{ethertype}",
                                "icmpv4T": "unspecified",
                                "icmpv6T": "unspecified",
                                "name": "{name}",
                                "prot": "{protocol}",
                                "rn": "e-{name}",
                                "sFromPort": "{src_start}",
                                "sToPort": "{src_end}",
                                "stateful": "no",
                                "status": "{status}",
                                "tcpRules": ""
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, dst_start=dst_start,
                   dst_end=dst_end, src_start=src_start, src_end=src_end,
                   ethertype=ethertype, protocol=protocol, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/flt-{}.json'
                       .format(self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Filter Policy Failed to deploy. "
                  "Check your payload and URL.")
        except Exception as e:
            print("Filter Failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "vzBrCP": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/brc-{name}",
                    "name": "{name}",
                    "prio": "unspecified",
                    "scope": "{scope}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "vzSubj": {{
                            "attributes": {{
                                "consMatchT": "AtleastOne",
                                "name": "{subject}",
                                "prio": "unspecified",
                                "provMatchT": "AtleastOne",
                                "revFltPorts": "{reverse_filter}",
                                "rn": "subj-{subject}",
                                "status": "{status}"
                            }},
                            "children": [
                                {{
                                    "vzRsSubjFiltAtt": {{
                                        "attributes": {{
                                            "rn": "rssubjFiltAtt-{filter}",
                                            "status": "{status}",
                                            "tnVzFilterName": "{filter}"
                                        }}
                                    }}
                                }}
                            ]
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, scope=scope, subject=subject,
                   filter=filter, reverse_filter=reverse_filter, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/brc-{}.json'
                       .format(self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Contract Failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # name: Name of the Application Profile
    # status: created | created,modified | deleted
    def app_profile(self, tn_name, name, status):
        payload = '''
        {{
            "fvAp": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/ap-{name}",
                    "name": "{name}",
                    "status": "{status}"
                }}
            }}
        }}
        '''.format(tn_name=tn_name, name=name, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/ap-{}.json'
                       .format(self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("App Profile failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # name: Name of the EPG
    # bd: Name of associated BD
    # status: created | created,modified | deleted
    def epg(self, tn_name, ap_name, name, bd, status):
        payload = '''
        {{
            "fvAEPg": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/ap-{ap_name}/epg-{name}",
                    "name": "{name}",
                    "rn": "epg-{name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "fvRsBd": {{
                            "attributes": {{
                                "tnFvBDName": "{bd}",
                                "status": "{status}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, ap_name=ap_name, name=name, bd=bd,
                   status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/ap-{}/epg-{}.json'
                       .format(self.apic, tn_name, ap_name, name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("EPG failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "fvRsDomAtt": {{
                "attributes": {{
                    "childAction": "",
                    "dn": "uni/tn-{tn_name}/ap-{ap_name}/epg-{epg_name}/rsdomAtt-[uni/phys-{epg_name}]",
                    "instrImedcy": "{deploy}",
                    "resImedcy": "{resolve}",
                    "status": "{status}"
                }}
            }}
        }}
        '''.format(tn_name=tn_name, ap_name=ap_name, epg_name=epg_name,
                   phys_dom=phys_dom, deploy=deploy, resolve=resolve,
                   status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/ap-{}/epg-{}.json'
                       .format(self.apic, tn_name, ap_name, epg_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("EPG to Phys Dom failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "fvRsDomAtt": {{
                "attributes": {{
                    "childAction": "",
                    "dn": "uni/tn-{tn_name}/ap-{ap_name}/epg-{epg_name}/rsdomAtt-[uni/vmmp-VMware/dom-{vmm_dom}]",
                    "instrImedcy": "{deploy}",
                    "resImedcy": "{resolve}",
                    "status": "{status}",
                    "tDn": "uni/vmmp-VMware/dom-{vmm_dom}"
                }},
                "children": [
                    {{
                        "vmmSecP": {{
                            "attributes": {{
                                "allowPromiscuous": "reject",
                                "forgedTransmits": "reject",
                                "macChanges": "reject",
                                "rn": "sec",
                                "status": "created,modified"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, ap_name=ap_name, epg_name=epg_name,
                   vmm_dom=vmm_dom, deploy=deploy, resolve=resolve,
                   status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/ap-{}/epg-{}.json'
                       .format(self.apic, tn_name, ap_name, epg_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("EPG to VMM Dom failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # contract: Name of the Contract
    # status: created | created,modified | deleted
    def provide_contract(self, tn_name, ap_name, epg_name, contract, status):
        payload = '''
        {{
            "fvRsProv": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/ap-{ap_name}/epg-{epg_name}/rsprov-{contract}",
                    "prio": "unspecified",
                    "status": "{status}",
                    "tnVzBrCPName": "{contract}"
                }}
            }}
        }}
        '''.format(tn_name=tn_name, ap_name=ap_name, epg_name=epg_name,
                   contract=contract, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/ap-{}/epg-{}/rsprov-{}.json'
                       .format(self.apic, tn_name, ap_name, epg_name, contract), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Provide Contract failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # ap_name: Name of parent Application Profile
    # epg_name: Name of the EPG
    # contract: Name of the Contract
    # status: created | created,modified | deleted
    def consume_contract(self, tn_name, ap_name, epg_name, contract, status):
        payload = '''
        {{
            "fvRsCons": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/ap-{ap_name}/epg-{epg_name}/rscons-{contract}",
                    "prio": "unspecified",
                    "status": "{status}",
                    "tnVzBrCPName": "{contract}"
                }}
            }}
        }}
        '''.format(tn_name=tn_name, ap_name=ap_name, epg_name=epg_name,
                   contract=contract, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/ap-{}/epg-{}/rscons-{}.json'
                       .format(self.apic, tn_name, ap_name, epg_name, contract),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("Consume Contract failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "fvAEPg": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/ap-{ap_name}/epg-{epg_name}",
                    "name": "{epg_name}",
                    "rn": "epg-{epg_name}",
                    "status": "created,modified"
                }},
                "children": [
                    {{
                        "fvRsPathAtt": {{
                            "attributes": {{
                                "tDn": "topology/pod-1/protpaths-{sw1}-{sw2}/pathep-[{vpc}]",
                                "encap": "vlan-{encap}",
                                "instrImedcy": "{deploy}",
                                "status": "{status}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, ap_name=ap_name, epg_name=epg_name,
                   sw1=sw1, sw2=sw2, vpc=vpc, encap=encap, deploy=deploy,
                   status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/ap-{}/epg-{}.json'
                       .format(self.apic, tn_name, ap_name, epg_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("Static path binding (vPC) failed to deploy. Exception: {}"
                  .format(e))
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
        payload = '''
        {{
            "fvAEPg": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/ap-{ap_name}/epg-{epg_name}",
                    "name": "{epg_name}",
                    "rn": "epg-{epg_name}",
                    "status": "created,modified"
                }},
                "children": [
                    {{
                        "fvRsPathAtt": {{
                            "attributes": {{
                                "dn": "uni/tn-{tn_name}/ap-{ap_name}/epg-{epg_name}/rspathAtt-[topology/pod-1/paths-{sw1}/pathep-[eth1/{port}]]",
                                "encap": "vlan-{encap}",
                                "instrImedcy": "{deploy}",
                                "status": "{status}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, ap_name=ap_name, epg_name=epg_name,
                  sw1=sw1, port=port, encap=encap, deploy=deploy,
                  status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/ap-{}/epg-{}.json'
                       .format(self.apic, tn_name, ap_name, epg_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("Static path binding (access) failed to deploy. Exception: "
                  "{}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # NOTE: At this time this only supports external DHCP servers (external to the fabric)
    # tn_name: The name of the Tenant
    # relay_name: Name of the DHCP Label/Provider
    # dhcp_ip: IP of the DHCP server
    # l3_tn: Name of the Tenant containing the L3 out used to reach DHCP server
    # l3_out: Name of the L3 out used to reach DHCP server
    # l3_network: Name of the L3 out Network used to reach DHCP server
    # status: created | created,modified | deleted
    def dhcp_relay(self, tn_name, relay_name, dhcp_ip, l3_tn, l3_out, l3_network, status):
        payload = '''
        {{
            "dhcpRelayP": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/relayp-{relay_name}",
                    "name": "{relay_name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "dhcpRsProv": {{
                            "attributes": {{
                                "addr": "{dhcp_ip}",
                                "rn": "rsprov-[uni/tn-{l3_tn}/out-{l3_out}/instP-{l3_network}]",
                                "status": "{status}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, relay_name=relay_name, dhcp_ip=dhcp_ip,
                   l3_tn=l3_tn, l3_out=l3_out, l3_network=l3_network,
                   status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/relayp-{}.json'
                       .format(self.apic, tn_name, relay_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("DHCP Relay failed to deploy. Exception: "
                  "{}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: The name of the Tenant
    # bd_name: Name of BD to deploy DHCP label to
    # relay_name: Name of the DHCP Label/Provider
    # status: created | created,modified | deleted
    # scope (optional): infra | tenant, defaults to tenant
    def dhcp_label(self, tn_name, bd_name, relay_name, scope, status):
        payload = '''
        {{
            "dhcpLbl": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/BD-{bd_name}/dhcplbl-{relay_name}",
                    "name": "{relay_name}",
                    "owner": "{scope}",
                    "status": "{status}"
                }}
            }}
        }}
        '''.format(tn_name=tn_name, bd_name=bd_name, relay_name=relay_name,
                   scope=scope, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/BD-{}.json'
                       .format(self.apic, tn_name, bd_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("DHCP Label failed to deploy. Exception: "
                  "{}".format(e))
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
        payload = '''
        {{
            "l3extOut": {{
                "attributes": {{
                    "enforceRtctrl": "export",
                    "name": "{name}",
                    "status": "{status}",
                    "targetDscp": "unspecified"
                }},
                "children": [
                    {{
                        "l3extRsEctx": {{
                            "attributes": {{
                                "rn": "rsectx",
                                "status": "{status}",
                                "tnFvCtxName": "{vrf}"
                            }}
                        }}
                    }},
                    {{
                        "l3extRsL3DomAtt": {{
                            "attributes": {{
                                "rn": "rsl3DomAtt",
                                "status": "{status}",
                                "tDn": "uni/l3dom-{domain}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, domain=domain, vrf=vrf,
                   status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/out-{}.json'
                       .format(self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (initial setup) Failed to deploy. Exception: {}"
                  .format(e))
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
        payload = '''
        {{
            "l3extOut": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/out-{name}",
                    "enforceRtctrl": "export",
                    "name": "{name}",
                    "status": "created,modified"
                }},
                "children": [
                    {{
                        "ospfExtP": {{
                            "attributes": {{
                                "areaCost": "1",
                                "areaCtrl": "redistribute,summary",
                                "areaId": "{area}",
                                "areaType": "{area_type}",
                                "rn": "ospfExtP",
                                "status": "{status}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, area=area, area_type=area_type,
                   status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/out-{}.json'
                       .format(self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (OSPF) Failed to deploy. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant
    # name: The name of the L3-Out
    # status: created | created,modified | deleted (of the BGP process)
    def bgp(self, tn_name, name, status):
        payload = '''
        {{
            "l3extOut": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/out-{name}",
                    "enforceRtctrl": "export",
                    "name": "{name}",
                    "status": "created,modified"
                }},
                "children": [
                    {{
                        "bgpExtP": {{
                            "attributes": {{
                                "rn": "bgpExtP",
                                "status": "{status}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/out-{}.json'
                       .format(self.apic, tn_name, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (BGP) Failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "l3extLNodeP": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/out-{name}/lnodep-{node_name}",
                    "name": "{node_name}",
                    "status": "{status}",
                    "tag": "yellow-green",
                    "targetDscp": "unspecified"
                }},
                "children": [
                    {{
                        "l3extRsNodeL3OutAtt": {{
                            "attributes": {{
                                "rn": "rsnodeL3OutAtt-[topology/pod-1/node-{sw1}]",
                                "rtrId": "{sw1_loop}",
                                "rtrIdLoopBack": "{loopback}",
                                "status": "created,modified"
                            }},
                            "children": [
                                {{
                                    "l3extLoopBackIfP": {{
                                        "attributes": {{
                                            "addr": "{sw1_loop}",
                                            "rn": "lbp-[{sw1_loop}]",
                                            "status": "created,modified"
                                        }}
                                    }}
                                }}
                            ]
                        }}
                    }},
                    {{
                        "l3extRsNodeL3OutAtt": {{
                            "attributes": {{
                                "rn": "rsnodeL3OutAtt-[topology/pod-1/node-{sw2}]",
                                "rtrId": "{sw2_loop}",
                                "rtrIdLoopBack": "{loopback}",
                                "status": "created,modified"
                            }},
                            "children": [
                                {{
                                    "l3extLoopBackIfP": {{
                                        "attributes": {{
                                            "addr": "{sw2_loop}",
                                            "rn": "lbp-[{sw2_loop}]",
                                            "status": "created,modified"
                                        }}
                                    }}
                                }}
                            ]
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, node_name=node_name, sw1=sw1,
                   sw2=sw2, sw1_loop=sw1_loop, sw2_loop=sw2_loop,
                   loopback=loopback, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/out-{}.json'
                       .format(self.apic, tn_name, name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (Node Profile) Failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "l3extRsNodeL3OutAtt": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/out-{name}/lnodep-{node_name}/rsnodeL3OutAtt-[topology/pod-1/node-{sw}]",
                    "status": "created,modified"
                }},
                "children": [
                    {{
                        "ipRouteP": {{
                            "attributes": {{
                                "aggregate": "no",
                                "ip": "{prefix}",
                                "pref": "1",
                                "rn": "rt-[{prefix}]",
                                "status": "{status}"
                            }},
                            "children": [
                                {{
                                    "ipNexthopP": {{
                                        "attributes": {{
                                            "nhAddr": "{next_hop}",
                                            "rn": "nh-[{next_hop}]",
                                            "status": "{status}"
                                        }}
                                    }}
                                }}
                            ]
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, node_name=node_name, sw=sw,
                   prefix=prefix, next_hop=next_hop, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/out-{}.json'
                       .format(self.apic, tn_name, name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (Static Route) Failed to deploy. Exception: {}"
                  .format(e))
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
        payload = '''
        {{
            "l3extLIfP": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/out-{name}/lnodep-{node_name}/lifp-{int_profile}",
                    "name": "{int_profile}",
                    "status": "{int_profile_status}"
                }},
                "children": [
                    {{
                        "l3extRsNdIfPol": {{
                            "attributes": {{
                                "status": "created,modified"
                            }}
                        }}
                    }},
                    {{
                        "l3extRsPathL3OutAtt": {{
                            "attributes": {{
                                "addr": "{ip}",
                                "encap": "unknown",
                                "ifInstT": "l3-port",
                                "llAddr": "::",
                                "mac": "00:22:BD:F8:19:FF",
                                "mode": "regular",
                                "mtu": "inherit",
                                "rn": "rspathL3OutAtt-[topology/pod-1/paths-{sw}/pathep-[eth1/{port}]]",
                                "status": "{status}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, node_name=node_name,
                   int_profile=int_profile, sw=sw, port=port, ip=ip,
                   int_profile_status=int_profile_status, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/out-{}/lnodep-{}/lifp-{}.json'
                       .format(self.apic, tn_name, name, node_name,
                        int_profile), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (Routed Ints) Failed to deploy. Exception: {}"
                  .format(e))
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
        payload = '''
        {{
            "l3extLIfP": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/out-{name}/lnodep-{node_name}/lifp-{int_profile}",
                    "name": "{int_profile}",
                    "status": "{int_profile_status}"
                }},
                "children": [
                    {{
                        "l3extRsNdIfPol": {{
                            "attributes": {{
                            "status": "created,modified"
                            }}
                        }}
                    }},
                    {{
                        "l3extRsPathL3OutAtt": {{
                            "attributes": {{
                                "addr": "{ip}",
                                "encap": "vlan-{vlan}",
                                "ifInstT": "sub-interface",
                                "llAddr": "::",
                                "mac": "00:22:BD:F8:19:FF",
                                "mode": "regular",
                                "mtu": "inherit",
                                "rn": "rspathL3OutAtt-[topology/pod-1/paths-{sw}/pathep-[eth1/{port}]]",
                                "status": "{status}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, node_name=node_name,
                   int_profile=int_profile, sw=sw, port=port, vlan=vlan,
                   ip=ip, int_profile_status=int_profile_status, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/out-{}/lnodep-{}/lifp'
                       '-{}.json'.format(self.apic, tn_name, name, node_name,
                       int_profile), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (Routed Ints) Failed to deploy. Exception: {}"
                  .format(e))
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
        payload = '''
        {{
            "l3extLIfP": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/out-{name}/lnodep-{node_name}/lifp-{int_profile}",
                    "name": "{int_profile}",
                    "status": "{int_profile_status}"
                }},
                "children": [
                    {{
                        "l3extRsNdIfPol": {{
                            "attributes": {{
                                "status": "created,modified"
                            }}
                        }}
                    }},
                    {{
                        "l3extRsPathL3OutAtt": {{
                            "attributes": {{
                                "encap": "vlan-{vlan}",
                                "ifInstT": "ext-svi",
                                "llAddr": "::",
                                "mac": "00:22:BD:F8:19:FF",
                                "mode": "regular",
                                "mtu": "inherit",
                                "status": "{status}",
                                "tDn": "topology/pod-1/protpaths-{sw1}-{sw2}/pathep-[{vpc}]",
                                "targetDscp": "unspecified"
                            }},
                            "children": [
                                {{
                                    "l3extMember": {{
                                        "attributes": {{
                                            "addr": "{sw2_ip}",
                                            "llAddr": "::",
                                            "rn": "mem-B",
                                            "side": "B",
                                            "status": "created,modified"
                                        }}
                                    }}
                                }},
                                {{
                                    "l3extMember": {{
                                        "attributes": {{
                                            "addr": "{sw1_ip}",
                                            "llAddr": "::",
                                            "rn": "mem-A",
                                            "side": "A",
                                            "status": "created,modified"
                                        }}
                                    }}
                                }}
                            ]
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, node_name=node_name,
                   int_profile=int_profile, sw1=sw1, sw2=sw2, sw1_ip=sw1_ip,
                   sw2_ip=sw2_ip, vlan=vlan, vpc=vpc,
                   int_profile_status=int_profile_status, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/out-{}/lnodep-{}/lifp-{}.json'
                       .format(self.apic, tn_name, name, node_name, int_profile),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (SVIs) Failed to deploy. Exception: {}".format(e))
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
        payload = '''
        {{
            "l3extInstP": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/out-{name}/instP-{epg_name}",
                    "matchT": "AtleastOne",
                    "name": "{epg_name}",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "l3extConfigOutDef": {{
                            "attributes": {{
                                "rn": "configOutDef",
                                "status": "created,modified"
                            }}
                        }}
                    }},
                    {{
                        "l3extSubnet": {{
                            "attributes": {{
                                "aggregate": "",
                                "ip": "{subnet}",
                                "name": "",
                                "rn": "extsubnet-[{subnet}]",
                                "scope": "import-security",
                                "status": "{subnet_status}"
                            }}
                        }}
                    }},
                    {{
                        "fvRsCustQosPol": {{
                            "attributes": {{
                                "status": "created,modified",
                                "tnQosCustomPolName": ""
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, epg_name=epg_name,
                   subnet=subnet, status=status, subnet_status=subnet_status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/out-{}/instP-{}.json'
                       .format(self.apic, tn_name, name, epg_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (Prefix Based EPG) Failed to deploy. Exception: {}"
                  .format(e))
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
        payload = '''
        {{
            "ospfIfPol": {{
                "attributes": {{
                    "cost": "unspecified",
                    "ctrl": "mtu-ignore",
                    "deadIntvl": "{dead}",
                    "dn": "uni/tn-{tn_name}/ospfIfPol-{pol_name}",
                    "helloIntvl": "{hello}",
                    "name": "{pol_name}",
                    "nwT": "{net_type}",
                    "prio": "1",
                    "rexmitIntvl": "5",
                    "status": "{status}",
                    "xmitDelay": "1"
                }}
            }}
        }}
        '''.format(tn_name=tn_name, pol_name=pol_name, hello=hello, dead=dead,
                   net_type=net_type, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/ospfIfPol-{}.json'
                       .format(self.apic, tn_name, pol_name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (OSPF Interface Policy) Failed to deploy. "
                  "Exception: {}".format(e))
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
        payload = '''
        {{
            "{pol_type}IfP": {{
                "attributes": {{
                    "authKeyId": "1",
                    "authType": "none",
                    "dn": "uni/tn-{tn_name}/out-{name}/lnodep-{node_name}/lifp-{int_profile}/{pol_type}IfP",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "ospfRsIfPol": {{
                            "attributes": {{
                                "rn": "rsIfPol",
                                "status": "{status}",
                                "tnOspfIfPolName": "{pol_name}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, node_name=node_name,
                   int_profile=int_profile, pol_type=pol_type,
                   pol_name=pol_name, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/out-{}/lnodep-{}/lifp'
                       '-{}.json' .format(self.apic, tn_name, name, node_name,
                                          int_profile),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (Deploy Interface Policy) Failed to deploy. "
                  "Exception: {}".format(e))
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
        payload = '''
        {{
            "l3extLNodeP": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/out-{name}/lnodep-{node_name}",
                    "name": "{node_name}",
                    "status": "created,modified"
                }},
                "children": [
                    {{
                        "bgpPeerP": {{
                            "attributes": {{
                                "addr": "{peer}",
                                "allowedSelfAsCnt": "3",
                                "ctrl": "",
                                "peerCtrl": "",
                                "rn": "peerP-[{peer}]",
                                "status": "{status}",
                                "ttl": "1"
                            }},
                            "children": [
                                {{
                                    "bgpRsPeerPfxPol": {{
                                        "attributes": {{
                                            "rn": "rspeerPfxPol",
                                            "status": "created,modified",
                                            "tnBgpPeerPfxPolName": ""
                                        }}
                                    }}
                                }},
                                {{
                                    "bgpLocalAsnP": {{
                                        "attributes": {{
                                            "asnPropagate": "none",
                                            "localAsn": "{local_asn}",
                                            "rn": "localasn",
                                            "status": "created,modified"
                                        }}
                                    }}
                                }},
                                {{
                                    "bgpAsP": {{
                                        "attributes": {{
                                            "asn": "{remote_asn}",
                                            "rn": "as",
                                            "status": "created,modified"
                                        }}
                                    }}
                                }}
                            ]
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, node_name=node_name, peer=peer,
                   local_asn=local_asn, remote_asn=remote_asn, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/out-{}.json'
                       .format(self.apic, tn_name, name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (BGP Peer - Loopback) Failed to deploy. "
                  "Exception: {}".format(e))
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
        payload = '''
        {{
            "l3extLIfP": {{
                "attributes": {{
                    "name": "{int_profile}",
                    "status": "created,modified"
                }},
                "children": [
                    {{
                        "l3extRsPathL3OutAtt": {{
                            "attributes": {{
                                "rn": "rspathL3OutAtt-[topology/pod-1/protpaths-{sw1}-{sw2}/pathep-[{vpc}]]",
                                "status": "created,modified"
                            }},
                            "children": [
                                {{
                                    "bgpPeerP": {{
                                        "attributes": {{
                                            "addr": "{peer}",
                                            "allowedSelfAsCnt": "3",
                                            "ctrl": "",
                                            "peerCtrl": "",
                                            "rn": "peerP-[{peer}]",
                                            "status": "{status}",
                                            "ttl": "1"
                                        }},
                                        "children": [
                                            {{
                                                "bgpRsPeerPfxPol": {{
                                                    "attributes": {{
                                                        "rn": "rspeerPfxPol",
                                                        "status": "",
                                                        "tnBgpPeerPfxPolName": ""
                                                    }}
                                                }}
                                            }},
                                            {{
                                                "bgpLocalAsnP": {{
                                                    "attributes": {{
                                                        "asnPropagate": "none",
                                                        "localAsn": "{local_asn}",
                                                        "rn": "localasn",
                                                        "status": "created,modified"
                                                    }}
                                                }}
                                            }},
                                            {{
                                                "bgpAsP": {{
                                                    "attributes": {{
                                                        "asn": "{remote_asn}",
                                                        "rn": "as",
                                                        "status": "created,modified"
                                                    }}
                                                }}
                                            }}
                                        ]
                                    }}
                                }}
                            ]
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, node_name=node_name,
                   int_profile=int_profile, sw1=sw1, sw2=sw2, vpc=vpc,
                   peer=peer, local_asn=local_asn, remote_asn=remote_asn,
                   status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/out-{}/lnodep-{}/lifp'
                       '-{}.json' .format(self.apic, tn_name, name, node_name,
                                          int_profile),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("L3 Out (BGP Peer - SVI) Failed to deploy. "
                  "Exception: {}".format(e))
            status = 666
        return status


# Class must be instantiated with APIC IP address and cookies
class TshootPol(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies

    # Method must be called with the following data.
    # tn_name: Name of the Tenant (for source of SPAN)
    # name: Name of the SPAN Source (automatically append -Group where appropriate)
    # admin: enabled | disabled
    # direction: both | in | out
    # ap: Name of Application Profile (for source of SPAN)
    # epg: Name of EPG (for source of SPAN)
    # dest: Name of SPAN Destination, -Group is automatically appended
    # status: created | created,modified | deleted
    def span_src(self, tn_name, name, admin, direction, ap, epg, dest, status):
        payload = '''
        {{
            "spanSrcGrp": {{
                "attributes": {{
                    "adminSt": "{admin}",
                    "dn": "uni/tn-{tn_name}/srcgrp-{name}-Group",
                    "name": "{name}-Group",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "spanSrc": {{
                            "attributes": {{
                                "dir": "{direction}",
                                "name": "{name}"
                            }},
                            "children": [
                                {{
                                    "spanRsSrcToEpg": {{
                                        "attributes": {{
                                            "tDn": "uni/tn-{tn_name}/ap-{ap}/epg-{epg}"
                                        }}
                                    }}
                                }}
                            ]
                        }}
                    }},
                    {{
                        "spanSpanLbl": {{
                            "attributes": {{
                                "name": "{dest}-Group",
                                "tag": "yellow-green"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(admin=admin, tn_name=tn_name, name=name, status=status,
                   direction=direction, ap=ap, epg=epg, dest=dest)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/srcgrp-'
                       '{}-Group.json'.format(self.apic, tn_name, name),
                       data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("SPAN Source Group Failed to deploy. Exception: {}"
                  .format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # tn_name: Name of the Tenant (where you are building the SPAN)
    # name: The name of the SPAN Destination Group
    # tn_dest: Name of the Tenant where the SPAN destination resides
    # ap: Name of Application Profile (for destination of SPAN)
    # epg: Name of EPG (for destination of SPAN)
    # dest_ip: IP address of device terminating SPAN
    # src_ip: IP address of ACI ERSPAN source
    # status: created | created,modified | deleted
    def span_dst(self, tn_name, name, tn_dest, ap, epg, dest_ip, src_ip,
                 status):
        payload = '''
        {{
            "spanDestGrp": {{
                "attributes": {{
                    "dn": "uni/tn-{tn_name}/destgrp-{name}-Group",
                    "name": "{name}-Group",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "spanDest": {{
                            "attributes": {{
                                "name": "{relay_name}"
                            }},
                            "children": [
                                {{
                                    "spanRsDestEpg": {{
                                        "attributes": {{
                                            "dscp": "unspecified",
                                            "finalIp": "0.0.0.0",
                                            "flowId": "1",
                                            "ip": "{dest_ip}",
                                            "mtu": "1518",
                                            "srcIpPrefix": "{src_ip}",
                                            "tDn": "uni/tn-{tn_dest}/ap-{ap}/epg-{epg}",
                                            "ttl": "64",
                                            "ver": "ver2",
                                            "verEnforced": "no"
                                        }}
                                    }}
                                }}
                            ]
                        }}
                    }}
                ]
            }}
        }}
        '''.format(tn_name=tn_name, name=name, status=status, dest_ip=dest_ip,
                   src_ip=src_ip, tn_dest=tn_dest, ap=ap, epg=epg)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/tn-{}/destgrp-{}-Group.'
                       'json'.format(self.apic, tn_name, name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("SPAN Destination Group Failed to deploy. Exception: {}"
                  .format(e))
            status = 666
        return status


# Class must be instantiated with APIC IP address and cookies
class Query(object):
    def __init__(self, apic, cookies):
        self.apic = apic
        self.cookies = cookies

    # Method must be called with the following data.
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
            r = s.get('https://{}/api/class/{}.json'.format(self.apic,
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

    # Method must be called with the following data. Note only supports
    # SCP at this time (could easily add SFTP or FTP if needed though)
    # name = name of the remote location
    # ip = IP of the remote location (note, module does no validation)
    # path = Path on the remote location
    # user = username for remote location
    # pword = password (sent in clear text) for the remote location
    # status = created | created,modified | deleted
    def remote_path(self, name, ip, path, user, pword, status):
        payload = '''
        {{
        "fileRemotePath": {{
            "attributes": {{
                "descr": "",
                "dn": "uni/fabric/path-{name}",
                "host": "{ip}",
                "name": "{name}",
                "protocol": "scp",
                "remotePath": "{path}",
                "remotePort": "22",
                "userName": "Carl",
                "userPasswd": "{pword}",
                "status": "{status}"
            }},
                "children": [
                    {{
                    "fileRsARemoteHostToEpg": {{
                        "attributes": {{
                            "tDn": "uni/tn-mgmt/mgmtp-default/oob-default"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, ip=ip, path=path, user=user, pword=pword,
                   status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/fabric/path-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Failed to create remote location. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # name = name of the snapshot itself
    # snapshot = true | false - if true it creates an export policy and
    # takes a snapshot, if false it simply creates an export policy
    # status = created | created,modified | deleted
    # path = (Optional) remote path for export (can be left blank for snapshot)
    def backup(self, name, snapshot, status, path=''):
        payload = '''
        {{
            "configExportP": {{
                "attributes": {{
                    "dn": "uni/fabric/configexp-{name}",
                    "name": "{name}",
                    "format": "json",
                    "snapshot": "{snapshot}",
                    "targetDn": "",
                    "adminSt": "triggered",
                    "status": "{status}"
                }},
                "children": [
                    {{
                        "configRsRemotePath": {{
                            "attributes": {{
                                "tnFileRemotePathName": "{path}"
                            }}
                        }}
                    }}
                ]
            }}
        }}
        '''.format(name=name, snapshot=snapshot, path=path, status=status)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/fabric/configexp-{}.jso'
                       'n'.format(self.apic, name),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("Failed to take snapshot. Exception: {}".format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # name = name of the import object itself
    # filename = name of the file to import
    # path = name of the remote path object where the file lives
    def replace(self, name, filename, path):
        payload = '''
        {{
          "configImportP": {{
            "attributes": {{
              "dn": "uni/fabric/configimp-{name}",
              "name": "{name}",
              "fileName": "{filename}",
              "importType": "replace",
              "rn": "configimp-test",
              "adminSt": "triggered",
              "status": "created"
            }},
            "children": [
            {{
              "configRsRemotePath": {{
                "attributes": {{
                  "tnFileRemotePathName": "{path}",
                  "status": "created,modified"
                }},
                "children": []
                }}
              }}
            ]
          }}
        }}
        '''.format(name=name, filename=filename, path=path)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/fabric/configimp-{}.json'
                       .format(self.apic, name), data=json.dumps(payload),
                       cookies=self.cookies, verify=False)
            status = r.status_code
        except Exception as e:
            print("Failed to import and replace config. Exception: {}"
                  .format(e))
            status = 666
        return status

    # Method must be called with the following data.
    # name = name of the snapshot itself (note you need to put the file
    # extension in yourself)
    def snapback(self, name):
        payload = '''
        {{
            "configImportP": {{
                "attributes": {{
                    "dn": "uni/fabric/configimp-default",
                    "name": "default",
                    "snapshot": "true",
                    "adminSt": "triggered",
                    "fileName": "{name}",
                    "importType": "replace",
                    "importMode": "atomic",
                    "rn": "configimp-default",
                    "status": "created,modified"
                }}
            }}
        }}
        '''.format(name=name)
        payload = json.loads(payload,
                             object_pairs_hook=collections.OrderedDict)
        s = requests.Session()
        try:
            r = s.post('https://{}/api/node/mo/uni/fabric/configimp-default.js'
                       'on'.format(self.apic),
                       data=json.dumps(payload), cookies=self.cookies,
                       verify=False)
            status = r.status_code
        except Exception as e:
            print("Failed to snapback. Exception: {}".format(e))
            status = 666
        return status

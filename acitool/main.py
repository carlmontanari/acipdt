from acitool import acipdt
import xlrd
import xlwt
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from xlutils.copy import copy
from orderedset import OrderedSet
import sys
import time
import ipaddress
import getpass
import os


def read_in(usr_path):
    try:
        wb_path = os.path.join(usr_path, 'ACI Deploy.xls')
        wb = xlrd.open_workbook(wb_path)
        print("Workbook Loaded.")
    except Exception as e:
        print("Something went wrong logging opening the workbook - ABORT!")
        sys.exit(e)
    return wb


def findKeys(ws, rows):
    func_list = OrderedSet()
    for i in range(2, rows):
        if (ws.cell(i, 0)).value:
            func_list.add((ws.cell(i, 0)).value)
        else:
            i += 1
    return func_list


def countKeys(ws, rows, func):
    count = 0
    for i in range(2, rows):
        if (ws.cell(i, 0)).value == func:
            count += 1
        else:
            i += 1
    return count


def findVars(ws, rows, func, count):
    var_list = []
    var_dict = {}
    for i in range(2, rows):
        if (ws.cell(i, 0)).value == func:
            try:
                for x in range(4, 17):
                    if (ws.cell(i - 1, x)).value:
                        var_list.append((ws.cell(i - 1, x)).value)
                    else:
                        x += 1
            except:
                pass
            break
    while count > 0:
        var_dict[count] = {}
        var_count = 0
        for z in var_list:
            var_dict[count][z] = ws.cell(i + count - 1, 4 + var_count).value
            var_count += 1
        var_dict[count]['row'] = i + count - 1
        count -= 1
    return var_dict


def wb_update(wr_ws, status, i):
    # build green and red style sheets for excel
    green_st = xlwt.easyxf('pattern: pattern solid;')
    green_st.pattern.pattern_fore_colour = 3
    red_st = xlwt.easyxf('pattern: pattern solid;')
    red_st.pattern.pattern_fore_colour = 2
    yellow_st = xlwt.easyxf('pattern: pattern solid;')
    yellow_st.pattern.pattern_fore_colour = 5
    # if stanzas to catch the status code from the request
    # and then input the appropriate information in the workbook
    # this then writes the changes to the doc
    if status == 200:
        wr_ws.write(i, 1, 'Success (200)', green_st)
    if status == 400:
        print("Error 400 - Bad Request - ABORT!")
        print("Probably have a bad URL or payload")
        wr_ws.write(i, 1, 'Bad Request (400)', red_st)
        pass
    if status == 401:
        print("Error 401 - Unauthorized - ABORT!")
        print("Probably have incorrect credentials")
        wr_ws.write(i, 1, 'Unauthorized (401)', red_st)
        pass
    if status == 403:
        print("Error 403 - Forbidden - ABORT!")
        print("Server refuses to handle your request")
        wr_ws.write(i, 1, 'Forbidden (403)', red_st)
        pass
    if status == 404:
        print("Error 404 - Not Found - ABORT!")
        print("Seems like you're trying to POST to a page that doesn't"
              " exist.")
        wr_ws.write(i, 1, 'Not Found (400)', red_st)
        pass
    if status == 666:
        print("Error - Something failed!")
        print("The POST failed, see stdout for the exception.")
        wr_ws.write(i, 1, 'Unkown Failure', yellow_st)
        pass
    if status == 667:
        print("Error - Invalid Input!")
        print("Invalid integer or other input.")
        wr_ws.write(i, 1, 'Unkown Failure', yellow_st)
        pass


def pod_policies(apic, cookies, wb, wr_wb):
    ws = wb.sheet_by_name('Fabric Pod Policies')
    wr_ws = wr_wb.get_sheet(0)
    rows = ws.nrows
    func_list = findKeys(ws, rows)
    podpol = acipdt.FabPodPol(apic, cookies)
    for func in func_list:
        count = countKeys(ws, rows, func)
        var_dict = findVars(ws, rows, func, count)
        for pos in var_dict:
            row_num = var_dict[pos]['row']
            del var_dict[pos]['row']
            for x in list(var_dict[pos].keys()):
                if var_dict[pos][x] == '':
                    del var_dict[pos][x]
            status = eval("podpol.%s(**var_dict[pos])" % func)
            wb_update(wr_ws, status, row_num)
            time.sleep(.025)


def access_policies(apic, cookies, wb, wr_wb):
    ws = wb.sheet_by_name('Fabric Access Policies')
    wr_ws = wr_wb.get_sheet(1)
    rows = ws.nrows
    func_list = findKeys(ws, rows)
    accpol = acipdt.FabAccPol(apic, cookies)
    for func in func_list:
        count = countKeys(ws, rows, func)
        var_dict = findVars(ws, rows, func, count)
        for pos in var_dict:
            row_num = var_dict[pos]['row']
            del var_dict[pos]['row']
            for x in list(var_dict[pos].keys()):
                if var_dict[pos][x] == '':
                    del var_dict[pos][x]
            status = eval("accpol.%s(**var_dict[pos])" % func)
            wb_update(wr_ws, status, row_num)
            time.sleep(.025)


def tn_policies(apic, cookies, wb, wr_wb):
    ws = wb.sheet_by_name('Tenant Configuration')
    wr_ws = wr_wb.get_sheet(2)
    rows = ws.nrows
    func_list = findKeys(ws, rows)
    tnpol = acipdt.FabTnPol(apic, cookies)
    for func in func_list:
        count = countKeys(ws, rows, func)
        var_dict = findVars(ws, rows, func, count)
        for pos in var_dict:
            row_num = var_dict[pos]['row']
            del var_dict[pos]['row']
            for x in list(var_dict[pos].keys()):
                if var_dict[pos][x] == '':
                    del var_dict[pos][x]
            status = eval("tnpol.%s(**var_dict[pos])" % func)
            wb_update(wr_ws, status, row_num)
            time.sleep(.025)


def l3_policies(apic, cookies, wb, wr_wb):
    ws = wb.sheet_by_name('L3 Out')
    wr_ws = wr_wb.get_sheet(3)
    rows = ws.nrows
    func_list = findKeys(ws, rows)
    l3pol = acipdt.FabL3Pol(apic, cookies)
    for func in func_list:
        count = countKeys(ws, rows, func)
        var_dict = findVars(ws, rows, func, count)
        for pos in var_dict:
            row_num = var_dict[pos]['row']
            del var_dict[pos]['row']
            for x in list(var_dict[pos].keys()):
                if var_dict[pos][x] == '':
                    del var_dict[pos][x]
            status = eval("l3pol.%s(**var_dict[pos])" % func)
            wb_update(wr_ws, status, row_num)
            time.sleep(.025)


def vmm_policies(apic, cookies, wb, wr_wb):
    ws = wb.sheet_by_name('VMM')
    wr_ws = wr_wb.get_sheet(4)
    rows = ws.nrows
    func_list = findKeys(ws, rows)
    vmm = acipdt.FabVMM(apic, cookies)
    for func in func_list:
        count = countKeys(ws, rows, func)
        var_dict = findVars(ws, rows, func, count)
        for pos in var_dict:
            row_num = var_dict[pos]['row']
            del var_dict[pos]['row']
            for x in list(var_dict[pos].keys()):
                if var_dict[pos][x] == '':
                    del var_dict[pos][x]
            status = eval("vmm.%s(**var_dict[pos])" % func)
            wb_update(wr_ws, status, row_num)
            time.sleep(.025)


def fab_admin_policies(apic, cookies, wb, wr_wb):
    ws = wb.sheet_by_name('Fabric Admin')
    wr_ws = wr_wb.get_sheet(5)
    rows = ws.nrows
    func_list = findKeys(ws, rows)
    fabadmin = acipdt.FabAdminMgmt(apic, cookies)
    for func in func_list:
        count = countKeys(ws, rows, func)
        var_dict = findVars(ws, rows, func, count)
        for pos in var_dict:
            row_num = var_dict[pos]['row']
            del var_dict[pos]['row']
            for x in list(var_dict[pos].keys()):
                if var_dict[pos][x] == '':
                    del var_dict[pos][x]
            status = eval("fabadmin.%s(**var_dict[pos])" % func)
            wb_update(wr_ws, status, row_num)
            time.sleep(.025)


def mpod_policies(apic, cookies, wb, wr_wb):
    ws = wb.sheet_by_name('Multipod')
    wr_ws = wr_wb.get_sheet(6)
    rows = ws.nrows
    func_list = findKeys(ws, rows)
    mpod = acipdt.Mpod(apic, cookies)
    for func in func_list:
        count = countKeys(ws, rows, func)
        var_dict = findVars(ws, rows, func, count)
        for pos in var_dict:
            row_num = var_dict[pos]['row']
            del var_dict[pos]['row']
            for x in list(var_dict[pos].keys()):
                if var_dict[pos][x] == '':
                    del var_dict[pos][x]
            status = eval("mpod.%s(**var_dict[pos])" % func)
            wb_update(wr_ws, status, row_num)
            time.sleep(.025)


def take_snapshot(apic, cookies, snapshot_name):
    query = acipdt.Query(apic, cookies)
    query_string = 'configSnapshot'
    query_payload = query.query_class(query_string)
    payload_len = len(query_payload[1]['imdata'])
    snap_count = 0
    for x in range(0, payload_len):
        if (query_payload[1]['imdata'][x]['configSnapshot']['attributes']
                ['fileName'])[4:17] == snapshot_name:
                snap_count += 1

    if snap_count > 0:
        print("A snapshot with that name ({}) already exists. Please change th"
              "e name of the snapshot in the main.py file, or delete the exist"
              "ing snapshot. Exiting.".format(snapshot_name))
        sys.exit()
    elif snap_count == 0:
        snapshot = 'true'
        status = 'created,modified'
        snapshot_args = {}
        snapshot_args['name'] = snapshot_name
        snapshot_args['snapshot'] = snapshot
        snapshot_args['status'] = status
        cfgmgmt = acipdt.FabCfgMgmt(apic, cookies)
        status = cfgmgmt.backup(**snapshot_args)
        if status == 200:
            print("Snapshot taken successfully, continuing.")
            time.sleep(5)
        else:
            print("Snapshot failed for some reason, do you want to continue?")
            while True:
                user_input = input("Continue 'y' or 'n' [n]: ")
                selection = user_input or 'n'
                if selection.lower() == 'y':
                    continue
                elif selection.lower() == 'n':
                    del_snap_pol(apic, cookies, snapshot_name)
                    sys.exit()


def revert_snapshot(apic, cookies, snapshot_name):
    print('Deployment completed, please verify status in workbook.')
    user_input = input("Rollback to previous snapshot 'y' or 'n' [n]: ")
    selection = user_input or 'n'
    if selection.lower() == 'n':
        pass
    elif selection.lower() == 'y':
        query = acipdt.Query(apic, cookies)
        query_string = 'configSnapshot'
        query_payload = query.query_class(query_string)
        payload_len = len(query_payload[1]['imdata'])
        for x in range(0, payload_len):
            if (query_payload[1]['imdata'][x]['configSnapshot']['attributes']
                    ['fileName'])[4:17] == snapshot_name:
                snapshot_name = (query_payload[1]['imdata'][x]
                                 ['configSnapshot']['attributes']
                                 ['fileName'])
                break
        cfgmgmt = acipdt.FabCfgMgmt(apic, cookies)
        snapshot_args = {}
        snapshot_args['name'] = snapshot_name
        cfgmgmt.snapback(**snapshot_args)


def del_snap_pol(apic, cookies, snapshot_name):
    status = 'deleted'
    snapshot = 'true'
    snapshot_args = {}
    snapshot_args['name'] = snapshot_name
    snapshot_args['snapshot'] = snapshot
    snapshot_args['status'] = status
    cfgmgmt = acipdt.FabCfgMgmt(apic, cookies)
    status = cfgmgmt.backup(**snapshot_args)


def main():
    # Disable urllib3 warnings
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    # Ask user for path to 'ACI Deploy.xls'
    while True:
        print('Please enter the path to \'ACI Deploy.xls\', note that this is '
              'also where the workbook will be saved upon completion.')
        usr_path = input('Path: ')
        if os.path.exists(usr_path):
            break
        else:
            print('Enter a valid path.')
    # Static snapshot name
    snapshot_name = 'acipdt_backup'
    # Prompt for APIC IP
    while True:
        apic = input('Enter the APIC IP: ')
        try:
            ipaddress.ip_address(apic)
            break
        except Exception as e:
            print('Enter a valid IP address. Error received: {}'.format(e))
    # Prompt for APIC Username
    user = input('Enter APIC username: ')
    # Prompt for APIC Password
    while True:
        try:
            pword = getpass.getpass(prompt='Enter APIC password: ')
            break
        except Exception as e:
            print('Something went wrong. Error received: {}'.format(e))
    # Initialize the fabric login method, passing appropriate variables
    fablogin = acipdt.FabLogin(apic, user, pword)
    # Run the login and load the cookies var
    cookies = fablogin.login()
    # Load workbook
    wb = read_in(usr_path)
    # Copy workbook to a RW version
    wr_wb = copy(wb)
    take_snapshot(apic, cookies, snapshot_name)
    pod_policies(apic, cookies, wb, wr_wb)
    access_policies(apic, cookies, wb, wr_wb)
    tn_policies(apic, cookies, wb, wr_wb)
    l3_policies(apic, cookies, wb, wr_wb)
    vmm_policies(apic, cookies, wb, wr_wb)
    fab_admin_policies(apic, cookies, wb, wr_wb)
    mpod_policies(apic, cookies, wb, wr_wb)
    # Save workbook to user path
    wr_wb.save('{}/ACI Deploy.xls'.format(usr_path))
    revert_snapshot(apic, cookies, snapshot_name)
    del_snap_pol(apic, cookies, snapshot_name)


if __name__ == '__main__':
    main()

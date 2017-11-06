import unittest
from unittest.mock import MagicMock
from acitool import acipdt


apic = '1.1.1.1'
cookies = 'mytastycookies'
var_dict = {'serial': '12345678', 'name': 'Leaf-101', 'id': '101'}


class BasicTests(unittest.TestCase):
    def test_comission_hw(self):
        podpol = acipdt.FabPodPol(apic, cookies)
        podpol.comission_hw = MagicMock(return_value=200)
        podpol.comission_hw.assert_called_with(var_dict)


if __name__ == '__main__':
    unittest.main()

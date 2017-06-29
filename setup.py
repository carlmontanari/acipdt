from setuptools import setup, find_packages

setup(name='ACIPDT',
      version='1.3',
      description='ACI Power Deployment Tool',
      url='',
      author='Carl Niger',
      author_email='carl@lumoscloud.com',
      license='',
      packages=find_packages(),
      install_requires=['ipaddress',
                        'requests',
                        'xlrd',
                        'xlwt',
                        'xlutils',
                        'orderedset'],
      package_data={'': ['*.json', '*.xls']})

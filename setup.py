import os

try:
    from setuptools import setup, find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]


setup(
    name='veribin', version='1.0', description="VeriBin - Adaptive binary-level patch verification",
    packages=packages,
    install_requires=['timeout_decorator', 'colorama'],
)

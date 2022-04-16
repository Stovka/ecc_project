import setuptools
import pathlib
import pkg_resources

with pathlib.Path('requirements.txt').open() as requirements_txt:
    install_requires = [
        str(requirement)
        for requirement
        in pkg_resources.parse_requirements(requirements_txt)
    ]

setuptools.setup(
    name='ecc_project',
    version='0.1',
    packages=[''],
    url='',
    license='',
    author='Petr Šťovíček',
    author_email='petrstovicek1@gmail.com',
    description='App for ECDH, ECDSA, ECIES, P2P',
    install_requires=install_requires
)
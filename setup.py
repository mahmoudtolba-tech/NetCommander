"""
AutomationNet Setup Script
Installs the application and its dependencies
"""
from setuptools import setup, find_packages
import os

# Read README
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r') as f:
            return f.read()
    return ''

# Read requirements
def read_requirements():
    req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    requirements = []
    if os.path.exists(req_path):
        with open(req_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    requirements.append(line)
    return requirements

setup(
    name='AutomationNet',
    version='2.0.0',
    description='Network Device Automation Tool with Modern GUI',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    author='Mahmoud Tolba',
    author_email='mahmoud.tolba@example.com',
    url='https://github.com/mahmoudtolba/AutomationNet',
    keywords=['network', 'automation', 'ssh', 'cisco', 'network-management', 'devops'],
    python_requires='>=3.8',
    packages=find_packages(),
    install_requires=read_requirements(),
    entry_points={
        'console_scripts': [
            'automationnet=src.gui.main_window:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Topic :: System :: Networking',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
)
